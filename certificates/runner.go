package certificates

import (
	"bufio"
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

type startLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newStartLimiter(rate int) *startLimiter {
	return &startLimiter{interval: time.Second / time.Duration(rate)}
}
func (l *startLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay := time.Until(l.next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	l.next = time.Now().Add(l.interval)
	return nil
}

type cacheItem struct {
	key  string
	time time.Time
}
type seenCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	entries  map[string]*list.Element
	order    *list.List
}

func newSeenCache(capacity int, ttl time.Duration) *seenCache {
	return &seenCache{capacity: capacity, ttl: ttl, entries: make(map[string]*list.Element), order: list.New()}
}
func (c *seenCache) Seen(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		item := entry.Value.(cacheItem)
		if now.Sub(item.time) < c.ttl {
			c.order.MoveToBack(entry)
			return true
		}
		c.order.Remove(entry)
		delete(c.entries, key)
	}
	if len(c.entries) >= c.capacity {
		old := c.order.Front()
		delete(c.entries, old.Value.(cacheItem).key)
		c.order.Remove(old)
	}
	c.entries[key] = c.order.PushBack(cacheItem{key: key, time: now})
	return false
}

type PortStats struct {
	Outcomes     int `json:"outcomes"`
	TCPConnected int `json:"tcp_connected"`
	Certificates int `json:"certificates"`
	Errors       int `json:"errors"`
}
type Stats struct {
	Input        int                   `json:"input"`
	Accepted     int                   `json:"accepted"`
	Duplicates   int                   `json:"duplicates"`
	InputErrors  int                   `json:"input_errors"`
	TCPConnected int                   `json:"tcp_connected"`
	Certificates int                   `json:"certificates"`
	Errors       int                   `json:"errors"`
	Ports        map[string]*PortStats `json:"ports"`
}
type readReport struct {
	input, accepted, duplicates int
	err                         error
}

// Run applies backpressure and serializes all writes. On cancellation it closes
// input when input implements io.Closer, so blocked stdin reads can terminate.
func Run(parent context.Context, input io.Reader, output io.Writer, o Options) (Stats, error) {
	stats := Stats{Ports: make(map[string]*PortStats)}
	if err := o.Validate(); err != nil {
		return stats, err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if closer, ok := input.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	o.limiter = newStartLimiter(o.RateLimit)
	o.seen = newSeenCache(o.DedupCapacity, o.DedupTTL)
	jobs := make(chan Target, o.QueueSize)
	results := make(chan Event, o.MaxThreads)
	readDone := make(chan readReport, 1)
	var workers sync.WaitGroup
	for i := 0; i < o.MaxThreads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				events, err := Collect(ctx, target, o)
				if err != nil {
					events = []Event{{EventType: "service", EventSource: "ip4scout/certs", IP: target.IP, Port: strconv.Itoa(target.Port), Host: target.Host, Time: time.Now().UTC(), Error: err.Error(), ErrorKind: "configuration"}}
				}
				for _, event := range events {
					results <- event
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		report := readReport{}
		defer func() { readDone <- report }()
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			if ctx.Err() != nil {
				break
			}
			if strings.TrimSpace(scanner.Text()) == "" {
				continue
			}
			report.input++
			target, err := ParseTarget(scanner.Bytes())
			if err != nil {
				event := Event{EventType: "input_error", EventSource: "ip4scout/certs", Time: time.Now().UTC(), Error: err.Error(), ErrorKind: "input", InputLine: report.input}
				select {
				case results <- event:
				case <-ctx.Done():
					return
				}
				continue
			}
			if o.seen.Seen(targetKey(target, o), time.Now()) {
				report.duplicates++
				continue
			}
			select {
			case jobs <- target:
				report.accepted++
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			report.err = fmt.Errorf("reading endpoint stream: %w", err)
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var writeErr error
	encoder := json.NewEncoder(output)
	for event := range results {
		if writeErr == nil {
			if err := encoder.Encode(event); err != nil {
				writeErr = fmt.Errorf("writing service stream: %w", err)
				cancel()
			}
		}
		if event.EventType == "input_error" {
			stats.InputErrors++
			continue
		}
		port := stats.Ports[event.Port]
		if port == nil {
			port = &PortStats{}
			stats.Ports[event.Port] = port
		}
		port.Outcomes++
		if event.TCPConnected {
			stats.TCPConnected++
			port.TCPConnected++
		}
		if event.SSL.Enabled {
			stats.Certificates++
			port.Certificates++
		}
		if event.Error != "" {
			stats.Errors++
			port.Errors++
		}
	}
	// Producer sends its report before closing jobs, so it is available here.
	report := <-readDone
	stats.Input = report.input
	stats.Accepted = report.accepted
	stats.Duplicates = report.duplicates
	if writeErr != nil {
		return stats, writeErr
	}
	if report.err != nil {
		return stats, report.err
	}
	if parent.Err() != nil {
		return stats, parent.Err()
	}
	return stats, nil
}
