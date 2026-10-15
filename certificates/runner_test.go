package certificates

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRunnerDeduplicatesAndPreservesMalformedInputOutcome(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "runner.example.test", "runner.example.test")}})
	line := fmt.Sprintf(`{"ip":%q,"port":"%d"}`, target.IP, target.Port)
	var out bytes.Buffer
	stats, err := Run(context.Background(), strings.NewReader(line+"\n"+line+"\n{broken\n"), &out, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Certificates != 1 || stats.Duplicates != 1 || stats.InputErrors != 1 {
		t.Fatalf("bad stats: %+v", stats)
	}
	dec := json.NewDecoder(&out)
	records := 0
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("corrupt NDJSON: %v", err)
		}
		records++
	}
	if records != 2 {
		t.Fatalf("got %d outcomes", records)
	}
}

func TestInvalidOptionsFailBeforeReadingInput(t *testing.T) {
	for _, modify := range []func(*Options){func(o *Options) { o.MaxThreads = 0 }, func(o *Options) { o.RateLimit = 0 }, func(o *Options) { o.QueueSize = -1 }, func(o *Options) { o.Timeout = 0 }, func(o *Options) { o.Retries = -1 }, func(o *Options) { o.DedupCapacity = 0 }, func(o *Options) { o.SNILimit = -1 }} {
		o := fastOptions()
		modify(&o)
		_, err := Run(context.Background(), unreadableInput{}, &bytes.Buffer{}, o)
		if err == nil {
			t.Fatal("accepted invalid option")
		}
	}
}

type unreadableInput struct{}

func (unreadableInput) Read([]byte) (int, error) { panic("invalid options read stdin") }

func TestCancellationStopsBlockedStdin(t *testing.T) {
	input, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, input, &bytes.Buffer{}, fastOptions())
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("blocked stdin prevented cancellation: %v", err)
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("fixture output unavailable") }

func TestOutputFailureCancelsAndJoinsWorkers(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "output.example.test", "output.example.test")}})
	var input strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&input, "{\"ip\":%q,\"port\":%d,\"host\":\"host-%d.example.test\"}\n", target.IP, target.Port, i)
	}
	start := time.Now()
	_, err := Run(context.Background(), strings.NewReader(input.String()), failedOutput{}, fastOptions())
	if err == nil || !strings.Contains(err.Error(), "fixture output unavailable") || time.Since(start) > time.Second {
		t.Fatalf("output failure did not stop collection: %v", err)
	}
}

func TestDedupCacheIsBoundedAndExpires(t *testing.T) {
	c := newSeenCache(2, time.Second)
	now := time.Now()
	if c.Seen("a", now) || !c.Seen("a", now) {
		t.Fatal("duplicate missed")
	}
	_ = c.Seen("b", now)
	_ = c.Seen("c", now)
	if c.Seen("a", now) {
		t.Fatal("old entry not evicted")
	}
	if c.Seen("a", now.Add(2*time.Second)) {
		t.Fatal("expired entry retained")
	}
}

func TestRunnerRateCapsAllConnectionStarts(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "one.example.test", "one.example.test")}})
	input := fmt.Sprintf("{\"ip\":%q,\"port\":%d,\"host\":\"one.example.test\"}\n{\"ip\":%q,\"port\":%d,\"host\":\"two.example.test\"}\n{\"ip\":%q,\"port\":%d,\"host\":\"three.example.test\"}\n", target.IP, target.Port, target.IP, target.Port, target.IP, target.Port)
	o := fastOptions()
	o.RateLimit = 20
	start := time.Now()
	stats, err := Run(context.Background(), strings.NewReader(input), &bytes.Buffer{}, o)
	if err != nil || stats.Certificates != 3 {
		t.Fatalf("%v %+v", err, stats)
	}
	if time.Since(start) < 90*time.Millisecond {
		t.Fatal("connections exceeded global rate cap")
	}
}

func TestSNIFollowupsShareInputDuplicateSuppression(t *testing.T) {
	target := fixtureTLS(t, "tls", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, "a.example.test", "a.example.test", "b.example.test")}})
	input := fmt.Sprintf("{\"ip\":%q,\"port\":%d}\n{\"ip\":%q,\"port\":%d,\"host\":\"a.example.test\"}\n", target.IP, target.Port, target.IP, target.Port)
	o := fastOptions()
	o.SNILimit = 1
	var out bytes.Buffer
	_, err := Run(context.Background(), strings.NewReader(input), &out, o)
	if err != nil {
		t.Fatal(err)
	}
	hosts := make(map[string]int)
	dec := json.NewDecoder(&out)
	for dec.More() {
		var event Event
		if err = dec.Decode(&event); err != nil {
			t.Fatal(err)
		}
		hosts[event.Host]++
	}
	for host, count := range hosts {
		if count > 1 {
			t.Fatalf("repeated same-endpoint SNI %q %d times", host, count)
		}
	}
	if hosts[""] != 1 || hosts["a.example.test"] != 1 {
		t.Fatalf("missing expected observations: %v", hosts)
	}
}
