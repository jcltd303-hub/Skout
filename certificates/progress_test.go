package certificates

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLiveStatsRenderer(t *testing.T) {
	var buf bytes.Buffer
	render := newLiveStatsRenderer(&buf, true)
	render(Stats{Input: 10, Accepted: 10, TCPConnected: 3, Certificates: 2, Errors: 5})
	out := buf.String()
	if !strings.Contains(out, "certs") || !strings.Contains(out, "tcp") || !strings.Contains(out, "errors") {
		t.Fatalf("renderer output missing counts: %q", out)
	}
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("color renderer produced no ANSI codes: %q", out)
	}
	if strings.Contains(out, "\n") {
		t.Fatalf("renderer must not emit newlines (in-place rewrite only): %q", out)
	}
	var plain bytes.Buffer
	renderPlain := newLiveStatsRenderer(&plain, false)
	renderPlain(Stats{Input: 1, Accepted: 1})
	if strings.Contains(plain.String(), "\x1b[2K") == false {
		t.Fatalf("plain renderer must still clear the line: %q", plain.String())
	}
	if strings.Contains(plain.String(), "\x1b[32") {
		t.Fatalf("plain renderer must not emit colors: %q", plain.String())
	}
}

func TestSnapshotStatsDeepCopiesPorts(t *testing.T) {
	orig := Stats{Input: 1, Ports: map[string]*PortStats{"443": {Outcomes: 1}}}
	snap := snapshotStats(orig)
	snap.Ports["443"].Outcomes = 99
	if orig.Ports["443"].Outcomes != 1 {
		t.Fatalf("snapshot shares Ports map with original")
	}
}

func TestRunCallsProgressFunc(t *testing.T) {
	var mu sync.Mutex
	var seen []Stats
	opts := fastOptions()
	opts.ProgressInterval = 10 * time.Millisecond
	opts.ProgressFunc = func(s Stats) {
		mu.Lock()
		seen = append(seen, s)
		mu.Unlock()
	}
	// Slow input: drip one unroutable endpoint, keeping Run alive long
	// enough for several progress ticks.
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_, _ = pw.Write([]byte("{\"ip\":\"192.0.2.10\",\"port\":443}\n"))
		time.Sleep(120 * time.Millisecond)
	}()
	_, _ = Run(context.Background(), pr, &bytes.Buffer{}, opts)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("ProgressFunc was never called")
	}
}
