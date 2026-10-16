package certificates

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Live stats render to stderr only. Stdout stays pure NDJSON so piping
// `certscout service | export_domains.py` keeps working.

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

// newLiveStatsRenderer returns a ProgressFunc that rewrites one animated,
// colorized status line in place (carriage return + clear line, no newline).
// It is safe for concurrent use; only the progress ticker calls it.
func newLiveStatsRenderer(w io.Writer, color bool) func(Stats) {
	var mu sync.Mutex
	frame := 0
	start := time.Now()
	return func(s Stats) {
		mu.Lock()
		defer mu.Unlock()
		frame++
		elapsed := time.Since(start).Round(time.Second)
		rate := 0.0
		if secs := time.Since(start).Seconds(); secs > 0 {
			rate = float64(s.Accepted) / secs
		}
		var line string
		if color {
			const (
				reset  = "\x1b[0m"
				cyan   = "\x1b[36m"
				green  = "\x1b[32;1m"
				red    = "\x1b[31m"
				yellow = "\x1b[33m"
				dim    = "\x1b[2m"
			)
			line = fmt.Sprintf("%s%s%s %s %s in %s%d%s · accepted %s%d%s · %stcp %d%s · %scerts %d%s · %serrors %d%s %s%.0f/s%s",
				cyan, spinnerFrames[frame%len(spinnerFrames)], reset,
				dim, elapsed, yellow, s.Input, reset,
				dim, s.Accepted, reset,
				cyan, s.TCPConnected, reset,
				green, s.Certificates, reset,
				red, s.Errors, reset,
				dim, rate, reset)
		} else {
			line = fmt.Sprintf("%s %s in %d · accepted %d · tcp %d · certs %d · errors %d %.0f/s",
				spinnerFrames[frame%len(spinnerFrames)], elapsed,
				s.Input, s.Accepted, s.TCPConnected, s.Certificates, s.Errors, rate)
		}
		fmt.Fprintf(w, "\r\x1b[2K%s", line)
	}
}

// snapshotStats deep-copies s so the progress callback never races the
// results loop over the Ports map.
func snapshotStats(s Stats) Stats {
	out := s
	if s.Ports != nil {
		out.Ports = make(map[string]*PortStats, len(s.Ports))
		for k, v := range s.Ports {
			if v == nil {
				continue
			}
			cp := *v
			out.Ports[k] = &cp
		}
	}
	return out
}
