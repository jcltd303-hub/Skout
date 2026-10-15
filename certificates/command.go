package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Command Options

func (cmd *Command) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	type completion struct {
		stats Stats
		err   error
	}
	done := make(chan completion, 1)
	go func() {
		stats, err := Run(ctx, os.Stdin, os.Stdout, Options(*cmd))
		done <- completion{stats: stats, err: err}
	}()
	report := func(result completion) error { _ = json.NewEncoder(os.Stderr).Encode(result.stats); return result.err }
	select {
	case result := <-done:
		return report(result)
	case <-ctx.Done():
		// Restore default signal behavior so a second interrupt terminates
		// even if a downstream pipe refuses to read.
		stop()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case result := <-done:
			return report(result)
		case <-timer.C:
			return fmt.Errorf("cancelled: output did not drain within 2s: %w", ctx.Err())
		}
	}
}

// Main implements the standalone CLI with no libpcap or raw-socket dependency.
func Main(args []string) int {
	cmd := Command(DefaultOptions())
	fs := flag.NewFlagSet("certscout", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: certscout [service] [flags] < endpoints.jsonl")
		fs.PrintDefaults()
	}
	fs.IntVar(&cmd.MaxThreads, "max-threads", cmd.MaxThreads, "Maximum concurrent certificate workers")
	fs.IntVar(&cmd.QueueSize, "queue-size", cmd.QueueSize, "Maximum queued endpoints")
	fs.IntVar(&cmd.RateLimit, "rate-limit", cmd.RateLimit, "Global TCP connection starts/second, including retries and SNI")
	fs.DurationVar(&cmd.Timeout, "timeout", cmd.Timeout, "Total deadline per connection attempt")
	fs.IntVar(&cmd.Retries, "retries", cmd.Retries, "Additional attempts for timeouts only")
	fs.IntVar(&cmd.SNILimit, "sni-limit", cmd.SNILimit, "Maximum same-IP/port concrete SAN follow-ups")
	fs.IntVar(&cmd.DedupCapacity, "dedup-capacity", cmd.DedupCapacity, "Maximum cached endpoint/SNI keys")
	fs.DurationVar(&cmd.DedupTTL, "dedup-ttl", cmd.DedupTTL, "Endpoint duplicate suppression window")
	fs.StringVar(&cmd.Protocol, "protocol", "auto", "auto, tls, smtp, ftp, imap or pop3")
	if len(args) > 0 && args[0] == "service" {
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		return 2
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return 1
	}
	return 0
}
