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
	// Live animated stats on stderr only, when attached to a terminal.
	// Stdout stays pure NDJSON for piping. A caller-supplied
	// ProgressFunc (e.g. tests) wins over the built-in renderer.
	live := false
	if !cmd.NoLiveStats && cmd.ProgressFunc == nil && isTerminal(os.Stderr) {
		cmd.ProgressFunc = newLiveStatsRenderer(os.Stderr, useColor())
		live = true
	}
	type completion struct {
		stats Stats
		err   error
	}
	done := make(chan completion, 1)
	go func() {
		stats, err := Run(ctx, os.Stdin, os.Stdout, Options(*cmd))
		done <- completion{stats: stats, err: err}
	}()
	report := func(result completion) error {
		if live {
			// End the rewritten live line before the final JSON summary.
			fmt.Fprintln(os.Stderr)
		}
		_ = json.NewEncoder(os.Stderr).Encode(result.stats)
		return result.err
	}
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
			if live {
				fmt.Fprintln(os.Stderr)
			}
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
	fs.IntVar(&cmd.MaxThreads, "max-threads", cmd.MaxThreads, "Maximum concurrent service workers")
	fs.IntVar(&cmd.QueueSize, "queue-size", cmd.QueueSize, "Maximum queued endpoints")
	fs.IntVar(&cmd.RateLimit, "rate-limit", cmd.RateLimit, "Global TCP connection starts/second, including retries and SNI")
	fs.DurationVar(&cmd.Timeout, "timeout", cmd.Timeout, "Total deadline per connection attempt")
	fs.IntVar(&cmd.Retries, "retries", cmd.Retries, "Additional attempts for timeouts only")
	fs.IntVar(&cmd.SNILimit, "sni-limit", cmd.SNILimit, "Maximum same-IP/port concrete SAN follow-ups")
	fs.IntVar(&cmd.DedupCapacity, "dedup-capacity", cmd.DedupCapacity, "Maximum cached endpoint/SNI keys")
	fs.DurationVar(&cmd.DedupTTL, "dedup-ttl", cmd.DedupTTL, "Endpoint duplicate suppression window")
	fs.StringVar(&cmd.Protocol, "protocol", "auto", "auto, tcp (connect only), tls, smtp, ftp, imap, pop3, ldap, xmpp, postgres or lmtp")
	fs.StringVar(&cmd.MinTLSVersion, "min-tls-version", cmd.MinTLSVersion, "Minimum TLS version: 1.0, 1.1, 1.2 or 1.3")
	fs.BoolVar(&cmd.VerifyChain, "verify-chain", cmd.VerifyChain, "Verify the certificate chain against system roots")
	fs.BoolVar(&cmd.HTTPBanner, "http-banner", cmd.HTTPBanner, "Fetch an HTTP banner (Server + title) on ports 443/8443")
	fs.IntVar(&cmd.ExpiryWithinDays, "expiry-within-days", cmd.ExpiryWithinDays, "Only keep certificates expiring within N days; 0 disables the filter")
	fs.BoolVar(&cmd.JARM, "jarm", cmd.JARM, "Compute the 10-probe JARM fingerprint for direct TLS endpoints")
	fs.BoolVar(&cmd.NoLiveStats, "no-live-stats", cmd.NoLiveStats, "Disable live animated stats on stderr")
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
