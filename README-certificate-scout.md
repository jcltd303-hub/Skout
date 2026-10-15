# Certificate-focused scout

This refactor specializes the original ip4scout/l9tcpid certificate-discovery
example. It adds `ip4scout certs` and a standalone `certscout` that uses ordinary
TCP connections. The standalone collector needs no libpcap or raw-socket
privileges. The existing SYN scanner keeps its original platform requirements.

## Build

Go 1.22+ and Python 3.9+ are required. The collector and reducer introduce no
third-party runtime dependencies.

```bash
go build -o certscout ./cmd/certscout
python3 tools/export_domains.py --help
```

To build the updated raw scanner too, install your platform's libpcap development
headers/libraries, then run:

```bash
go build -o ip4scout ./cmd/ip4scout
```

The old l9format v1.0.0 dependency referenced an unavailable socksme host. This
refactor uses l9format v1.3.1, which removes that dependency, and updates go.sum.

## Replace the certificate stage in your pipeline

Your existing `ip4scout` binary can feed the standalone collector immediately:

```bash
set -o pipefail
./ip4scout random -r 1000 -p 443,587,21 \
  | ./certscout service --max-threads=100 --rate-limit=50 --timeout=8s \
  | tee services.jsonl \
  | python3 tools/export_domains.py \
      --database scout.sqlite --domains domains.txt \
      --evidence evidence.jsonl --stream
```

This prints newly discovered names continuously, saves every collector outcome
in services.jsonl and commits certificate evidence before printing names.
SQLite provides exact name deduplication across repeated input and restarts.
Domains/evidence exports are finalized when input reaches EOF. If the pipeline
is interrupted, regenerate those exports by replaying the saved JSON:

```bash
python3 tools/export_domains.py \
  --database scout.sqlite --domains domains.txt --evidence evidence.jsonl \
  < services.jsonl
```

The same reducer accepts JSON saved by the original l9tcpid pipeline, so old
results can be normalized without rescanning.

With the rebuilt ip4scout, the integrated equivalent is:

```bash
./ip4scout random --certificate-profile -r 1000 \
  | ./ip4scout certs --max-threads=100 --rate-limit=50 \
  | tee services.jsonl
```

The opt-in profile covers 443,587,21,465,993,995,8443. Explicit `-p` ports take
precedence. Existing blacklist behavior and `random -p ... -r ...` remain.

## Collector behavior

| Input port | Certificate exchange |
| --- | --- |
| 25, 587 | SMTP greeting, EHLO, advertised STARTTLS, positive readiness reply |
| 21 | FTP greeting, AUTH TLS, positive readiness reply |
| 143 | IMAP greeting, tagged STARTTLS, tagged OK reply |
| 110 | POP3 greeting, STLS, +OK reply |
| Other ports | Direct TLS handshake |

Use `--protocol=smtp` (or ftp/imap/pop3/tls) for a service on a nonstandard port.
Input is newline-delimited l9format endpoint JSON, for example:

```json
{"ip":"192.0.2.10","port":"443","host":"www.example.com"}
```

`ip` must be a literal IPv4/IPv6 address; numeric ports are also accepted.
`host` is optional and supplies SNI. Certificate names never cause DNS lookup
or a connection to a new IP. Optional `--sni-limit=2` tries up to two concrete
SANs on the original IP/port. Wildcards are not used as SNI candidates.

The collector preserves SANs, valid DNS common names, SHA-256 fingerprint,
issuer, validity dates, SNI, IP/port, protocol, timestamp and attempt count.
Normalized names remain in `.ssl.certificate.domain`, so existing jq filters
still work. `*.example.com` stays a wildcard pattern; `example.com` is not
invented from it. Raw SANs and CN remain available for inspection.

Self-signed and expired certificate observations are retained.
`chain_validation: "not_assessed"` is explicit; `time_valid`, `hostname_checked`
and `hostname_matches` have separate meanings. A certificate name is evidence
from that endpoint, not proof that the name resolves there or belongs to it.

## Tune from measured results

`random -r` measures SYN packets/second. The collector's `--rate-limit` measures
TCP connection starts/second, including timeout retries and SNI follow-ups.
They are different budgets. The sample's 1000/50 settings are starting values,
not a measured optimum for your network. Keep your original 10000 packet rate
only if capture capacity and the downstream collector can support it.

The worker queue and endpoint/SNI cache are bounded. A slow downstream writer
applies backpressure to the collector. It cannot make the separate raw SYN
sender wait for TLS work or guarantee that high-rate packet capture is lossless.
Use the final stderr summary's per-port certificate/error counts to tune rates
and port selection; more SYN packets do not by themselves prove better yield.

Defaults: 100 workers, 200 queued endpoints, 50 connection starts/second, 8s total
deadline per attempt, one additional attempt for timeouts only, no SNI
follow-ups, 100000 endpoint/SNI cache entries, 1h duplicate suppression.
Cache eviction or expiry can allow an endpoint to be revisited; the SQLite
reducer still deduplicates names exactly. No banner fuzzing, deep HTTP, JARM,
credentials, or application-content collection is performed by this mode.

All accepted endpoints receive JSON outcome records, including connection and
protocol errors. Malformed individual input lines produce `input_error` records;
an oversized input line or I/O failure ends the collector with a nonzero exit.
The reducer continues past malformed rows and exits nonzero if it found any.
Ctrl-C cancels queued/network work and flushes outcomes already produced; a
failed or blocked output destination remains an output error, not a successful
completed scan. CLI cancellation allows up to two seconds to drain output;
a second interrupt terminates immediately. The lower-level Go `Run` API uses
ordinary `io.Reader`/`io.Writer` interfaces; arbitrary uninterruptible readers
or writers must be managed by their caller.

## Verification

```bash
go test ./...
go test -race ./certificates
go vet ./...
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

Tests use generated certificates and loopback services. No live Internet
scanning, production throughput benchmark, upstream push or publication was
performed. See VALIDATION.md for the delivered verification results.
