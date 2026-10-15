# Skout

Certificate-focused network discovery built on [LeakIX/ip4scout](https://github.com/LeakIX/ip4scout).
Collect TLS certificate names with endpoint evidence, normalize SANs and common
names, suppress repeated probes, and retain discoveries in SQLite.

The standalone collector uses ordinary TCP connections and needs no libpcap or
raw-socket privileges. The original SYN scanner remains available for endpoint
discovery, with its existing platform requirements.

## Build and run

Requires Go 1.22+ and Python 3.9+.

```bash
go build -o certscout ./cmd/certscout
```

Feed it endpoint JSON from your existing ip4scout binary:

```bash
set -o pipefail
./ip4scout random -r 1000 -p 443,587,21 \
  | ./certscout service --max-threads=100 --rate-limit=50 --timeout=8s \
  | tee services.jsonl \
  | python3 tools/export_domains.py \
      --database scout.sqlite --domains domains.txt \
      --evidence evidence.jsonl --stream
```

To build the integrated scanner and `certs` command, install libpcap development
headers/libraries and run `go build -o ip4scout ./cmd/ip4scout`.

## Included

- Direct TLS plus SMTP STARTTLS, FTP AUTH TLS, IMAP STARTTLS and POP3 STLS.
- SAN and common-name collection, preserved wildcard patterns and certificate metadata.
- Bounded worker queue, global connection-start rate cap, timeout retries and shared endpoint/SNI deduplication.
- Optional SNI follow-ups confined to the original IP and port.
- NDJSON success/error outcomes and per-port result counts.
- Durable SQLite evidence, unique-name streaming and restart-safe exports.

See [the collector guide](README-certificate-scout.md) for protocols, flags,
port profiles, replay instructions, rate tuning and practical limits. See
[validation](VALIDATION.md) for local test results and review corrections.

## Checks

```bash
go test -race ./...
go vet ./...
python3 -m unittest discover -s tools -p 'test_*.py' -v
```

GitHub Actions runs these checks on pushes and pull requests and produces Linux
x86-64 build artifacts. CI uses loopback fixtures; it performs no Internet scan.

## Attribution

Derived from LeakIX/ip4scout, preserving its MIT license and attribution. This
repository begins with a source snapshot; upstream history remains available in
[LeakIX/ip4scout](https://github.com/LeakIX/ip4scout). The original Go module path
is retained for compatibility. Certificate names are observations
from an endpoint; they do not establish current DNS resolution, ownership or
certificate-chain trust.
