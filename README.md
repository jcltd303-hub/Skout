# Skout

Port exposure and certificate discovery built on [LeakIX/ip4scout](https://github.com/LeakIX/ip4scout).
Discover a shared 20-port service profile, record TCP reachability, collect TLS
certificate names where supported, and retain certificate evidence in SQLite.

The standalone collector uses ordinary TCP connections and needs no libpcap or
raw-socket privileges. The original SYN scanner remains available for endpoint
discovery, with its existing platform requirements.

## Build and run

Requires Go 1.26.9 (the `go` directive in `go.mod`) and Python 3.9+.
The collector and reducer introduce no third-party runtime dependencies.

```bash
CGO_ENABLED=0 go build -o certscout ./cmd/certscout
```

On Termux, install dependencies with `pkg install git golang python`, then build
on the phone. Generate random endpoint JSON without root or packet capture:

```bash
set -o pipefail
python3 -u tools/random_targets.py --count 100 --port-profile exposure20 \
  | ./certscout service --max-threads=100 --rate-limit=20 --timeout=5s \
      --retries=1 --sni-limit=2 \
  | tee -a services.jsonl \
  | python3 tools/export_domains.py \
      --database scout.sqlite --domains domains.txt \
      --evidence evidence.jsonl --stream
```

To build the integrated scanner and `certs` command, install libpcap development
headers/libraries and run `go build -o ip4scout ./cmd/ip4scout`.

`certscout --version`, `ip4scout --version`, and `ip4scout random --version`
print the binary name and version and exit 0. Release binaries are stamped
with the tag; local builds report `dev`.

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

The certificate profile covers 443,587,21,465,993,995,8443. The new default
`--port-profile exposure20` selects [20 service ports](docs/port-profile.md).
Explicit `-p` ports take precedence. `--certificate-profile` remains an alias
for selecting the certificate profile. Use `random --list-ports` to inspect
the effective selection before network setup.

## Random targets and masscan exclusions

Both `ip4scout random` and `tools/random_targets.py` use the same bundled
[masscan exclusion snapshot](data/MASSCAN.md): all 332 active IPv4 entries from
the pinned upstream `data/exclude.conf`. It includes CIDRs, individual IPs and
inclusive ranges. Mandatory private, loopback, multicast and reserved-space
exclusions are also retained. The previous recommended/CDN policy is replaced
by this masscan snapshot. The list is local and is not downloaded during scans.

For unrooted Termux, use the root-free generator with the standalone collector:

```bash
pkg install -y git golang python
CGO_ENABLED=0 go build -o certscout ./cmd/certscout
mkdir -p results
set -o pipefail
python3 -u tools/random_targets.py --count 100 --port-profile exposure20 \
  | ./certscout service --max-threads=100 --rate-limit=20 --timeout=5s \
      --retries=1 --sni-limit=2 \
  | tee -a results/services.jsonl \
  | python3 tools/export_domains.py \
      --database results/scout.sqlite --domains results/domains.txt \
      --evidence results/evidence.jsonl --stream
```

`--count` is the number of IP samples, with one endpoint emitted for each listed
port. Samples may repeat; collector/SQLite deduplication still applies. The
generator emits JSON only and makes no connections itself. Its pipe is bounded
by the downstream collector's queue and connection rate.

Add custom exclusions with `--excludefile extra.conf` or `-b extra.conf` on
either generator. Python accepts repeated files; native `--blacklist-file`
also accepts an additional file. When both native spellings are supplied,
their exclusions are combined. Files contain one IPv4
address, CIDR, or inclusive `first-last` range per line; blank lines and `#`
comments are accepted. Invalid/unreadable files and lists excluding every IPv4
address fail before target output or network setup. The native scanner embeds
the defaults, so rebuild it after updating the list. Its existing `-d` flag
disables the masscan snapshot while retaining mandatory exclusions. Explicit
endpoint input to the certificate collector remains caller-selected.

Both generators now default to **exposure20** when ports are omitted. The
[profile and rationale](docs/port-profile.md) cover container/Kubernetes APIs,
remote access, databases and web services. Inspect the selection without starting
discovery using `python3 tools/random_targets.py --list-ports` or
`./ip4scout random --list-ports`. Explicit `--ports`/`-p` overrides it; select
`--port-profile certificates` for the previous seven-port certificate profile.
One Python sample generates 20 endpoints, so `--count 100` produces 2,000 rows.

## Collector behavior

### Protocols

| Input port | Certificate exchange |
| --- | --- |
| 25, 587 | SMTP greeting, EHLO, advertised STARTTLS, positive readiness reply |
| 21 | FTP greeting, AUTH TLS, positive readiness reply |
| 143 | IMAP greeting, tagged STARTTLS, tagged OK reply |
| 110 | POP3 greeting, STLS, +OK reply |
| 389 | LDAP StartTLS extended request (RFC 4511), success result code |
| 5222 | XMPP stream open, `<starttls/>`, `<proceed/>` |
| 5432 | PostgreSQL SSLRequest, `S` proceeds |
| 24 | LMTP (SMTP-style greeting, EHLO, STARTTLS) |
| Exposure-profile ports marked `tcp` | TCP connect/close only; no application bytes or TLS assessment |
| Other ports, including the profile's five TLS ports | Direct TLS handshake |

Precedence: an explicit override wins first (`--protocol`, or an endpoint's
`protocol` field), then the **explicit port table** above, then the
port-profile hint, then direct TLS. The explicit table beats profile hints:
port 5432's exposure20 hint is `tcp`, but the collector runs the PostgreSQL
SSLRequest upgrade for 5432 unless overridden — the hint describes the
conventional service, not the exchange the collector performs. `tcp` never
implies plaintext: it means only reachability was checked. RDP, SMB and
database-specific TLS negotiations beyond the table above are not implemented;
TLS configured on a port normally checked by TCP requires an explicit TLS
override.

Use `--protocol=smtp` (or ftp/imap/pop3/ldap/xmpp/postgres/lmtp/tls/tcp) to
override port hints. A supplied endpoint's `protocol` can also select these
modes.

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
Certificate events also carry `chain_length` (non-leaf peer certificates),
`chain_validation` (`not_assessed` by default; `valid` or `invalid:<err>`
with `--verify-chain`), and `expires_in_days`. With `--http-banner`, events
on ports 443/8443 also carry a `http_banner` object (`server`, `title`,
`status`). With `--jarm`, direct-TLS events carry a `jarm` fingerprint.
Normalized names remain in `.ssl.certificate.domain`, so existing jq filters
still work. `*.example.com` stays a wildcard pattern; `example.com` is not
invented from it. Raw SANs and CN remain available for inspection.

Self-signed and expired certificate observations are retained.
`chain_validation: "not_assessed"` is explicit; `time_valid`, `hostname_checked`
and `hostname_matches` have separate meanings. A certificate name is evidence
from that endpoint, not proof that the name resolves there or belongs to it.

### Flags

`certscout service` and `ip4scout certs` share the collector flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--max-threads` | 100 | Maximum concurrent service workers (1–4096) |
| `--queue-size` | 200 | Maximum queued endpoints |
| `--rate-limit` | 50 | Global TCP connection starts/second, includes retries and SNI |
| `--timeout` | 8s | Total deadline per connection attempt |
| `--retries` | 1 | Additional attempts for timeouts only (0–10) |
| `--sni-limit` | 0 | Maximum same-endpoint follow-ups using concrete certificate SANs (0–64) |
| `--dedup-capacity` | 100000 | Maximum cached endpoint/SNI keys |
| `--dedup-ttl` | 1h | Endpoint duplicate suppression window |
| `--protocol` | auto | auto, tcp, tls, smtp, ftp, imap, pop3, ldap, xmpp, postgres, lmtp; overrides port hints |
| `--min-tls-version` | 1.2 | Minimum TLS version: 1.0, 1.1, 1.2 or 1.3 |
| `--verify-chain` | off | Verify the certificate chain against system roots |
| `--http-banner` | off | Best-effort Server/title fetch on ports 443/8443; never fails the certificate event |
| `--expiry-within-days` | 0 (off) | Drop certificate events expiring later than N days; error events pass through |
| `--jarm` | off | 10-probe JARM fingerprint on direct-TLS endpoints; best-effort, empty when any probe fails |

`ip4scout random` flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p, --ports` | exposure20 profile | Comma-separated ports; overrides `--port-profile` |
| `--port-profile` | exposure20 | exposure20 or certificates |
| `--certificate-profile` | off | Alias for the certificates profile when `-p` is omitted |
| `--list-ports` | off | Print selected ports and exit before network setup |
| `-r, --rate-limit` | 1000 | Max SYN packets/second |
| `-s, --source-port` | random | Source port |
| `-b, --blacklist-file` | — | Additional exclusions file |
| `--excludefile` | — | Additional masscan-format exclusion file |
| `-d, --disable-recommended` | off | Disable bundled masscan exclusions (mandatory exclusions remain) |
| `--seed` | 0 (crypto-random) | RNG seed for deterministic sampling |
| `--count` | 0 (scan forever) | Send exactly N packets, then exit |
| `--wait-after` | 5 | Seconds to wait after sending `--count` packets for SYN/ACK replies before exiting (`0` exits immediately) |
| `--distinct` | on | With `--count`, resample until target IPs are distinct (`--no-distinct` disables) |
| `--ipv6` | off | Generate IPv6 targets; raw IPv6 packet emission is not implemented, so IPv6 targets are skipped at send time with a log line |

`tools/random_targets.py` flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--count` | 1000 | Number of samples; one endpoint per port per sample |
| `--ports, -p` | exposure20 profile | Comma-separated ports; overrides `--port-profile` |
| `--port-profile` | exposure20 | exposure20 or certificates |
| `--list-ports` | off | Print selected ports and exit without generating endpoints |
| `--excludefile, -b` | — | Additional masscan-format exclusion file; may be repeated |
| `--seed` | system randomness | Seed the RNG for deterministic output |
| `--family` | 4 | Address family: 4, 6, or both |
| `--ipv6` | off | Shorthand for `--family 6` |
| `--distinct` / `--no-distinct` | distinct on | Emit distinct (ip, port) pairs or allow duplicates |

`tools/export_domains.py` flags: `--database`, `--domains`, `--evidence`,
`--stream` (print newly discovered names immediately after committing their
evidence), `--with-timestamps` (export domains as TSV `name, first_seen,
last_seen`), `--metrics` (write JSON ingest metrics to this path, atomically).

### Included

- A shared default 20-port exposure profile with inspectable port selection.
- TCP-only reachability outcomes for services without a supported TLS exchange.
- Direct TLS plus SMTP, FTP, IMAP, POP3, LDAP, XMPP, PostgreSQL and LMTP
  STARTTLS upgrades.
- Masscan exclusion data shared by native and root-free random target generators.
- SAN and common-name collection, preserved wildcard patterns and certificate metadata.
- Chain evidence, expiry filtering, optional chain verification, best-effort
  HTTP banners and JARM fingerprints.
- Bounded worker queue, global connection-start rate cap, timeout retries and shared endpoint/SNI deduplication.
- Optional SNI follow-ups confined to the original IP and port.
- NDJSON success/error outcomes and per-port result counts.
- Durable SQLite evidence, unique-name streaming and restart-safe exports.
- A Termux-compatible top-20 remediation report for supplied CVE findings.

## Tune from measured results

`random -r` measures SYN packets/second. The collector's `--rate-limit` measures
TCP connection starts/second, including timeout retries and SNI follow-ups.
They are different budgets. The sample's 1000/50 settings are starting values,
not a measured optimum for your network. Keep your original 10000 packet rate
only if capture capacity and the downstream collector can support it.

The worker queue and endpoint/SNI cache are bounded. A slow downstream writer
applies backpressure to the collector. It cannot make the separate raw SYN
sender wait for TLS work or guarantee that high-rate packet capture is lossless.
Use the final stderr summary's per-port TCP-connected/certificate/error counts to tune rates
and port selection; more SYN packets do not by themselves prove better yield.

Defaults: 100 workers, 200 queued endpoints, 50 connection starts/second, 8s total
deadline per attempt, one additional attempt for timeouts only, no SNI
follow-ups, 100000 endpoint/SNI cache entries, 1h duplicate suppression.
Cache eviction or expiry can allow an endpoint to be revisited; the SQLite
reducer still deduplicates names exactly. No credentials or application-content
collection is performed; HTTP banner and JARM are best-effort observations that
never fail a certificate event.

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

## Prioritize vulnerability findings

Use an existing vulnerability inventory to produce a **top 20 unique CVEs** by
default. [CISA KEV](https://github.com/cisagov/kev-data) entries sort first;
within each tier, [FIRST EPSS](https://www.first.org/epss/) probability sorts
descending, with CVE ID breaking ties. This is a remediation policy, not a
universal list of the 20 most exploitable vulnerabilities.

On Termux, the Python tool needs no additional packages or root:

```bash
git pull --ff-only
python3 tools/prioritize_vulnerabilities.py \
  --inventory findings.jsonl --top 20 --output top20.json
```

Supply one JSON object per line with `asset` and `cve`. Optional `source` and
`evidence` fields must also be strings; other fields are rejected. This example
shows the schema; replace it with findings from your actual software inventory:

```json
{"asset":"server.example.test","cve":"CVE-2014-0160","source":"inventory export","evidence":"Example only: replace with verified software/version evidence."}
```

The report retains distinct asset/evidence records, removes exact duplicates,
and includes KEV remediation guidance, feed provenance and dates. A zero EPSS
score is retained; unavailable scores are `null` and listed in `unscored_cves`
even when outside the top 20. Fewer than 20 input CVEs produce fewer results.
Input is limited to 10,000 rows and 8 MiB. `--inventory -` reads stdin.

Online mode retrieves CISA's complete official mirror and sends only CVE IDs to
the FIRST API in bounded batches. It never connects to inventory assets. To use
saved feeds without network requests:

```bash
python3 tools/prioritize_vulnerabilities.py --inventory findings.jsonl \
  --offline --kev-file kev.json --epss-file epss.json --output top20.json
```

`kev.json` must be the complete upstream KEV JSON document; `epss.json` must be
a complete [FIRST API response](https://api.first.org/epss/), including its
pagination fields. Missing CVEs in that response remain unscored. Truncated,
malformed, future-dated or stale feeds fail without replacing an existing
`--output` report. Default freshness limits are 30 days for KEV's release and
3 days for EPSS scores, configurable with `--max-kev-age-days` and
`--max-epss-age-days` (zero requires today's date). Mixed EPSS dates fail.
Each feed response is capped at 8 MiB; each request times out after 20 seconds.

CVE applicability is supplied by your inventory and explicitly marked unverified
by Skout. Certificate output alone cannot supply that evidence. EPSS estimates
exploitation in the next 30 days across the population, not the chance of
compromise of a particular asset. Absence from KEV or a missing score does not
establish safety. KEV's `dueDate` is catalog metadata, not a universal deadline.
KEV membership sorts first even when a KEV CVE has no EPSS score and a non-KEV
CVE scores 0.99; use `--kev-epss-floor` to demote KEV CVEs below the floor
under non-KEV CVEs at or above it. Exploit maturity breaks ties within each
tier: weaponized (Metasploit or Nuclei template) sorts above proof-of-concept,
which sorts above none.

Additional flags: `--inventory-format` (jsonl, cyclonedx, spdx),
`--cvss-file` (NVD-style CVSS JSON used as the tie-break after EPSS),
`--criticality-weight` (adds weight × criticality boost — critical 0.3, high
0.2 — to EPSS for ranking, capped at 1.0; default 0),
`--exploit-file` (JSON list of `{cve, public_poc, nuclei_template, metasploit}`
for exploit-maturity sorting), `--cache-dir` (feed cache directory; default
`~/.cache/skout`), `--no-cache` (bypass the feed cache for reads and writes),
`--format` (json, csv, sarif).

## Checks

```bash
make test        # go test -race ./... + Python suite
make vet         # go vet + gofmt check
make lint        # vet + Python byte-compile check
make build       # both binaries for the host platform
```

GitHub Actions runs these checks on pushes and pull requests and produces
build artifacts for linux/amd64, linux/arm64, and darwin/arm64 (retained
30 days). CI uses loopback fixtures; it performs no Internet scan. Tagged
`v*` pushes additionally publish release binaries. See
[ARCHITECTURE.md](ARCHITECTURE.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [validation](VALIDATION.md) for local test
results and review corrections.

## Practical limits

- `CGO_ENABLED=0` covers `certscout` only. The `ip4scout` SYN scanner needs
  libpcap via cgo by design and builds only where libpcap-dev is installed
  (CI: linux/amd64).
- Android execution is untested on a phone; only the cross-build is verified.
- No live Internet scan was performed for validation; tests use generated
  certificates and loopback services.
- JARM is best-effort: empty when any of the 10 probes fails, and a JARM
  fingerprint against a real TLS stack is unverified.
- IPv6 targets are sampled but raw IPv6 packet emission is not implemented;
  IPv6 targets are skipped at send time.
- Rate examples are starting values; discovery yield and suitable rates must
  be measured on the actual scan host and input population.
- Only scan targets you own or are authorized to test — see
  [SECURITY.md](SECURITY.md).

## Attribution

Derived from LeakIX/ip4scout, preserving its MIT license and attribution. This
repository begins with a source snapshot; upstream history remains available in
[LeakIX/ip4scout](https://github.com/LeakIX/ip4scout). The Go module path is now
`github.com/jcltd303-hub/Skout`; the old import path `github.com/LeakIX/ip4scout`
was the upstream module path and is no longer used — update imports when vendoring
or forking from this repository. Certificate names are observations
from an endpoint; they do not establish current DNS resolution, ownership or
certificate-chain trust.

The bundled masscan exclusion data retains its [upstream license](data/MASSCAN-LICENSE)
and [source provenance](data/MASSCAN.md).
