# Skout

Port exposure and certificate discovery built on [LeakIX/ip4scout](https://github.com/LeakIX/ip4scout).
Discover a shared 20-port service profile, record TCP reachability, collect TLS
certificate names where supported, and retain certificate evidence in SQLite.

The standalone collector uses ordinary TCP connections and needs no libpcap or
raw-socket privileges. The original SYN scanner remains available for endpoint
discovery, with its existing platform requirements.

## Build and run

Requires Go 1.22+ and Python 3.9+.

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

`ip4scout random` accepts `--seed` (deterministic RNG; 0 seeds from crypto/rand),
`--count` (send exactly N packets, then exit; 0 scans forever), `--distinct`
(resample until `--count` targets are distinct; default true), and `--ipv6`
(generate IPv6 targets). `--version` prints the build version for both binaries.
IPv6 mode affects target sampling only: raw IPv6 packet emission is not yet
implemented, so IPv6 targets are skipped at send time with a log line.

`certscout service` accepts `--min-tls-version` (1.0–1.3, default 1.2),
`--verify-chain` (verify against system roots; default is observation-only),
`--http-banner` (best-effort Server/title fetch on ports 443/8443),
`--expiry-within-days` (drop certificate events expiring later than N days;
error events pass through), and `--jarm` (10-probe JARM fingerprint on direct
TLS endpoints; best-effort, empty when any probe fails).

Both `tools/random_targets.py` and the rebuilt `ip4scout random` use the same
bundled [masscan exclusions](data/MASSCAN.md) by default: all 332 active entries
from the pinned upstream file, plus mandatory nonpublic/multicast exclusions.
To add your own masscan-format file, use `--excludefile extra.conf` with either
generator (`-b` also works). Single IPs, CIDRs, inclusive IP ranges and `#`
comments are accepted. Missing/invalid files and fully excluded target spaces
stop generation. The collector still accepts explicitly supplied endpoints.

Both generators now default to **exposure20** when ports are omitted. The
[profile and rationale](docs/port-profile.md) cover container/Kubernetes APIs,
remote access, databases and web services. Inspect the selection without starting
discovery using `python3 tools/random_targets.py --list-ports` or
`./ip4scout random --list-ports`. Explicit `--ports`/`-p` overrides it; select
`--port-profile certificates` for the previous seven-port certificate profile.
One Python sample generates 20 endpoints, so `--count 100` produces 2,000 rows.

Rebuild `certscout` after updating: its new TCP-only mode records reachability on
other service ports without sending application data. Results include `tcp_connected`,
unverified `service_hint` and heuristic `port_review_order`. A reachable port
does not establish an affected product, missing authentication or CVE severity.
The existing masscan exclusions, worker bounds and global rate cap also apply.

## Included

- A shared default 20-port exposure profile with inspectable port selection.
- TCP-only reachability outcomes for services without a supported TLS exchange.
- Direct TLS plus SMTP STARTTLS, FTP AUTH TLS, IMAP STARTTLS and POP3 STLS.
- Masscan exclusion data shared by native and root-free random target generators.
- SAN and common-name collection, preserved wildcard patterns and certificate metadata.
- Bounded worker queue, global connection-start rate cap, timeout retries and shared endpoint/SNI deduplication.
- Optional SNI follow-ups confined to the original IP and port.
- NDJSON success/error outcomes and per-port result counts.
- Durable SQLite evidence, unique-name streaming and restart-safe exports.
- A Termux-compatible top-20 remediation report for supplied CVE findings.

See [the collector guide](README-certificate-scout.md) for protocols, flags,
port profiles, replay instructions, rate tuning and practical limits. See
[validation](VALIDATION.md) for local test results and review corrections.

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
[LeakIX/ip4scout](https://github.com/LeakIX/ip4scout). The Go module path is now
`github.com/jcltd303-hub/Skout`; the old import path `github.com/LeakIX/ip4scout`
was the upstream module path and is no longer used — update imports when vendoring
or forking from this repository. Certificate names are observations
from an endpoint; they do not establish current DNS resolution, ownership or
certificate-chain trust.

The bundled masscan exclusion data retains its [upstream license](data/MASSCAN-LICENSE)
and [source provenance](data/MASSCAN.md).
