# Delivered validation

## Batch 1–3 hardening validation

Batch 3 (Docs/CI/DX + full verification), run 2026-10-15 on this tree at
remote HEAD `ba03c90` plus uncommitted Batch 3 changes. Go toolchain
1.26.9 (the `go.mod` pin), Python 3.12, local libpcap dev headers present.

- `go test -race ./... -count=1 -timeout=180s`: **passed** — root,
  certificates, portprofiles packages ok; `cmd/*`, `version` have no test
  files.
- `go vet ./...`: **passed**.
- `govulncheck ./...`: **"No vulnerabilities found."**
- `gofmt -l .`: empty. `git diff --check`: clean.
- `python3 -m unittest discover -s tools -p 'test_*.py' -v`: **74 tests,
  OK** (71 pre-existing + 3 new property-test classes: 1 normalize in
  `test_export_domains.py`, 2 parse/exclusion in `test_random_targets.py`;
  suite runs in ~3.1s).
- Builds: `CGO_ENABLED=0 go build ./cmd/certscout` ok;
  `go build ./cmd/ip4scout` ok (libpcap headers present);
  `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` certscout ok;
  `CGO_ENABLED=0 GOOS=darwin GOARCH=arm64` certscout ok;
  `make termux` ok — output `bin/certscout-termux` verified as
  `ELF 64-bit LSB pie executable, ARM aarch64, ... interpreter
  /system/bin/linker64`.
- `--version`: `certscout dev`, `ip4scout dev`,
  `ip4scout random --version` → `ip4scout dev` (local unstamped builds).
- `--list-ports` agreement: Go `ip4scout random --list-ports` and Python
  `random_targets.py --list-ports` printed identical output for both
  profiles — exposure20:
  `2375,10250,6443,445,3389,5985,5986,5900,22,6379,27017,9200,1433,5432,3306,443,8443,80,8080,21`;
  certificates: `443,587,21,465,993,995,8443`
  (`--certificate-profile` alias agrees too). No docs/code mismatch found.
- Smoke: `python3 tools/random_targets.py --count 5 --ports 443 --seed 42 |
  ./certscout service --max-threads=4 --rate-limit=10 --timeout=3s` exited
  **0** with 5 outcomes: 5 TCP-connected, 0 certificates, 5 errors
  (TLS handshake failures against random public IPs — expected; no crash).
- Loopback E2E: covered by the passing Go suite —
  `TestCollectChainExpiryAndVerify` asserts `chain_length`, `expires_in_days`
  and `chain_validation` on a loopback fixture, and
  `TestHTTPBannerLoopback` asserts the `http_banner` (`server`/`title`/
  `status`) fields. No separate manual E2E was run.
- Finite determinism: `TestRandomSeedDeterminism` **passed**.
- Fuzz (10s each, no crashes): `FuzzNormalizeName` (20,339 execs),
  `FuzzParseTarget` (126,764 execs), `FuzzReplyReader` (130,611 execs),
  `FuzzParseExclusion` (32,846 execs). No `testdata/fuzz/` corpus files
  were left behind (interesting inputs stay in the Go build cache).
- `make build`, `make vet`, `make lint` (vet + gofmt + Python
  byte-compile): all passed.

Documented limits (not verified, not claimed): `CGO_ENABLED=0` does **not**
cover the `ip4scout` SYN scanner — it links libpcap via cgo by design and
builds only where libpcap-dev is installed (CI: linux/amd64). Android
execution is untested on a phone; only the cross-build is verified. No live
scan was performed. JARM is best-effort (empty when any probe fails) and a
JARM fingerprint against a real TLS stack is unverified.

## Exposure20 default profile update

Both endpoint generators now default to the same 20-port selection. Its JSON
source is embedded into Go and read by Python. Explicit ports and the previous
seven-port certificate profile remain available. Profile order is a review
heuristic based on potential exposure impact, not CVSS or a measured exploit
probability. Port-derived service names remain unverified hints.

All 43 Python tests and the full Go race suite passed. New regressions cover
the shared port selection and collector modes, native flags, explicit overrides,
cross-language parity, TCP-only connections sending zero application bytes,
retained TCP evidence on TLS failure, and per-port statistics that do not count
successful TCP-only outcomes as certificate errors. `go vet ./...`, native Linux
builds and the Android ARM64 standalone collector cross-build passed.

The first full race run hit `TestCLIBlockedOutputCancellation/second_interrupt`'s
one-second wall-clock assertion. Five isolated repetitions passed (about 0.22s
per second-interrupt subtest), followed by a passing fresh full race suite.
Cancellation code and its deadline were not changed; the initial timing failure
was not reproduced.

Native default/certificate/override `--list-ports` commands were exercised at
rate zero, exiting before network setup. A standalone CLI smoke test connected
only to a loopback fixture, emitted a successful TCP outcome, sent zero application
bytes and reported one TCP connection with zero certificates/errors. There were
no live Internet scans. Android execution remains untested on a phone.

## Vulnerability prioritization update

The Python prioritizer ranks supplied CVE findings, defaulting to 20 unique CVEs
with KEV membership first and EPSS probability descending within each tier.
It performs no vulnerability probes and does not infer CVEs from certificates.

All 41 Python tests passed, including 23 new prioritization tests. The new
coverage includes ranking/ties, duplicate and distinct evidence, zero versus
missing scores, future/stale/mixed feed dates, malformed inventories and
probabilities, feed counts/pagination, unexpected CVEs, 100-entry/2,000-character
request bounds, no retry on transport failure, offline CLI operation, stdin,
atomic report replacement and unchanged reports after failure. Tests use
offline fixtures and mocked feed transport, with no live feed dependency.

Independent review found one important issue: a redirected stdin inventory
could be replaced when its path was also passed as `--output`. A subprocess
regression reproduced the overwrite before the fix. The output guard now
compares the redirected regular-file descriptor with the output file identity;
the regression and all 41 tests pass after the fix. No findings remain deferred.

The full Go race suite (`-count=1 -timeout=120s`) and `go vet ./...` also passed.
An additional live feed-format smoke check used a synthetic inventory record
and retrieved KEV release `2026-10-14T19:27:28.0105Z` and EPSS scores dated
`2026-10-14`. It connected only to the two official feeds, never to the example
asset. This check is outside CI and is not an assessment of any real host.
The tool uses Python 3.9+ standard-library features; validation ran on Python
3.12. Actual Termux execution remains untested on a phone. Supplied CVE findings
remain unverified by this report.

## Original certificate scout validation

Source baseline: LeakIX/ip4scout commit
`46c7982059652e76402c839e6962a2eb6de4f773`.

Validation used Go 1.27.2, Python 3.12 and local libpcap development/runtime
libraries. Tests and smoke checks used generated certificates and loopback
services. These local checks preceded publication. There was no live Internet
scan, production throughput benchmark, or upstream publication.

## Results

- `go test ./... -count=1`: passed.
- `go test -race ./... -count=1`: passed for both tested packages.
- `go vet ./...`: passed.
- Standalone `certscout` and integrated `ip4scout` builds: passed.
- `ip4scout certs --help`: recognized every collector flag.
- Python reducer suite: 9 tests passed.
- Full CLI → NDJSON → SQLite/live names/evidence export smoke checks: passed
  for both standalone and integrated commands. Each processed one certificate,
  suppressed one repeated endpoint, retained one malformed-input outcome and
  exported three names with correct endpoint provenance. Replaying each result
  imported zero additional certificates and printed no repeated names.

## Coverage

Direct TLS, SMTP STARTTLS, FTP AUTH TLS, IMAP STARTTLS and POP3 STLS;
fragmented/multiline replies; rejected upgrades; bounded protocol response
sizes; total connection deadlines; timeout retry recovery; rate caps applying
to retries and concurrent workers; SNI restricted to the original IP/port;
shared input/follow-up duplicate suppression; common names, wildcard patterns
and SAN provenance; malformed endpoints/options; single-writer JSON output;
failed output; blocked stdin cancellation; bounded CLI cancellation with a
stalled output pipe; second-interrupt termination; cache capacity/expiry;
SQLite replay, restart, streaming, atomic observation rollback and evidence
from different endpoints/times; port-range validation and SYN/ACK packet
validation.

## Independent review and corrections

An independent reviewer inspected implementation commit `751a5fc` against the
design. The reviewer requested changes. All three concrete findings were
reproduced by failing regression tests and corrected in one fix pass:

1. Blocked stdout prevented cancellation: CLI shutdown now permits two seconds
   to drain and restores default signal handling for subsequent interrupts.
2. A CN-only certificate could acquire false SAN provenance: empty SANs are
   serialized as an explicit array, and the reducer distinguishes absent
   legacy SAN metadata from an explicit null/empty field.
3. SNI follow-ups bypassed the input cache: both scheduling paths now share a
   synchronized bounded cache. This was treated as material because redundant
   probes consume the same connection budget that funds useful discoveries.

The independent review was not repeated. Regression tests, the complete race
suite, vet, builds and CLI smoke checks verified the corrected implementation.
The final vet pass also corrected legacy/nonstandard Kong command tags while
preserving both CLI commands.

## Decisions and practical limits

- The requested scout source was not identified separately; upstream ip4scout
  is the deliverable's basis. Cost if this assumption is wrong: these changes
  need integrating into the user's actual scout repository.
- SQLite evidence and exports are authoritative. Exactly-once delivery to an
  arbitrary stdout consumer is not promised; replay the saved JSON to regenerate
  exports after interruption. Cost if a downstream consumer requires that
  guarantee: it needs its own acknowledgement/replay protocol.
- No broader TLS cipher baseline, chain-certificate inventory, or exhaustive
  virtual-host discovery was specified. This version collects the leaf
  certificate with modern Go's supported handshake algorithms and explicitly
  bounded SAN follow-ups. Cost if broader coverage is required: additional
  compatibility/exploration work and more connections.
- The lower-level Go Run API cannot interrupt arbitrary custom blocking
  io.Reader/io.Writer implementations. The CLI manages process cancellation;
  library callers own their stream lifecycle.
- The collector's queue is bounded; this does not couple a separate raw SYN
  sender to TLS throughput or guarantee lossless high-rate packet capture.
- Rate examples are starting values; discovery yield and suitable rates must
  be measured on the actual scan host and input population.

No review findings remain deferred.

## Masscan blacklist update

The pinned masscan snapshot contains all 332 active entries from upstream commit
`8e6b3b0c07a81e8ea61d557c06134a21a6881614`; its active-entry SHA-256 is checked
by a regression test. The native scanner and root-free Python generator use
the same data. A cross-language test compares every merged exclusion interval
and the complete remaining-address count.

The new regressions cover inclusive range/CIDR/single-IP boundaries, comments,
host-bit masking, IPv4 arithmetic at zero and the maximum address, additive
custom files, isolated command state, missing/invalid/unreadable files, and
fully excluded target spaces. An offline PCAP fixture verifies that excluded
SYN/ACK replies are not emitted as collector endpoints. Native exclusion flag
spellings were exercised with rate zero, before network setup. The root-free CLI
was exercised from a different working directory and sampled a two-IP remainder
without rejection loops.

`go test -race ./... -count=1 -timeout=120s`, `go vet ./...`, all 18 Python tests,
native Linux builds and the standalone Android ARM64 cross-build passed.
Android execution was not tested on a phone. No live scanning was performed.

Independent review found no blocking issues. Its one minor finding, Python
accepting CIDR prefix lengths with leading zeros while Go rejected them, was
reproduced by a failing test and corrected. Both parsers now reject those
noncanonical custom entries. The reviewer independently passed the root Go
race tests, all Python tests and 500 randomized interval/rank oracle checks.
