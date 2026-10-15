# Changelog

## Unreleased

### Changed

- Module renamed from `github.com/LeakIX/ip4scout` to
  `github.com/jcltd303-hub/Skout`; all Go imports updated. The old import path
  was the upstream LeakIX/ip4scout module path and is no longer used.
- Go directive pinned to `go 1.26.9`; dependencies refreshed with
  `go get -u ./...` (Kong v0.2 → v1.16.1, `go.uber.org/ratelimit` v0.1.0 →
  v0.3.1, `golang.org/x/net` → v0.61.0). `gopacket`, `l9format`, and `arp`
  stayed on their latest available releases.
- `RandomCommand` (`ip4scout random`) rewritten: `RunContext(ctx)` does the
  real work with context cancellation of the send loop and the ACK listener;
  `--seed` (deterministic RNG, 0 = crypto-random), `--count` (finite mode:
  send exactly N packets, then exit), `--distinct` (default true, resample
  until finite-mode targets are distinct), `--ipv6` (sample IPv6 targets).
  No `log.Fatal`/`panic` paths remain in the scanner: routing, pcap, BPF, ARP,
  checksum, serialize, and send errors are returned; the send loop logs send
  failures and continues (100 consecutive failures aborts with an error).
  `RandomPublicIp` now returns `(net.IP, error)`; `AddBLockToBlacklist`
  returns an error instead of exiting.
- Certificate `ParseTarget` accepts integral float ports (`443.0`), rejects
  non-integral floats and bool ports, and reports `missing required field
  "port"` / `missing required field "ip"` for absent fields.
- `NormalizeName` accepts single-label names (`localhost`), underscore labels
  (`_dmarc.example.com`), and IDNs (`münchen.de` → `xn--mnchen-3ya.de` via
  IDNA Punycode). Wildcard preservation, IP rejection, length limits, and
  hyphen rules are unchanged.
- The collector start limiter reserves its slot under the mutex and sleeps
  outside the lock, so concurrent `Wait` calls pace instead of serializing.
- Collector `protocolFor`: the explicit port table (25/587→smtp, 21→ftp,
  143→imap, 110→pop3, 389→ldap, 5222→xmpp, 5432→postgres, 24→lmtp) now takes
  precedence over port-profile hints. Overrides (`--protocol`, endpoint mode)
  still win.
- `handshake` takes the full `Options`; `--min-tls-version` (1.0–1.3, default
  1.2) is validated and mapped to the TLS minimum version.

### Added

- IPv6 exclusion support: IPv6 CIDR/single/range entries parse in exclusion
  files, with a 128-bit `addressAtV6` sampler. Mandatory IPv6 exclusions
  (loopback `::1/128`, link-local `fe80::/10`, ULA `fc00::/7`, multicast
  `ff00::/8`, documentation `2001:db8::/32`) apply when `--ipv6` is set.
  `IsIpPublic` handles IPv6 when the flag is set and keeps returning false for
  non-IPv4 targets when it is not. Limitation: raw IPv6 packet emission is
  not yet implemented; IPv6 targets are generated for sampling and skipped at
  send time.
- Certificate chain evidence: `Certificate.Chain` / `ChainLength` from peer
  certificates after the leaf, plus `ExpiresInDays`. `--verify-chain`
  verifies against system roots (`valid` / `invalid:<err>` / `not_assessed`).
  `--expiry-within-days` drops certificate events expiring later than the
  window; error events pass through.
- JARM: new `certificates/jarm.go` implements the 10-probe JARM fingerprint
  (62-char hex, best-effort empty on any probe failure). `--jarm` enables it
  for direct TLS endpoints; it is off by default.
- HTTP banner: `--http-banner` fetches a best-effort `Server` / `<title>` /
  status on ports 443/8443 without failing the certificate event.
- STARTTLS: `ldap` (RFC 4511 StartTLS extended request), `xmpp`
  (`<starttls/>` / `<proceed`), `postgres` (SSLRequest, `S` proceeds), and
  `lmtp` (SMTP-style exchange) join the supported upgrade protocols.
- `version` package with `Version = "dev"`; `certscout --version`,
  `ip4scout --version`, and `ip4scout random --version` print the binary name
  and version and exit 0.

### Batch 3 — Docs/CI/DX + verification

### Changed

- CI (`.github/workflows/go.yml`): Go version is the `go.mod` pin
  (`1.26.9`); adds a `govulncheck ./...` step; build matrix is
  linux/amd64 + linux/arm64 + darwin/arm64 with `CGO_ENABLED=0` for
  certscout everywhere and `ip4scout` gated to linux/amd64 (libpcap needs
  cgo by design); artifact retention 7 → 30 days. Existing test steps
  (race suite, vet, Python unittest) kept, plus a `gofmt -l .` emptiness
  check.
- Go 1.26.9 rationale: Go 1.23 reached end-of-life when Go 1.25 shipped
  (only the two most recent major releases are supported), so the
  toolchain moves to the pinned 1.26.9, against which `govulncheck ./...`
  reports no vulnerabilities (see VALIDATION.md for the actual run).
- `docs/port-profile.md`: port 5432 row corrected from "TCP only" to
  "PostgreSQL STARTTLS" with a precedence note. Exposure20 merge note:
  the exposure20 profile's `collector_mode` for 5432 is `tcp`, but the
  collector's explicit port table (5432 → postgres) beats profile hints,
  so 5432 endpoints run the PostgreSQL SSLRequest upgrade unless an
  explicit `--protocol` / endpoint `protocol` override wins. Explicit
  port table > profile hint > direct TLS.
- README: `README-certificate-scout.md` folded into `README.md` (protocols
  table incl. new STARTTLS modes + tcp mode + 5432 precedence note, flags
  tables for all binaries/tools, pipeline examples, Termux, replay
  instructions, rate tuning, practical limits) and the separate file
  deleted. All internal links updated; required Go version corrected to
  1.26.9. A stale "no banner fuzzing, deep HTTP, JARM" sentence from the
  pre-Batch-1 guide was dropped — banner and JARM exist as best-effort
  observations.

### Added

- `.github/workflows/release.yml`: on `v*` tags, builds certscout for
  linux/amd64, linux/arm64, darwin/arm64 + ip4scout for linux/amd64,
  stamps `version.Version` with the tag, and attaches binaries + LICENSE +
  `data/` files via `softprops/action-gh-release`.
- `.github/dependabot.yml`: gomod + github-actions, weekly, 5 open PRs each.
- `Makefile`: `build`, `test`, `vet`, `lint` (vet + gofmt check + Python
  byte-compile), `release` (local matrix into `bin/`), `clean`, `termux`
  (`CGO_ENABLED=0 GOOS=android GOARCH=arm64` certscout into
  `bin/certscout-termux`). Makefile matrix, no GoReleaser.
- `ARCHITECTURE.md`: pipeline diagram, package map, data flow, key
  invariants (dedup, exclusions, atomic writes, best-effort JARM/banner).
- `CONTRIBUTING.md`: build/test, commit style, PR checks, fuzz instructions.
- `SECURITY.md`: vulnerability reporting via GitHub Security Advisories,
  scanning-authorization requirement, no active exploitation (discovery
  only: handshakes, no auth attempts, no payloads), data handling
  (certificates are public observations; no credentials).
- `VALIDATION.md`: new "Batch 1–3 hardening validation" section with actual
  Batch 3 results (go test/vet/govulncheck, Python count, builds,
  `--version`, `--list-ports` agreement, smoke, loopback E2E, finite
  determinism, fuzz).
- Go native fuzz: `FuzzNormalizeName`, `FuzzParseTarget`, `FuzzReplyReader`
  in `certificates/fuzz_test.go`; `FuzzParseExclusion` in root
  `fuzz_test.go` (small seed corpora, no crashes in 10s runs).
- Python property-style tests with fixed seed 42:
  `TestNormalizeProperties` in `test_export_domains.py` (normalize never
  crashes, lowercase output, no trailing dot, idempotent) and
  `TestParseProperties` in `test_random_targets.py` (parse_ports /
  exclusion parsing never crash, parse round-trips).
