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
