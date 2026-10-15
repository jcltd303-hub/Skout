# Delivered validation

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
