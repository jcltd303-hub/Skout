# Certificate Scout Implementation Plan

> For agentic workers: use superpowers:executing-plans to implement this plan inline, with a final independent review.

**Goal:** collect certificate names with endpoint evidence efficiently.
**Architecture:** a standard-library Go collector plugs into ip4scout and a
standalone CLI; a Python/SQLite reducer stores and exports results.
**Tech stack:** Go standard library, existing Kong CLI, Python 3 / SQLite.
**Spec:** ../specs/2026-10-14-certificate-scout-design.md

## Global Constraints

- No live Internet scans or upstream publication during development.
- Preserve the original random command and l9format domain-array output.
- All network calls use deadlines, rate caps and cancellation.
- Bounded endpoint cache and worker queue; one output writer.
- Wildcards remain literal; certificate collection does not assert trust.

## Review Focus

- Fragmented or multiline STARTTLS replies must complete correctly.
- Invalid numeric flags and input must fail before a network connection.
- Slow output must apply backpressure without corrupting JSON.
- Timeout retries must obey the global connection-start cap.
- Replaying reducer inputs must retain provenance without duplicates.

### Task 1: Names, endpoint parsing and upstream fixes

Files: `certificates/types.go`, `certificates/names.go`, their tests,
`utils.go`, `utils_test.go`, `random.go`, `synack.go`, `synack_test.go`.
Interfaces: `Target`, `ParseTarget([]byte) (Target,error)`,
`NormalizeName(string) (string,bool)`, `CertificateNames(*x509.Certificate) []string`.

- [x] Write normalization, endpoint validation, port range and packet fixture tests.
- [x] Observe failures against absent/new behavior.
- [x] Implement pure parsing and SYN/ACK validation; add certificate profile.
- [x] Verify task tests and commit.

### Task 2: Certificate collector and streaming CLI

Files: `certificates/collector.go`, `certificates/runner.go`, their tests,
`cmd/certscout/main.go`, `cmd/ip4scout/main.go`.
Interfaces: `Collect(context.Context,Target,Options) ([]Event,error)`,
`Run(context.Context,io.Reader,io.Writer,Options) (Stats,error)`,
`Command.Run() error` for Kong and standalone `Main([]string) int`.

- [x] Write loopback TLS/STARTTLS/SNI, timeout/retry/cancellation, queue and JSON tests.
- [x] Observe failures, implement collector and runner, and verify tests.
- [x] Wire both CLIs, build and check help/input failures, then commit.

### Task 3: Durable reducer and delivery

Files: `tools/export_domains.py`, `tools/test_export_domains.py`,
`README-certificate-scout.md`, `VALIDATION.md`.
Interfaces: CLI stdin NDJSON → SQLite observations + sorted domain export.

- [x] Write SQLite replay, schema/null/malformed-input and provenance tests.
- [x] Observe failures, implement reducer and run its full suite.
- [x] Run Go suite/race/vet/build and CLI smoke checks; review the complete diff.
- [x] Document verified behavior and limitations; create a portable patch package.
