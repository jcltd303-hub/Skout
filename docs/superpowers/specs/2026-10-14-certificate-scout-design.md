# Certificate discovery scout

Goal: specialize the ip4scout → l9tcpid example for collecting useful TLS
certificate names, preserving source evidence and reducing unnecessary probes.
The source is LeakIX/ip4scout at 46c7982059652e76402c839e6962a2eb6de4f773.
No separate user scout repository was found; this deliverable is a portable
refactor package, with no upstream publication or live Internet scan.

## Collection

Add a `certs` command to ip4scout and a standalone `certscout` executable.
Both consume newline-delimited l9format endpoint records on stdin. Target IPs
must be literal IP addresses, ports must be 1..65535, and supplied SNI names
must be valid DNS names. Input hostnames are never resolved as new targets.

Collect a certificate directly for implicit TLS ports. Use SMTP STARTTLS on
25/587, FTP AUTH TLS on 21, IMAP STARTTLS on 143, and POP3 STLS on 110.
Use bounded multiline protocol parsing with positive readiness responses;
protocol refusals produce error records, not false TLS results. Other ports
default to direct TLS. Each connection has a total deadline, context
cancellation, a global connection-start rate cap and configurable timeout
retries. No banner fuzzing, credentials, deep HTTP or JARM is used in this mode.
Optional SNI follow-ups connect only to the same IP and port using names from
the initial certificate, with a configurable limit (default zero).

Emit every accepted endpoint's outcome, including errors, as NDJSON from a
single writer. Preserve IP, port, SNI, protocol, timestamp, attempt count,
certificate SHA-256, SANs, common name, issuer and validity dates. Collection
does not establish certificate chain trust. Distinguish hostname matching and
time validity from trust.

## Scheduling and data

Use a fixed worker pool and bounded queue. Validate all flags before dialing.
Suppress duplicate endpoint/SNI records with a bounded cache and configurable
TTL. Completion order may differ from input order. On cancellation, stop
accepting input, cancel network work and flush completed results. Report
counts and per-port certificate yield on stderr; stdout contains JSON only.

Canonicalize ASCII DNS names: lowercase, remove a terminal dot, preserve
wildcards as literal patterns, reject malformed labels and IP literals.
Include valid common-name evidence as well as SANs, without rewriting a
wildcard into a concrete hostname. Keep expired/self-signed observations.

Provide a Python standard-library reducer that accepts both this output and
existing l9tcpid NDJSON. Use SQLite for durable deduplication and endpoint/name
provenance, with restart-safe transactions. Export sorted unique names and
observation records; repeated input is idempotent. Explain that certificate
names are observations, not proof of current DNS resolution or ownership.

## Upstream compatibility

Keep `random -p ... -r ...` and the existing l9tcpid pipeline working.
Add an opt-in certificate port profile; explicit ports take precedence.
Reject invalid port ranges and nonpositive packet rates. Correct SYN/ACK
handling so non-TCP IPv4 packets cannot become bogus port-zero discoveries.
Keep existing blacklist behavior.

## Verification

Use generated certificates and loopback TCP fixtures to test direct TLS,
SNI, SMTP/FTP/IMAP/POP3 upgrades, split/multiline responses, refused upgrades,
timeouts, retries, cancellation, JSON integrity, deduplication, DNS-name
normalization and malformed flags/input. Verify the original package and new
standalone executable, plus reducer persistence with temporary databases.
