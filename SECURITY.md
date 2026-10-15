# Security

## Reporting a vulnerability

Report vulnerabilities via **GitHub Security Advisories** on this
repository (Security → Report a vulnerability). Do not open a public issue
for a vulnerability until it is fixed. Include reproduction steps, the
affected version/commit, and the impact you observed.

## Scanning authorization

**Only scan targets you own or are explicitly authorized to test.**
Skout sends SYN packets and initiates TCP/TLS connections to the targets it
is pointed at. Unauthorized scanning may violate the law and your network's
acceptable-use policy. The bundled masscan exclusions exist to keep default
generation away from reserved and nonpublic space; they are not a substitute
for authorization.

## No active exploitation

Skout does **discovery only**:

- The SYN scanner sends SYN packets and records SYN/ACK replies.
- The collector performs TCP connects and TLS / STARTTLS handshakes only.
- No authentication attempts, no credentials, no payloads, no exploit
  traffic, no application-content collection beyond a best-effort HTTP
  `Server` header / `<title>` and the JARM handshake fingerprint.
- The prioritizer ranks *supplied* CVE findings; it never probes hosts and
  never infers CVEs from certificates.

## Data handling

- Certificates are **public observations** from an endpoint: names, issuers,
  fingerprints, and validity windows. They do not establish ownership,
  DNS resolution, or chain trust.
- Do not store credentials in Skout output, configs, or reports. Skout has
  no credential inputs; if a fixture or test needs a secret, generate it
  locally and never commit it.
- Scan output (`services.jsonl`, SQLite evidence, domain lists) may reveal
  what you looked at — treat it as sensitive, keep it out of version
  control (it is gitignored), and handle it per your authorization scope.
