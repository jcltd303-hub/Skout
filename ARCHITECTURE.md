# Architecture

## Pipeline

```
                    ┌─────────────────────┐
  random targets    │  certscout service  │   export_domains.py
  ───────────────   │  (or ip4scout certs)│   ───────────────
  ip4scout random   │                     │   SQLite evidence
  (SYN scanner,     │  TCP connect +      │   + domains.txt
   libpcap)         │  TLS / STARTTLS    │   + evidence.jsonl
        │           │  handshake          │
        │           └────────┬────────────┘
        ▼                    ▼
  tools/random_targets.py ──▶ NDJSON events ──▶ SQLite ──▶ prioritize_vulnerabilities.py
  (root-free, no pcap)    (services.jsonl)    (durable)   (KEV/EPSS ranking of
                                                          supplied CVE findings)
```

1. **Generate** endpoints: `ip4scout random` (raw SYN scanner) or
   `tools/random_targets.py` (root-free sampler). Both draw from the same
   port profile and masscan exclusions; both emit l9format endpoint JSON.
2. **Collect**: `certscout service` / `ip4scout certs` reads endpoint JSON,
   connects, performs the protocol exchange, and emits one NDJSON outcome per
   endpoint (certificate events and error events alike).
3. **Export**: `tools/export_domains.py` ingests NDJSON into SQLite
   (deduplicated by name + endpoint), streams newly discovered names, and
   writes `domains.txt` / `evidence.jsonl` on EOF or replay.
4. **Prioritize** (separate track): `tools/prioritize_vulnerabilities.py`
   ranks *supplied* CVE findings with KEV + EPSS. It never infers CVEs from
   certificates and never connects to inventory assets.

## Package map

| Path | Role |
| --- | --- |
| `cmd/certscout` | Standalone collector binary (pure Go, `CGO_ENABLED=0`). Handles `--version`, delegates to `certificates.Main`. |
| `cmd/ip4scout` | Integrated binary: `random` (SYN scanner) + `certs` (collector). Links libpcap via cgo. |
| `certificates/` | Collector: target parsing/normalization (`types.go`, `names.go`), worker runner (`runner.go`, `command.go`), protocol exchanges (`collector.go`), JARM (`jarm.go`). |
| `portprofiles/` | Shared port profiles. `exposure20.json` is embedded in Go binaries and read by the Python generator. |
| `version/` | Build version (`Version = "dev"`; release builds stamp the tag via `-X`). |
| Root package (`ip4scout`) | SYN scanner (`random.go`), SYN/ACK parsing (`synack.go`), exclusion sets (`blacklist.go`), port parsing (`utils.go`). |
| `tools/random_targets.py` | Root-free endpoint generator (IPv4/IPv6, masscan exclusions). |
| `tools/export_domains.py` | NDJSON → SQLite evidence + domain/evidence exports. |
| `tools/prioritize_vulnerabilities.py` | KEV/EPSS CVE ranking with offline/cache/sarif/csv modes. |
| `data/` | Bundled masscan exclusion snapshot + provenance/license. |

## Data flow

- Endpoints flow as NDJSON (`{"ip","port","host","protocol"}`) between
  generator and collector; collector outcomes are NDJSON events
  (`event_type`, `ssl.certificate`, `tcp_connected`, `error`, …).
- SQLite is the durable store: events are committed before names are
  printed, so replaying saved JSON regenerates identical exports.
- The prioritizer is independent: it reads a findings inventory (JSONL,
  CycloneDX, or SPDX) plus KEV/EPSS feeds and writes a ranked report. It
  shares no state with the collector.

## Key invariants

- **Dedup**: the collector suppresses duplicate endpoint/SNI keys within a
  bounded cache + TTL; SQLite deduplicates names exactly across restarts.
  Replay is idempotent.
- **Exclusions**: both generators apply the same bundled masscan snapshot
  plus mandatory nonpublic/multicast exclusions; custom files are additive.
  Fully excluded target spaces fail before network setup. Explicitly
  supplied endpoints to the collector are caller-selected and bypass
  generator exclusions.
- **Atomic writes**: the reducer's exports and the prioritizer's `--output`
  report are replaced atomically; a failed run never clobbers a good report.
- **Best-effort enrichment**: JARM and HTTP banner failures leave the
  certificate event intact with the field empty/absent.
- **No hidden connections**: the collector never resolves names or connects
  to a new IP; SNI follow-ups stay on the original IP/port. The prioritizer
  never connects to inventory assets.
- **Bounded work**: worker queue, connection-start rate cap, per-attempt
  deadlines, timeout-only retries, bounded reply sizes (128 lines / 64 KiB),
  and bounded caches keep a hostile or slow peer from growing memory
  without bound.
- **Errors are outcomes**: connection/protocol failures produce error
  events, not crashes; malformed input lines produce `input_error` records.
