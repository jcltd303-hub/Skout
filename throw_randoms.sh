#!/usr/bin/env bash
# throw_randoms.sh — throw random public IPs at the LeakIX/Skout pipeline,
# filtered by masscan's blacklist + mandatory private/reserved ranges.
#
# Root-free: no ip4scout / raw sockets. Generates l9format JSON and pipes it
# to l9tcpid (LeakIX) or certscout (Skout). Only scan targets you own or
# have explicit written permission to test.
#
# Usage:
#   ./throw_randoms.sh [--count N] [--ports 443,8443] [--excludefile FILE]
#                      [--pipeline leakix|skout] [--dry-run] [--tee FILE]
#
#   --count       IP samples (one endpoint per port per sample). Default 100.
#   --ports       Comma-separated ports. Default 443.
#   --excludefile Masscan-format exclusions (CIDR, single IP, first-last).
#                 Default: auto-detect (Skout data/masscan-exclude.conf,
#                 $PREFIX/etc/masscan/exclude.conf, /etc/masscan/exclude.conf).
#   --pipeline    leakix (l9tcpid | l9filter human) or skout
#                 (certscout | export_domains). Default leakix.
#   --dry-run     Print generated l9format JSON only, run no pipeline.
#   --tee FILE    Also save pipeline input (generated JSON) to FILE.
#   --help        Show this help.
#
# Examples:
#   ./throw_randoms.sh --count 200 --ports 443,8443 --dry-run | head
#   ./throw_randoms.sh --count 500 --ports 443 --pipeline skout
#   ./throw_randoms.sh --count 100 --ports 27017,9200 --tee targets.jsonl
set -euo pipefail

COUNT=100
PORTS="443"
EXCLUDEFILE=""
PIPELINE="leakix"
DRY_RUN=0
TEE_FILE=""

usage() { sed -n '2,24p' "$0" | sed 's/^# \?//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count) COUNT="$2"; shift 2 ;;
    --ports) PORTS="$2"; shift 2 ;;
    --excludefile) EXCLUDEFILE="$2"; shift 2 ;;
    --pipeline) PIPELINE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --tee) TEE_FILE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "throw_randoms: unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$PIPELINE" in leakix|skout) ;; *) echo "throw_randoms: --pipeline must be leakix or skout" >&2; exit 2 ;; esac
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then echo "throw_randoms: --count must be a positive integer" >&2; exit 2; fi

# Resolve masscan blacklist: explicit > env > next-to-script > CWD >
# Skout checkout > ~/leakix > system locations.
# Missing file is NOT fatal — mandatory exclusions below still apply.
if [[ -z "$EXCLUDEFILE" ]]; then
  for cand in "${MASSCAN_EXCLUDE:-}" \
      "$(dirname "$0")/masscan-exclude.conf" \
      "$(dirname "$0")/data/masscan-exclude.conf" \
      ./masscan-exclude.conf \
      "$(dirname "$0")/skout/data/masscan-exclude.conf" \
      "$HOME/Skout/data/masscan-exclude.conf" \
      "$HOME/workspace/skout/data/masscan-exclude.conf" \
      "$HOME/leakix/masscan-exclude.conf" \
      "${PREFIX:-}/etc/masscan/exclude.conf" \
      /etc/masscan/exclude.conf; do
    if [[ -n "$cand" && -f "$cand" ]]; then EXCLUDEFILE="$cand"; break; fi
  done
fi
if [[ -n "$EXCLUDEFILE" ]]; then
  echo "throw_randoms: exclusions from $EXCLUDEFILE" >&2
else
  echo "throw_randoms: no masscan exclude file found; using mandatory exclusions only" >&2
  echo "throw_randoms: for the full 332-entry list, run:" >&2
  echo "throw_randoms:   cp ~/Skout/data/masscan-exclude.conf ~/leakix/masscan-exclude.conf" >&2
  echo "throw_randoms:   # or, without a Skout checkout:" >&2
  echo "throw_randoms:   curl -sL https://raw.githubusercontent.com/jcltd303-hub/Skout/main/data/masscan-exclude.conf -o ~/leakix/masscan-exclude.conf" >&2
fi

# Resolve the Skout checkout for the skout pipeline (certscout binary +
# tools/export_domains.py). Env SKOUT_DIR wins; otherwise auto-detect.
resolve_skout_dir() {
  if [[ -n "${SKOUT_DIR:-}" && -d "$SKOUT_DIR/tools" ]]; then echo "$SKOUT_DIR"; return; fi
  for cand in "$(dirname "$0")" "$HOME/Skout" "$HOME/workspace/skout" "$(dirname "$0")/skout" ./skout "$HOME/skout"; do
    if [[ -d "$cand/tools" ]]; then echo "$cand"; return; fi
  done
  echo ""
}
resolve_certscout() {
  if command -v certscout >/dev/null; then command -v certscout; return; fi
  local dir="$1"
  for cand in "$dir/bin/certscout" "$dir/certscout" "${PREFIX:-}/bin/certscout"; do
    if [[ -x "$cand" ]]; then echo "$cand"; return; fi
  done
  echo ""
}

# Generator: Python (fast + correct CIDR/range math) embedded in bash.
# Samples uniformly from allowed space, never from excluded/private ranges.
generate() {
  MASSCAN_EXCLUDE="$EXCLUDEFILE" COUNT="$COUNT" PORTS="$PORTS" python3 - <<'PY'
import ipaddress, json, os, random, signal, sys
# Die silently on SIGPIPE when the downstream pipeline exits early
# (e.g. l9tcpid crash / Ctrl-C) instead of a BrokenPipeError traceback.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

mandatory = """0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/3
240.0.0.0/4
255.255.255.255/32
"""
ranges = []
def add_text(text):
    for raw in text.splitlines():
        v = raw.partition("#")[0].strip()
        if not v:
            continue
        try:
            if "-" in v:
                a, b = (int(ipaddress.IPv4Address(p.strip())) for p in v.split("-", 1))
            elif "/" in v:
                n = ipaddress.IPv4Network(v, strict=False)
                a, b = int(n.network_address), int(n.broadcast_address)
            else:
                a = b = int(ipaddress.IPv4Address(v))
        except ValueError as e:
            print(f"throw_randoms: bad exclusion {v!r}: {e}", file=sys.stderr)
            sys.exit(2)
        ranges.append((a, b))
add_text(mandatory)
path = os.environ.get("MASSCAN_EXCLUDE") or ""
if path:
    try:
        add_text(open(path, encoding="utf-8").read())
    except OSError as e:
        print(f"throw_randoms: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)
# Merge intervals, build allowed gaps, sample uniformly from allowed space.
ranges.sort()
merged = []
for a, b in ranges:
    if not merged or a > merged[-1][1] + 1:
        merged.append([a, b])
    elif b > merged[-1][1]:
        merged[-1][1] = b
allowed, cum, cursor, total = [], [], 0, 0
MAX = (1 << 32) - 1
for a, b in merged:
    if cursor < a:
        allowed.append((cursor, a - 1)); total += a - cursor; cum.append(total)
    cursor = b + 1
if cursor <= MAX:
    allowed.append((cursor, MAX)); total += MAX - cursor + 1; cum.append(total)
if total == 0:
    print("throw_randoms: exclusions leave no targets", file=sys.stderr); sys.exit(2)
import bisect
ports = []
for tok in os.environ["PORTS"].split(","):
    tok = tok.strip()
    if not tok.isdigit() or not 1 <= int(tok) <= 65535:
        print(f"throw_randoms: bad port {tok!r}", file=sys.stderr); sys.exit(2)
    if int(tok) not in ports:
        ports.append(int(tok))
rng = random.SystemRandom()
seen = set()
count = int(os.environ["COUNT"])
for _ in range(count):
    while True:
        rank = rng.randrange(total)
        i = bisect.bisect_right(cum, rank)
        prev = cum[i-1] if i else 0
        ip = str(ipaddress.IPv4Address(allowed[i][0] + rank - prev))
        if all((ip, p) not in seen for p in ports):
            break
    for p in ports:
        seen.add((ip, p))
        try:
            # Port as STRING: l9format (l9tcpid/l9filter/l9explore)
            # defines Port as string; a numeric port fails to unmarshal
            # ("cannot unmarshal number into ... port of type string")
            # and in stock l9tcpid that error path deadlocks in goccm.
            # Skout's collector accepts both, so string works everywhere.
            print(json.dumps({"ip": ip, "port": str(p)}), flush=True)
        except BrokenPipeError:
            # Downstream closed (SIG_DFL usually kills us first; this
            # is the fallback so no traceback ever leaks out).
            try:
                sys.stdout.close()
            except Exception:
                pass
            os._exit(0)
PY
}

# Pipeline: stdout stays l9format until the final human/export step.
if [[ "$DRY_RUN" -eq 1 ]]; then
  generate
  exit 0
fi

run_leakix() {
  command -v l9tcpid >/dev/null || { echo "throw_randoms: l9tcpid not found in PATH (build: cd ~/leakix/l9tcpid && go build -o \$PREFIX/bin/l9tcpid ./cmd/l9tcpid)" >&2; exit 1; }
  command -v l9filter >/dev/null || { echo "throw_randoms: l9filter not found in PATH (build: cd ~/leakix/l9filter && go build -o \$PREFIX/bin/l9filter ./cmd/l9filter)" >&2; exit 1; }
  if [[ -n "$TEE_FILE" ]]; then
    generate | tee "$TEE_FILE" | l9tcpid service --max-threads=100 | l9filter transform -i l9 -o human
  else
    generate | l9tcpid service --max-threads=100 | l9filter transform -i l9 -o human
  fi
}
run_skout() {
  local skout_dir certscout_bin exporter
  skout_dir="$(resolve_skout_dir)"
  certscout_bin="$(resolve_certscout "$skout_dir")"
  if [[ -z "$certscout_bin" ]]; then
    echo "throw_randoms: certscout not found. Build Skout first:" >&2
    echo "throw_randoms:   cd ~/Skout && CGO_ENABLED=0 go build -o \$PREFIX/bin/certscout ./cmd/certscout" >&2
    echo "throw_randoms:   # or set SKOUT_DIR to your checkout: SKOUT_DIR=~/Skout ./throw_randoms.sh --pipeline skout" >&2
    exit 1
  fi
  exporter="$skout_dir/tools/export_domains.py"
  if [[ ! -f "$exporter" ]]; then
    echo "throw_randoms: $exporter not found (SKOUT_DIR=$skout_dir)" >&2; exit 1
  fi
  if [[ -n "$TEE_FILE" ]]; then
    generate | tee "$TEE_FILE" | "$certscout_bin" service --max-threads=100 --rate-limit=50 --timeout=8s | python3 "$exporter" --database scout.sqlite --domains domains.txt --evidence evidence.jsonl --stream
  else
    generate | "$certscout_bin" service --max-threads=100 --rate-limit=50 --timeout=8s | python3 "$exporter" --database scout.sqlite --domains domains.txt --evidence evidence.jsonl --stream
  fi
}
if [[ "$PIPELINE" == "leakix" ]]; then run_leakix; else run_skout; fi
