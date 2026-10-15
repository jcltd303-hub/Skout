#!/usr/bin/env python3
"""Prioritize supplied CVE findings using CISA KEV and FIRST EPSS evidence."""

import argparse
from datetime import date, datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import urllib.parse
import urllib.request


KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10000
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


def normalize_cve(value):
    if not isinstance(value, str) or not CVE_PATTERN.fullmatch(value.strip().upper()):
        raise ValueError("cve must have the form CVE-YYYY-NNNN (at least four final digits)")
    return value.strip().upper()


def load_inventory(stream):
    findings = []
    seen = set()
    total_bytes = count = 0
    for line_number, raw in enumerate(iter(lambda: stream.readline(MAX_BYTES + 1), ""), 1):
        total_bytes += len(raw.encode("utf-8"))
        if total_bytes > MAX_BYTES:
            raise ValueError("inventory exceeds the 8 MiB limit")
        if not raw.strip():
            continue
        count += 1
        if count > MAX_FINDINGS:
            raise ValueError("inventory exceeds 10000 findings")
        try:
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError("each finding must be a JSON object")
            if set(row) - {"asset", "cve", "source", "evidence"}:
                raise ValueError("finding fields must be asset, cve, source and evidence")
            if not isinstance(row.get("asset"), str) or not row["asset"].strip():
                raise ValueError("asset must be a nonempty string")
            cve = normalize_cve(row.get("cve"))
            source, evidence = row.get("source", "supplied_inventory"), row.get("evidence", "")
            if not isinstance(source, str) or not isinstance(evidence, str):
                raise ValueError("source and evidence must be strings")
            finding = {"asset": row["asset"].strip(), "cve": cve,
                       "source": source, "evidence": evidence}
        except ValueError as error:
            raise ValueError(f"inventory line {line_number}: {error}") from error
        identity = tuple(finding.values())
        if identity not in seen:
            findings.append(finding)
            seen.add(identity)
    if not findings:
        raise ValueError("inventory contains no findings")
    return findings


def checked_date(value, today, max_age, label):
    if type(max_age) is not int or max_age < 0:
        raise ValueError("maximum feed age must be a nonnegative integer")
    if not isinstance(value, str):
        raise ValueError(f"{label} date is missing")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"invalid {label} date") from error
    if value != parsed.isoformat():
        raise ValueError(f"{label} date must use YYYY-MM-DD")
    age = (today - parsed).days
    if age < 0 or age > max_age:
        raise ValueError(f"{label} date {value} is future or stale (maximum {max_age} days)")
    return value


def parse_kev(doc, today, max_age):
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("KEV feed must contain a vulnerabilities array")
    if type(doc.get("count")) is not int or doc["count"] != len(doc["vulnerabilities"]):
        raise ValueError("KEV count does not match the complete feed")
    if not isinstance(doc.get("catalogVersion"), str) or not doc["catalogVersion"].strip():
        raise ValueError("KEV catalogVersion is missing")
    try:
        released = doc["dateReleased"]
        if not isinstance(released, str) or not re.match(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T", released):
            raise ValueError("invalid timestamp")
        stamp = datetime.fromisoformat(released.replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            raise ValueError("timezone is missing")
    except (KeyError, ValueError) as error:
        raise ValueError("KEV dateReleased must be an ISO timestamp with a timezone") from error
    checked_date(stamp.astimezone(timezone.utc).date().isoformat(), today, max_age, "KEV")
    entries = {}
    for row in doc["vulnerabilities"]:
        if not isinstance(row, dict):
            raise ValueError("invalid KEV entry")
        cve = normalize_cve(row.get("cveID"))
        if cve in entries:
            raise ValueError(f"duplicate KEV entry for {cve}")
        for key in ("vendorProject", "product", "vulnerabilityName", "requiredAction"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f"KEV {cve}: {key} is missing")
        entries[cve] = dict(row, cveID=cve)
    return {"entries": entries, "catalog_version": doc["catalogVersion"],
            "date_released": released, "url": KEV_URL}


def probability(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{label} must be a finite probability from 0 to 1")
    try:
        number = float(value)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{label} must be a finite probability from 0 to 1") from error
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ValueError(f"{label} must be a finite probability from 0 to 1")
    return number


def parse_epss(doc, today, max_age):
    if not isinstance(doc, dict) or doc.get("status") != "OK" or doc.get("status-code") != 200:
        raise ValueError("EPSS feed did not report success")
    rows = doc.get("data")
    if (not isinstance(rows, list) or type(doc.get("total")) is not int
            or doc["total"] != len(rows) or type(doc.get("offset")) is not int
            or doc["offset"] != 0 or type(doc.get("limit")) is not int
            or doc["limit"] < max(1, len(rows))):
        raise ValueError("EPSS response is incomplete or has invalid pagination")
    scores = {}
    score_date = None
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid EPSS entry")
        cve = normalize_cve(row.get("cve"))
        if cve in scores:
            raise ValueError(f"duplicate EPSS entry for {cve}")
        row_date = checked_date(row.get("date"), today, max_age, "EPSS")
        if score_date is not None and score_date != row_date:
            raise ValueError("mixed EPSS score dates; refresh the feed")
        score_date = row_date
        scores[cve] = {"epss": probability(row.get("epss"), "EPSS score"),
                       "percentile": probability(row.get("percentile"), "EPSS percentile"),
                       "date": row_date}
    return {"scores": scores, "score_date": score_date, "url": EPSS_URL}


def build_report(findings, kev, epss, top=20, generated_at=None):
    if type(top) is not int or top < 1:
        raise ValueError("top must be a positive integer")
    generated_at = generated_at or datetime.now(timezone.utc)
    groups = {}
    for row in findings:
        groups.setdefault(row["cve"], []).append(row)
    entries, scores = kev["entries"], epss["scores"]
    ordered = sorted(groups, key=lambda cve: (
        cve not in entries, cve not in scores, -scores.get(cve, {}).get("epss", 0), cve,
    ))
    ranked = []
    for rank, cve in enumerate(ordered[:top], 1):
        score = scores.get(cve)
        ranked.append({
            "rank": rank, "cve": cve, "known_exploited": cve in entries,
            "epss": score["epss"] if score else None,
            "epss_percentile": score["percentile"] if score else None,
            "epss_date": score["date"] if score else None,
            "priority_reason": "cisa_kev" if cve in entries else "epss" if score else "no_epss_score",
            "kev": entries.get(cve), "findings": groups[cve],
        })
    unscored = sorted(set(groups) - set(scores))
    return {
        "schema_version": 1,
        "generated_at": generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy": "kev_then_epss", "top": top,
        "applicability": "supplied_inventory_not_verified",
        "input_findings": len(findings), "unique_cves": len(groups), "returned_cves": len(ranked),
        "unscored_cves": unscored,
        "sources": {"kev": {key: value for key, value in kev.items() if key != "entries"},
                    "epss": {key: value for key, value in epss.items() if key != "scores"}},
        "limitations": [
            "CVE applicability comes from supplied findings and is not verified by Skout.",
            "EPSS estimates exploitation in the next 30 days, not compromise of a specific asset.",
            "KEV absence or missing EPSS data does not establish safety.",
            "KEV dueDate is CISA catalog metadata, not a universal remediation deadline.",
        ],
        "vulnerabilities": ranked,
    }


def decode_json(raw, source):
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{source}: response exceeds the 8 MiB limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as error:
        raise ValueError(f"{source}: invalid UTF-8 JSON") from error


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Skout-vulnerability-priority/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_BYTES + 1)
    except OSError as error:
        raise ValueError(f"feed request failed for {url}: {error}") from error
    return decode_json(raw, url)


def load_json_file(path):
    with Path(path).open("rb") as stream:
        return decode_json(stream.read(MAX_BYTES + 1), str(path))


def fetch_epss(cves, today, max_age):
    batches = []
    batch = []
    length = 0
    for cve in sorted({normalize_cve(cve) for cve in cves}):
        added = len(cve) + bool(batch)
        if batch and (len(batch) == 100 or length + added > 2000):
            batches.append(batch)
            batch, length, added = [], 0, len(cve)
        batch.append(cve)
        length += added
    if batch:
        batches.append(batch)
    result = {"scores": {}, "score_date": None, "url": EPSS_URL, "loaded_from": EPSS_URL}
    for batch in batches:
        query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": 100})
        parsed = parse_epss(fetch_json(EPSS_URL + "?" + query), today, max_age)
        if set(parsed["scores"]) - set(batch):
            raise ValueError("EPSS returned a CVE outside the requested batch")
        if parsed["score_date"] is not None:
            if result["score_date"] is not None and result["score_date"] != parsed["score_date"]:
                raise ValueError("mixed EPSS score dates between batches; refresh the feed")
            result["score_date"] = parsed["score_date"]
        result["scores"].update(parsed["scores"])
    return result


def write_report(report, output):
    serialized = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(serialized)
        return
    target = Path(output)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=f".{target.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def nonnegative_integer(text):
    try:
        value = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from error
    if value < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Rank supplied CVE findings for remediation: CISA KEV first, then EPSS. "
                    "Default: 20 unique CVEs. No connections are made to inventory assets.",
    )
    parser.add_argument("--inventory", required=True, help="JSONL with asset and cve; '-' reads stdin")
    parser.add_argument("--top", type=nonnegative_integer, default=20, help="positive result limit (default: 20)")
    parser.add_argument("--kev-file", help="saved complete CISA KEV JSON instead of downloading it")
    parser.add_argument("--epss-file", help="saved complete FIRST EPSS API JSON instead of querying CVE IDs")
    parser.add_argument("--offline", action="store_true", help="require both feed files; make no network requests")
    parser.add_argument("--max-kev-age-days", type=nonnegative_integer, default=30, help="maximum KEV release age (default: 30)")
    parser.add_argument("--max-epss-age-days", type=nonnegative_integer, default=3, help="maximum EPSS score age (default: 3)")
    parser.add_argument("--output", help="atomically replace this JSON report after success; default: stdout")
    args = parser.parse_args(argv)
    if args.top == 0:
        parser.error("--top must be positive")
    if args.offline and (not args.kev_file or not args.epss_file):
        parser.error("--offline requires --kev-file and --epss-file")
    if args.output:
        inputs = [args.kev_file, args.epss_file, args.inventory if args.inventory != "-" else None]
        if any(Path(path).resolve() == Path(args.output).resolve() for path in inputs if path):
            parser.error("--output must differ from all input files")
        if args.inventory == "-":
            same_input = False
            try:
                input_stat = os.fstat(sys.stdin.fileno())
                if stat.S_ISREG(input_stat.st_mode):
                    same_input = os.path.samestat(input_stat, Path(args.output).stat())
            except (OSError, ValueError):
                # A pipe/StringIO or a nonexistent output has no shared file to protect.
                pass
            if same_input:
                parser.error("--output must differ from the redirected stdin inventory")
    try:
        if args.inventory == "-":
            findings = load_inventory(sys.stdin)
        else:
            with Path(args.inventory).open(encoding="utf-8") as stream:
                findings = load_inventory(stream)
        today = datetime.now(timezone.utc).date()
        kev_doc = load_json_file(args.kev_file) if args.kev_file else fetch_json(KEV_URL)
        kev = parse_kev(kev_doc, today, args.max_kev_age_days)
        kev["loaded_from"] = args.kev_file or KEV_URL
        if args.epss_file:
            epss = parse_epss(load_json_file(args.epss_file), today, args.max_epss_age_days)
            epss["loaded_from"] = args.epss_file
        else:
            epss = fetch_epss([row["cve"] for row in findings], today, args.max_epss_age_days)
        write_report(build_report(findings, kev, epss, args.top), args.output)
    except (OSError, ValueError) as error:
        print(f"priority: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
