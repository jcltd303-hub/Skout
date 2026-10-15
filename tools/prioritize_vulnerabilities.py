#!/usr/bin/env python3
"""Prioritize supplied CVE findings using CISA KEV and FIRST EPSS evidence."""

import argparse
import csv
from datetime import date, datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.parse
import urllib.request


KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 10000
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
CVE_SEARCH = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.IGNORECASE)
CRITICALITIES = ("critical", "high", "medium", "low")
CRITICALITY_BOOSTS = {"critical": 0.3, "high": 0.2, "medium": 0.0, "low": 0.0}
CRITICALITY_RANKS = {"critical": 3, "high": 2, "medium": 1, "low": 0}
EXPOSURES = ("internet", "internal", "unknown")
SEVERITIES = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
EXPLOIT_TIERS = {"weaponized": 0, "poc": 1, "none": 2}
POLICY_NOTES = [
    "KEV-unscored outranks non-KEV even at EPSS 0.99 (KEV membership sorts first); "
    "use --kev-epss-floor to change this.",
]


def normalize_cve(value):
    if not isinstance(value, str) or not CVE_PATTERN.fullmatch(value.strip().upper()):
        raise ValueError("cve must have the form CVE-YYYY-NNNN (at least four final digits)")
    return value.strip().upper()


def _append_finding(findings, seen, finding):
    identity = (finding["asset"], finding["cve"], finding["source"],
                finding["evidence"], finding["criticality"], finding["exposure"])
    if identity not in seen:
        findings.append(finding)
        seen.add(identity)


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
            if set(row) - {"asset", "cve", "source", "evidence", "criticality", "exposure"}:
                raise ValueError("finding fields must be asset, cve, source, evidence, criticality and exposure")
            if not isinstance(row.get("asset"), str) or not row["asset"].strip():
                raise ValueError("asset must be a nonempty string")
            cve = normalize_cve(row.get("cve"))
            source, evidence = row.get("source", "supplied_inventory"), row.get("evidence", "")
            if not isinstance(source, str) or not isinstance(evidence, str):
                raise ValueError("source and evidence must be strings")
            criticality = row.get("criticality", "medium")
            if not isinstance(criticality, str) or criticality.strip().lower() not in CRITICALITIES:
                raise ValueError("criticality must be critical, high, medium or low")
            exposure = row.get("exposure", "unknown")
            if not isinstance(exposure, str) or exposure.strip().lower() not in EXPOSURES:
                raise ValueError("exposure must be internet, internal or unknown")
            finding = {"asset": row["asset"].strip(), "cve": cve,
                       "source": source, "evidence": evidence,
                       "criticality": criticality.strip().lower(),
                       "exposure": exposure.strip().lower()}
        except ValueError as error:
            raise ValueError(f"inventory line {line_number}: {error}") from error
        _append_finding(findings, seen, finding)
    if not findings:
        raise ValueError("inventory contains no findings")
    return findings


def _component_asset(component):
    name = component.get("name")
    version = component.get("version")
    if isinstance(name, str) and name.strip():
        if isinstance(version, str) and version.strip():
            return f"{name.strip()}@{version.strip()}"
        return name.strip()
    ref = component.get("bom-ref")
    return ref if isinstance(ref, str) else None


def load_inventory_cyclonedx(doc):
    """CycloneDX JSON: vulnerabilities[]/affects[] map to components, with a
    components[].properties fallback when there is no vulnerabilities array."""
    if not isinstance(doc, dict):
        raise ValueError("CycloneDX inventory must be a JSON object")
    components = doc.get("components", [])
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be an array")
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("invalid CycloneDX component")
    by_ref = {}
    for component in components:
        ref = component.get("bom-ref")
        if isinstance(ref, str):
            asset = _component_asset(component)
            if asset is not None:
                by_ref[ref] = asset
    findings, seen = [], set()
    vulnerabilities = doc.get("vulnerabilities")
    if vulnerabilities is not None and not isinstance(vulnerabilities, list):
        raise ValueError("CycloneDX vulnerabilities must be an array")
    if vulnerabilities:
        for entry in vulnerabilities:
            if not isinstance(entry, dict):
                raise ValueError("invalid CycloneDX vulnerability")
            cve = normalize_cve(entry.get("id"))
            evidence = entry.get("description")
            if not isinstance(evidence, str):
                evidence = ""
            affects = entry.get("affects", [])
            if not isinstance(affects, list):
                raise ValueError(f"CycloneDX {cve}: affects must be an array")
            for affect in affects:
                if not isinstance(affect, dict) or not isinstance(affect.get("ref"), str):
                    raise ValueError(f"CycloneDX {cve}: affects entries need a ref")
                ref = affect["ref"]
                _append_finding(findings, seen, {
                    "asset": by_ref.get(ref, ref), "cve": cve, "source": "cyclonedx",
                    "evidence": evidence, "criticality": "medium", "exposure": "unknown"})
    else:
        for component in components:
            asset = _component_asset(component)
            if asset is None:
                continue
            properties = component.get("properties", [])
            if isinstance(properties, dict):
                items = [{"name": key, "value": value} for key, value in properties.items()]
            elif isinstance(properties, list):
                items = properties
            else:
                raise ValueError("CycloneDX component properties must be an array or object")
            for prop in items:
                if not isinstance(prop, dict):
                    continue
                if "cve" not in str(prop.get("name", "")).lower():
                    continue
                value = prop.get("value")
                if not isinstance(value, str):
                    continue
                try:
                    cve = normalize_cve(value)
                except ValueError:
                    continue
                _append_finding(findings, seen, {
                    "asset": asset, "cve": cve, "source": "cyclonedx",
                    "evidence": "", "criticality": "medium", "exposure": "unknown"})
    if not findings:
        raise ValueError("inventory contains no findings")
    if len(findings) > MAX_FINDINGS:
        raise ValueError("inventory exceeds 10000 findings")
    return findings


def load_inventory_spdx(doc):
    """SPDX JSON: packages[] with externalRefs of referenceType "cve"."""
    if not isinstance(doc, dict):
        raise ValueError("SPDX inventory must be a JSON object")
    packages = doc.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be an array")
    findings, seen = [], set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("invalid SPDX package")
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        version = package.get("versionInfo")
        asset = (f"{name.strip()}@{version.strip()}"
                 if isinstance(version, str) and version.strip() else name.strip())
        refs = package.get("externalRefs", [])
        if not isinstance(refs, list):
            raise ValueError("SPDX externalRefs must be an array")
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if str(ref.get("referenceType", "")).lower() != "cve":
                continue
            locator = ref.get("referenceLocator", "")
            if not isinstance(locator, str):
                continue
            match = CVE_SEARCH.search(locator)
            if not match:
                continue
            _append_finding(findings, seen, {
                "asset": asset, "cve": normalize_cve(match.group(0)), "source": "spdx",
                "evidence": "", "criticality": "medium", "exposure": "unknown"})
    if not findings:
        raise ValueError("inventory contains no findings")
    if len(findings) > MAX_FINDINGS:
        raise ValueError("inventory exceeds 10000 findings")
    return findings


def load_cvss_file(path):
    """NVD-style CVSS: a list or {"vulnerabilities": [...]} of
    {cve, cvss_v31_base_score, cvss_v31_vector, cvss_v31_severity} entries."""
    doc = load_json_file(path)
    if isinstance(doc, dict):
        rows = doc.get("vulnerabilities")
        if not isinstance(rows, list):
            raise ValueError("CVSS file must be a list or an object with a vulnerabilities array")
    elif isinstance(doc, list):
        rows = doc
    else:
        raise ValueError("CVSS file must be a list or an object with a vulnerabilities array")
    entries = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid CVSS entry")
        cve = normalize_cve(row.get("cve"))
        if cve in entries:
            raise ValueError(f"duplicate CVSS entry for {cve}")
        score = row.get("cvss_v31_base_score")
        if isinstance(score, bool) or not isinstance(score, (int, float)) \
                or not math.isfinite(score) or not 0 <= score <= 10:
            raise ValueError(f"CVSS score for {cve} must be a finite number from 0 to 10")
        vector = row.get("cvss_v31_vector", "")
        if not isinstance(vector, str):
            raise ValueError(f"CVSS vector for {cve} must be a string")
        severity = row.get("cvss_v31_severity")
        if severity is None:
            severity_out = None
        elif isinstance(severity, str) and severity.strip().upper() in SEVERITIES:
            severity_out = severity.strip().upper()
        else:
            raise ValueError(f"CVSS severity for {cve} must be NONE, LOW, MEDIUM, HIGH or CRITICAL")
        entries[cve] = {"score": float(score), "vector": vector, "severity": severity_out}
    return entries


def load_exploit_file(path):
    """JSON list of {cve, public_poc, nuclei_template, metasploit} (bools,
    default false) mapped to an exploit-maturity label."""
    doc = load_json_file(path)
    if not isinstance(doc, list):
        raise ValueError("exploit file must be a JSON list")
    entries = {}
    for row in doc:
        if not isinstance(row, dict):
            raise ValueError("invalid exploit entry")
        cve = normalize_cve(row.get("cve"))
        if cve in entries:
            raise ValueError(f"duplicate exploit entry for {cve}")
        flags = {}
        for key in ("public_poc", "nuclei_template", "metasploit"):
            value = row.get(key, False)
            if not isinstance(value, bool):
                raise ValueError(f"exploit {cve}: {key} must be a boolean")
            flags[key] = value
        maturity = ("weaponized" if flags["metasploit"] or flags["nuclei_template"]
                    else "poc" if flags["public_poc"] else "none")
        entries[cve] = {"maturity": maturity, **flags}
    return entries


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


def _kev_tier(is_kev, effective_epss, floor):
    """KEV/floor tier. floor == 0 reproduces the old behavior: every KEV CVE
    sorts above every non-KEV CVE. With floor > 0, a KEV CVE whose effective
    EPSS is missing or below the floor drops below non-KEV CVEs at/above it."""
    if floor == 0:
        return 0 if is_kev else 1
    if is_kev and effective_epss is not None and effective_epss >= floor:
        return 0
    if not is_kev and effective_epss is not None and effective_epss >= floor:
        return 1
    if is_kev:
        return 2
    return 3


def build_report(findings, kev, epss, top=20, generated_at=None, kev_epss_floor=0,
                 cvss=None, criticality_weight=0, exploit=None):
    if type(top) is not int or top < 1:
        raise ValueError("top must be a positive integer")
    if isinstance(kev_epss_floor, bool) or not isinstance(kev_epss_floor, (int, float)) \
            or not math.isfinite(kev_epss_floor) or not 0 <= kev_epss_floor <= 1:
        raise ValueError("kev_epss_floor must be a number from 0 to 1")
    if isinstance(criticality_weight, bool) or not isinstance(criticality_weight, (int, float)) \
            or not math.isfinite(criticality_weight) or criticality_weight < 0:
        raise ValueError("criticality_weight must be a nonnegative number")
    cvss = cvss or {}
    exploit = exploit or {}
    generated_at = generated_at or datetime.now(timezone.utc)
    normalized = []
    for row in findings:
        item = dict(row)
        criticality = str(item.get("criticality", "medium")).lower()
        if criticality not in CRITICALITY_BOOSTS:
            raise ValueError(f"criticality must be critical, high, medium or low, got {item.get('criticality')!r}")
        exposure = str(item.get("exposure", "unknown")).lower()
        if exposure not in EXPOSURES:
            raise ValueError(f"exposure must be internet, internal or unknown, got {item.get('exposure')!r}")
        item["criticality"] = criticality
        item["exposure"] = exposure
        normalized.append(item)
    groups = {}
    for row in normalized:
        groups.setdefault(row["cve"], []).append(row)
    entries, scores = kev["entries"], epss["scores"]

    def maturity_of(cve):
        entry = exploit.get(cve)
        if isinstance(entry, dict):
            return entry.get("maturity", "none")
        return entry or "none"

    def effective_epss(cve):
        score = scores.get(cve)
        value = score["epss"] if score else None
        if value is None or not criticality_weight:
            return value
        best = max(CRITICALITY_RANKS[row["criticality"]] for row in groups[cve])
        boost = CRITICALITY_BOOSTS[[key for key, rank in CRITICALITY_RANKS.items()
                                    if rank == best][0]]
        return min(1.0, value + criticality_weight * boost)

    ordered = sorted(groups, key=lambda cve: (
        _kev_tier(cve in entries, effective_epss(cve), kev_epss_floor),
        EXPLOIT_TIERS[maturity_of(cve)],
        effective_epss(cve) is None,
        -(effective_epss(cve) or 0.0),
        cvss.get(cve) is None,
        -(cvss.get(cve) or {}).get("score", 0.0),
        cve,
    ))
    ranked = []
    for rank, cve in enumerate(ordered[:top], 1):
        score = scores.get(cve)
        ranked.append({
            "rank": rank, "cve": cve, "known_exploited": cve in entries,
            "epss": score["epss"] if score else None,
            "epss_percentile": score["percentile"] if score else None,
            "epss_date": score["date"] if score else None,
            "effective_epss": effective_epss(cve),
            "cvss": cvss.get(cve),
            "exploit_maturity": maturity_of(cve),
            "priority_reason": "cisa_kev" if cve in entries else "epss" if score else "no_epss_score",
            "kev": entries.get(cve), "findings": groups[cve],
        })
    unscored = sorted(set(groups) - set(scores))
    policy_notes = list(POLICY_NOTES)
    if kev_epss_floor:
        policy_notes.append(
            f"KEV EPSS floor is {kev_epss_floor}: KEV CVEs with effective EPSS below "
            "the floor sort below non-KEV CVEs at or above the floor.")
    if criticality_weight:
        policy_notes.append(
            "Effective EPSS adds criticality_weight * boost (critical 0.3, high 0.2) "
            "using each CVE's highest-criticality finding, capped at 1.0.")
    if exploit:
        policy_notes.append(
            "Exploit maturity sorts within each KEV tier: weaponized (Metasploit or "
            "Nuclei template), then proof-of-concept, then none.")
    return {
        "schema_version": 1,
        "generated_at": generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy": "kev_then_epss", "top": top,
        "applicability": "supplied_inventory_not_verified",
        "input_findings": len(findings), "unique_cves": len(groups), "returned_cves": len(ranked),
        "unscored_cves": unscored,
        "policy_notes": policy_notes,
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


def _default_cache_dir():
    return Path.home() / ".cache" / "skout"


def _cache_is_fresh(path, max_age_days):
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age <= max_age_days * 86400


def _read_cached_json(path):
    with path.open("rb") as stream:
        return decode_json(stream.read(MAX_BYTES + 1), str(path))


def _write_cache(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(doc, ensure_ascii=False, sort_keys=True).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _epss_cache_name(cves):
    digest = hashlib.sha256(
        ",".join(sorted({normalize_cve(cve) for cve in cves})).encode("utf-8")).hexdigest()
    return f"epss-{digest}.json"


def _epss_doc_from_scores(parsed):
    rows = [{"cve": cve, "epss": str(value["epss"]), "percentile": str(value["percentile"]),
             "date": value["date"]} for cve, value in sorted(parsed["scores"].items())]
    return {"status": "OK", "status-code": 200, "version": "1.0", "access": "public",
            "total": len(rows), "offset": 0, "limit": max(100, len(rows)), "data": rows}


def _load_cached_kev(cache_dir, today, max_age):
    path = cache_dir / "kev.json"
    if not _cache_is_fresh(path, max_age):
        return None
    try:
        return parse_kev(_read_cached_json(path), today, max_age)
    except (OSError, ValueError):
        # Corrupt or content-stale cache: fall back to a fresh fetch.
        return None


def _load_cached_epss(cache_dir, cves, today, max_age):
    path = cache_dir / _epss_cache_name(cves)
    if not _cache_is_fresh(path, max_age):
        return None
    try:
        return parse_epss(_read_cached_json(path), today, max_age)
    except (OSError, ValueError):
        return None


def report_to_csv(report):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["rank", "cve", "known_exploited", "epss", "epss_percentile",
                     "cvss", "exploit_maturity", "assets"])
    for row in report["vulnerabilities"]:
        assets = sorted({finding["asset"] for finding in row["findings"]})
        cvss = row.get("cvss") or {}
        writer.writerow([
            row["rank"], row["cve"], "true" if row["known_exploited"] else "false",
            "" if row["epss"] is None else row["epss"],
            "" if row["epss_percentile"] is None else row["epss_percentile"],
            "" if cvss.get("score") is None else cvss["score"],
            row.get("exploit_maturity", "none"),
            ";".join(assets),
        ])
    return buffer.getvalue()


def report_to_sarif(report):
    results = []
    for row in report["vulnerabilities"]:
        epss_text = f"EPSS {row['epss']}" if row["epss"] is not None else "EPSS unavailable"
        results.append({
            "ruleId": row["cve"],
            "level": "error" if row["known_exploited"] else "warning",
            "message": {"text": f"{row['priority_reason']}: {row['cve']} ({epss_text})"},
        })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "Skout", "version": "1",
                "informationUri": "https://github.com/jcltd303-hub/Skout", "rules": []}},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def write_report(report, output, fmt="json"):
    if fmt == "json":
        serialized = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    elif fmt == "csv":
        serialized = report_to_csv(report)
    elif fmt == "sarif":
        serialized = report_to_sarif(report)
    else:
        raise ValueError(f"unknown report format {fmt!r}")
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
    parser.add_argument("--inventory-format", choices=("jsonl", "cyclonedx", "spdx"), default="jsonl",
                        help="Inventory document format (default: jsonl)")
    parser.add_argument("--top", type=nonnegative_integer, default=20, help="positive result limit (default: 20)")
    parser.add_argument("--kev-file", help="saved complete CISA KEV JSON instead of downloading it")
    parser.add_argument("--epss-file", help="saved complete FIRST EPSS API JSON instead of querying CVE IDs")
    parser.add_argument("--offline", action="store_true", help="require both feed files; make no network requests")
    parser.add_argument("--max-kev-age-days", type=nonnegative_integer, default=30, help="maximum KEV release age (default: 30)")
    parser.add_argument("--max-epss-age-days", type=nonnegative_integer, default=3, help="maximum EPSS score age (default: 3)")
    parser.add_argument("--kev-epss-floor", type=float, default=0,
                        help="KEV CVEs with EPSS below this floor sort below non-KEV CVEs at or above it (default: 0, KEV always first)")
    parser.add_argument("--cvss-file", help="NVD-style CVSS JSON (list or {vulnerabilities: [...]}) used as the tie-break after EPSS")
    parser.add_argument("--criticality-weight", type=float, default=0,
                        help="add weight * criticality boost (critical 0.3, high 0.2) to EPSS for ranking, capped at 1.0 (default: 0)")
    parser.add_argument("--exploit-file", help="JSON list of {cve, public_poc, nuclei_template, metasploit} for exploit-maturity sorting")
    parser.add_argument("--cache-dir", help="cache directory for online KEV/EPSS responses (default: ~/.cache/skout)")
    parser.add_argument("--no-cache", action="store_true", help="bypass the feed cache for reads and writes")
    parser.add_argument("--format", choices=("json", "csv", "sarif"), default="json",
                        help="report format (default: json)")
    parser.add_argument("--output", help="atomically replace this file after success; default: stdout")
    args = parser.parse_args(argv)
    if args.top == 0:
        parser.error("--top must be positive")
    if not 0 <= args.kev_epss_floor <= 1:
        parser.error("--kev-epss-floor must be from 0 to 1")
    if args.criticality_weight < 0:
        parser.error("--criticality-weight must be nonnegative")
    if args.offline and (not args.kev_file or not args.epss_file):
        parser.error("--offline requires --kev-file and --epss-file")
    if args.output:
        inputs = [args.kev_file, args.epss_file, args.cvss_file, args.exploit_file,
                  args.inventory if args.inventory != "-" else None]
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
        if args.inventory_format == "jsonl":
            if args.inventory == "-":
                findings = load_inventory(sys.stdin)
            else:
                with Path(args.inventory).open(encoding="utf-8") as stream:
                    findings = load_inventory(stream)
        else:
            if args.inventory == "-":
                raw = sys.stdin.read()
            else:
                raw = Path(args.inventory).read_text(encoding="utf-8")
            if len(raw.encode("utf-8")) > MAX_BYTES:
                raise ValueError("inventory exceeds the 8 MiB limit")
            try:
                doc = json.loads(raw)
            except ValueError as error:
                raise ValueError(f"inventory: invalid JSON: {error}") from error
            if args.inventory_format == "cyclonedx":
                findings = load_inventory_cyclonedx(doc)
            else:
                findings = load_inventory_spdx(doc)
        today = datetime.now(timezone.utc).date()
        cache_dir = None if args.no_cache else (
            Path(args.cache_dir) if args.cache_dir else _default_cache_dir())
        if args.kev_file:
            kev = parse_kev(load_json_file(args.kev_file), today, args.max_kev_age_days)
            kev["loaded_from"] = args.kev_file
        else:
            kev = _load_cached_kev(cache_dir, today, args.max_kev_age_days) if cache_dir else None
            if kev is None:
                kev_doc = fetch_json(KEV_URL)
                kev = parse_kev(kev_doc, today, args.max_kev_age_days)
                kev["loaded_from"] = KEV_URL
                if cache_dir is not None:
                    try:
                        _write_cache(cache_dir / "kev.json", kev_doc)
                    except OSError:
                        pass
            else:
                kev["loaded_from"] = str(cache_dir / "kev.json")
        if args.epss_file:
            epss = parse_epss(load_json_file(args.epss_file), today, args.max_epss_age_days)
            epss["loaded_from"] = args.epss_file
        else:
            cve_list = [row["cve"] for row in findings]
            epss = _load_cached_epss(cache_dir, cve_list, today, args.max_epss_age_days) if cache_dir else None
            if epss is None:
                epss = fetch_epss(cve_list, today, args.max_epss_age_days)
                if cache_dir is not None:
                    try:
                        _write_cache(cache_dir / _epss_cache_name(cve_list),
                                     _epss_doc_from_scores(epss))
                    except OSError:
                        pass
            else:
                epss["loaded_from"] = str(cache_dir / _epss_cache_name(cve_list))
        cvss = load_cvss_file(args.cvss_file) if args.cvss_file else {}
        exploit = load_exploit_file(args.exploit_file) if args.exploit_file else {}
        report = build_report(findings, kev, epss, args.top,
                              kev_epss_floor=args.kev_epss_floor, cvss=cvss,
                              criticality_weight=args.criticality_weight, exploit=exploit)
        write_report(report, args.output, args.format)
    except (OSError, ValueError) as error:
        print(f"priority: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
