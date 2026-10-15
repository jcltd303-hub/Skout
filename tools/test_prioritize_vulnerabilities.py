import copy
from datetime import date, datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse


TOOL = Path(__file__).with_name("prioritize_vulnerabilities.py")
if TOOL.exists():
    spec = importlib.util.spec_from_file_location("prioritize_vulnerabilities", TOOL)
    priority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(priority)
else:
    priority = None

TODAY = date(2026, 10, 15)
NOW = datetime(2026, 10, 15, 1, 0, tzinfo=timezone.utc)


def kev_doc(*cves):
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.10.14",
        "dateReleased": "2026-10-14T19:27:28.0105Z",
        "count": len(cves),
        "vulnerabilities": [{
            "cveID": cve, "vendorProject": "Fixture Vendor", "product": "Fixture Product",
            "vulnerabilityName": "Fixture vulnerability", "dateAdded": "2026-10-14",
            "shortDescription": "Synthetic test fixture", "requiredAction": "Apply vendor updates.",
            "dueDate": "2026-11-04", "knownRansomwareCampaignUse": "Unknown",
            "notes": "", "cwes": ["CWE-20"],
        } for cve in cves],
    }


def epss_doc(*values):
    return {
        "status": "OK", "status-code": 200, "version": "1.0", "access": "public",
        "total": len(values), "offset": 0, "limit": max(100, len(values)),
        "data": [{"cve": cve, "epss": str(score), "percentile": "0.99", "date": "2026-10-14"}
                 for cve, score in values],
    }


def finding(cve, asset="host.example.test", evidence="Version confirmed in inventory"):
    return {"asset": asset, "cve": cve, "source": "inventory", "evidence": evidence}


class PriorityCoreTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(priority, "top-20 vulnerability prioritizer is missing")

    def report(self, findings, kev=(), scores=(), top=20):
        return priority.build_report(
            findings, priority.parse_kev(kev_doc(*kev), TODAY, 30),
            priority.parse_epss(epss_doc(*scores), TODAY, 3), top, NOW,
        )

    def test_known_exploitation_precedes_probability_and_ties_are_stable(self):
        cves = ["CVE-2026-0004", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"]
        report = self.report([finding(cve) for cve in cves],
                             kev=("CVE-2026-0001",),
                             scores=(("CVE-2026-0001", .01), ("CVE-2026-0002", .98),
                                     ("CVE-2026-0003", .98), ("CVE-2026-0004", .20)))
        rows = report["vulnerabilities"]
        self.assertEqual([row["cve"] for row in rows],
                         ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"])
        self.assertEqual([row["rank"] for row in rows], [1, 2, 3, 4])
        self.assertTrue(rows[0]["known_exploited"])
        self.assertEqual(rows[0]["kev"]["requiredAction"], "Apply vendor updates.")
        self.assertEqual(rows[0]["findings"][0]["asset"], "host.example.test")
        self.assertEqual(report["sources"]["epss"]["score_date"], "2026-10-14")
        self.assertEqual(report["applicability"], "supplied_inventory_not_verified")

    def test_zero_is_scored_and_missing_is_unknown_within_each_tier(self):
        cves = ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]
        report = self.report([finding(cve) for cve in cves], kev=(cves[0], cves[1]),
                             scores=((cves[0], 0), (cves[2], 0)))
        self.assertEqual([row["cve"] for row in report["vulnerabilities"]], cves)
        self.assertEqual(report["vulnerabilities"][0]["epss"], 0.0)
        self.assertIsNone(report["vulnerabilities"][1]["epss"])
        self.assertEqual(report["unscored_cves"], [cves[1], cves[3]])

    def test_top_limit_counts_unique_cves_without_padding(self):
        findings = [finding(f"CVE-2026-{i:04d}") for i in range(1, 26)]
        report = self.report(findings)
        self.assertEqual(len(report["vulnerabilities"]), 20)
        self.assertEqual(report["unique_cves"], 25)
        self.assertEqual(report["returned_cves"], 20)
        self.assertEqual(len(report["unscored_cves"]), 25)
        self.assertEqual(len(self.report(findings[:2])["vulnerabilities"]), 2)
        self.assertEqual(len(self.report(findings, top=3)["vulnerabilities"]), 3)
        with self.assertRaises(ValueError):
            self.report(findings, top=0)

    def test_inventory_normalizes_ids_deduplicates_and_preserves_distinct_evidence(self):
        first = finding(" cve-2026-0001 ")
        second = finding("CVE-2026-0001", asset="other.example.test")
        third = finding("CVE-2026-0001", evidence="Second observation")
        stream = io.StringIO("\n".join(json.dumps(row) for row in [first, first, second, third]))
        findings = priority.load_inventory(stream)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["cve"], "CVE-2026-0001")
        report = self.report(findings)
        self.assertEqual(report["input_findings"], 3)
        self.assertEqual(len(report["vulnerabilities"][0]["findings"]), 3)
        self.assertEqual(report["vulnerabilities"][0]["findings"][2]["evidence"], "Second observation")

    def test_invalid_inventory_fails_with_line_context(self):
        invalid = ["null", "[]", "{broken", '{}',
                   json.dumps({"asset": "a", "cve": "CVE-2026-1"}),
                   json.dumps({"asset": "", "cve": "CVE-2026-0001"}),
                   json.dumps({"asset": "a", "cve": "CVE-2026-0001", "evidence": []}),
                   json.dumps({"ip": "192.0.2.1", "port": "443", "ssl": {}})]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "line 2"):
                priority.load_inventory(io.StringIO("\n" + raw))
        with self.assertRaises(ValueError):
            priority.load_inventory(io.StringIO("\n"))

    def test_inventory_is_bounded(self):
        row = json.dumps(finding("CVE-2026-0001")) + "\n"
        with self.assertRaises(ValueError):
            priority.load_inventory(io.StringIO(row * 10001))
        with self.assertRaises(ValueError):
            priority.load_inventory(io.StringIO(json.dumps(finding("CVE-2026-0001", evidence="x" * (8 * 1024 * 1024)))))

    def test_kev_rejects_count_duplicates_and_invalid_entries(self):
        doc = kev_doc("CVE-2026-0001")
        cases = []
        changed = copy.deepcopy(doc); changed["count"] = 2; cases.append(changed)
        changed = kev_doc("CVE-2026-0001", "CVE-2026-0001"); cases.append(changed)
        changed = copy.deepcopy(doc); changed["vulnerabilities"][0]["cveID"] = "junk"; cases.append(changed)
        changed = copy.deepcopy(doc); changed["vulnerabilities"][0]["requiredAction"] = None; cases.append(changed)
        for bad in cases:
            with self.subTest(doc=bad), self.assertRaises(ValueError):
                priority.parse_kev(bad, TODAY, 30)

    def test_kev_timestamp_must_be_aware_current_and_not_future(self):
        for released in ["2026-08-01T00:00:00Z", "2026-10-16T00:00:00Z", "2026-10-14T00:00:00", "garbage"]:
            bad = kev_doc(); bad["dateReleased"] = released
            with self.subTest(released=released), self.assertRaises(ValueError):
                priority.parse_kev(bad, TODAY, 30)
        boundary = kev_doc(); boundary["dateReleased"] = "2026-09-15T00:00:00Z"
        self.assertEqual(priority.parse_kev(boundary, TODAY, 30)["date_released"], "2026-09-15T00:00:00Z")

    def test_epss_rejects_bad_status_incomplete_pagination_and_duplicates(self):
        doc = epss_doc(("CVE-2026-0001", .5))
        cases = []
        for key, value in [("status", "ERROR"), ("status-code", 500), ("total", 2), ("offset", 1), ("limit", 0)]:
            changed = copy.deepcopy(doc); changed[key] = value; cases.append(changed)
        cases.append(epss_doc(("CVE-2026-0001", .5), ("CVE-2026-0001", .7)))
        for bad in cases:
            with self.subTest(doc=bad), self.assertRaises(ValueError):
                priority.parse_epss(bad, TODAY, 3)

    def test_epss_rejects_nonfinite_out_of_range_boolean_and_missing_scores(self):
        for key in ("epss", "percentile"):
            for value in ["nan", "inf", "-0.1", "1.1", True, None, []]:
                bad = epss_doc(("CVE-2026-0001", .5)); bad["data"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    priority.parse_epss(bad, TODAY, 3)

    def test_epss_rejects_future_stale_and_mixed_dates(self):
        for score_date in ["2026-10-16", "2026-10-11", "invalid"]:
            bad = epss_doc(("CVE-2026-0001", .5)); bad["data"][0]["date"] = score_date
            with self.subTest(score_date=score_date), self.assertRaises(ValueError):
                priority.parse_epss(bad, TODAY, 3)
        mixed = epss_doc(("CVE-2026-0001", .5), ("CVE-2026-0002", .7))
        mixed["data"][1]["date"] = "2026-10-13"
        with self.assertRaises(ValueError):
            priority.parse_epss(mixed, TODAY, 3)
        valid = epss_doc(("CVE-2026-0001", .5)); valid["data"][0]["date"] = "2026-10-12"
        self.assertEqual(priority.parse_epss(valid, TODAY, 3)["score_date"], "2026-10-12")

    def test_empty_epss_response_preserves_unknown_date(self):
        parsed = priority.parse_epss(epss_doc(), TODAY, 3)
        self.assertEqual(parsed["scores"], {})
        self.assertIsNone(parsed["score_date"])


class PriorityTransportTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(priority is not None and hasattr(priority, "fetch_epss"),
                        "feed transport is missing")

    def test_batches_respect_count_and_query_length_and_keep_asset_evidence_local(self):
        cves = [f"CVE-2026-{i:019d}" for i in range(205)]
        requested = []

        def serve(request, timeout):
            self.assertEqual(timeout, 20)
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.netloc, url.path), ("https", "api.first.org", "/data/v1/epss"))
            query = urllib.parse.parse_qs(url.query)
            self.assertEqual(set(query), {"cve", "limit"})
            self.assertEqual(query["limit"], ["100"])
            batch = query["cve"][0].split(",")
            self.assertLessEqual(len(batch), 100)
            self.assertLessEqual(len(query["cve"][0]), 2000)
            requested.extend(batch)
            return io.BytesIO(json.dumps(epss_doc(*((cve, .5) for cve in batch))).encode())

        with patch.object(priority.urllib.request, "urlopen", side_effect=serve):
            parsed = priority.fetch_epss(cves, TODAY, 3)
        self.assertEqual(requested, sorted(cves))
        self.assertEqual(len(parsed["scores"]), 205)

    def test_batches_respect_100_entry_limit_even_for_short_ids(self):
        sizes = []

        def serve(request, timeout):
            batch = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["cve"][0].split(",")
            sizes.append(len(batch))
            return io.BytesIO(json.dumps(epss_doc(*((cve, .1) for cve in batch))).encode())

        with patch.object(priority.urllib.request, "urlopen", side_effect=serve):
            priority.fetch_epss([f"CVE-2026-{i:04d}" for i in range(205)], TODAY, 3)
        self.assertEqual(sizes, [100, 100, 5])

    def test_absent_requested_score_stays_missing_but_unexpected_score_fails(self):
        with patch.object(priority.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(epss_doc()).encode())):
            parsed = priority.fetch_epss(["CVE-2026-0001"], TODAY, 3)
        self.assertEqual(parsed["scores"], {})
        unrelated = epss_doc(("CVE-2026-9999", .9))
        with patch.object(priority.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(unrelated).encode())):
            with self.assertRaises(ValueError):
                priority.fetch_epss(["CVE-2026-0001"], TODAY, 3)

    def test_date_rollover_between_batches_fails(self):
        def serve(request, timeout):
            batch = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["cve"][0].split(",")
            doc = epss_doc(*((cve, .5) for cve in batch))
            if len(batch) == 1:
                doc["data"][0]["date"] = "2026-10-13"
            return io.BytesIO(json.dumps(doc).encode())

        with patch.object(priority.urllib.request, "urlopen", side_effect=serve), self.assertRaises(ValueError):
            priority.fetch_epss([f"CVE-2026-{i:04d}" for i in range(101)], TODAY, 3)

    def test_transport_failure_has_no_retry_and_response_bytes_are_bounded(self):
        with patch.object(priority.urllib.request, "urlopen", side_effect=urllib.error.URLError("unavailable")) as opened:
            with self.assertRaises(ValueError):
                priority.fetch_epss(["CVE-2026-0001"], TODAY, 3)
        self.assertEqual(opened.call_count, 1)
        huge = io.BytesIO(b" " * (8 * 1024 * 1024 + 2))
        with patch.object(priority.urllib.request, "urlopen", return_value=huge), self.assertRaises(ValueError):
            priority.fetch_json(priority.KEV_URL)
        with patch.object(priority.urllib.request, "urlopen", return_value=io.BytesIO(b"{invalid")):
            with self.assertRaises(ValueError):
                priority.fetch_json(priority.KEV_URL)


class PriorityCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "inventory.jsonl"
        self.kev = self.root / "kev.json"
        self.epss = self.root / "epss.json"
        self.output = self.root / "top20.json"
        self.inventory.write_text(json.dumps(finding("CVE-2026-0001")) + "\n", encoding="utf-8")
        doc = kev_doc("CVE-2026-0001")
        doc["dateReleased"] = datetime.now(timezone.utc).isoformat()
        self.kev.write_text(json.dumps(doc), encoding="utf-8")
        doc = epss_doc(("CVE-2026-0001", .75))
        doc["data"][0]["date"] = datetime.now(timezone.utc).date().isoformat()
        self.epss.write_text(json.dumps(doc), encoding="utf-8")

    def run_cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                              input=stdin, capture_output=True, text=True, timeout=10)

    def offline_args(self):
        return ["--inventory", self.inventory, "--offline", "--kev-file", self.kev, "--epss-file", self.epss]

    def test_offline_cli_emits_ranked_report_and_provenance(self):
        run = self.run_cli(*self.offline_args())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(run.stdout.strip(), "CLI produced no report")
        report = json.loads(run.stdout)
        self.assertEqual(report["top"], 20)
        self.assertEqual(report["vulnerabilities"][0]["epss"], .75)
        self.assertEqual(report["sources"]["kev"]["loaded_from"], str(self.kev))
        self.assertEqual(report["sources"]["epss"]["loaded_from"], str(self.epss))
        self.assertEqual(run.stderr, "")

    def test_offline_cli_accepts_stdin_and_atomic_file_output(self):
        args = self.offline_args(); args[1] = "-"
        run = self.run_cli(*args, "--output", self.output, "--top", "1", stdin=self.inventory.read_text())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(self.output.exists(), "report output is missing")
        self.assertEqual(json.loads(self.output.read_text())["returned_cves"], 1)
        self.assertEqual(run.stdout, "")
        self.assertEqual(sorted(path.name for path in self.root.iterdir()),
                         ["epss.json", "inventory.jsonl", "kev.json", "top20.json"])

    def test_invalid_inventory_stops_before_any_feed_request(self):
        self.inventory.write_text('{"asset":"a","cve":"invalid"}\n')
        run = self.run_cli("--inventory", self.inventory)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, "")
        self.assertIn("line 1", run.stderr)

    def test_stale_feed_does_not_replace_existing_report(self):
        self.output.write_text("previous report\n")
        doc = json.loads(self.epss.read_text()); doc["data"][0]["date"] = "2020-01-01"
        self.epss.write_text(json.dumps(doc))
        run = self.run_cli(*self.offline_args(), "--output", self.output)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(run.stdout, "")
        self.assertIn("stale", run.stderr)
        self.assertEqual(self.output.read_text(), "previous report\n")

    def test_redirected_stdin_inventory_cannot_be_overwritten(self):
        original = self.inventory.read_bytes()
        args = self.offline_args(); args[1] = "-"
        with self.inventory.open("rb") as stream:
            run = subprocess.run(
                [sys.executable, str(TOOL), *map(str, args), "--output", str(self.inventory)],
                stdin=stream, capture_output=True, text=True, timeout=10,
            )
        self.assertNotEqual(run.returncode, 0, "redirected inventory was replaced by a report")
        self.assertEqual(run.stdout, "")
        self.assertEqual(self.inventory.read_bytes(), original)

    def test_invalid_config_and_input_overwrite_fail_without_output(self):
        cases = [
            ["--inventory", self.inventory, "--offline"],
            [*self.offline_args(), "--top", "0"],
            [*self.offline_args(), "--max-epss-age-days", "-1"],
            [*self.offline_args(), "--output", self.inventory],
            [*self.offline_args(), "--output", self.kev],
        ]
        original = self.inventory.read_text()
        for args in cases:
            with self.subTest(args=args):
                run = self.run_cli(*args)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "")
                self.assertTrue(run.stderr)
        self.assertEqual(self.inventory.read_text(), original)


if __name__ == "__main__":
    unittest.main()
