import importlib.util
import contextlib
import io
import ipaddress
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).with_name("random_targets.py")
ROOT = SCRIPT.parent.parent
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location("random_targets", SCRIPT)
    targets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(targets)
else:
    targets = None


class RandomTargetTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(targets, "root-free random generator is missing")

    def test_default_profile_emits_twenty_prioritized_endpoints_per_sample(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--count", "1"], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([row["port"] for row in rows], [2375,10250,6443,445,3389,5985,5986,5900,22,6379,27017,9200,1433,5432,3306,443,8443,80,8080,21])
        self.assertEqual(len({row["ip"] for row in rows}), 1)
        self.assertFalse(targets.load_exclusions().contains(rows[0]["ip"]))

    def test_profile_listing_and_explicit_ports_do_not_generate_endpoints(self):
        for args, want in [(["--port-profile", "certificates"], "443,587,21,465,993,995,8443"),
                           (["--ports", "443,22,443"], "443,22"),
                           (["-p", "443,22,443"], "443,22")]:
            result = subprocess.run([sys.executable, str(SCRIPT), *args, "--list-ports"], text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), want)
        result = subprocess.run([sys.executable, str(SCRIPT), "--port-profile", "typo", "--count", "1"], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_masscan_defaults_and_boundary_neighbors(self):
        excluded = targets.load_exclusions()
        for value in ("153.11.0.0", "153.11.255.255", "8.12.162.0", "8.12.164.255", "146.82.55.93", "194.77.40.242", "194.77.40.246", "205.1.2.3", "129.123.0.1", "193.60.0.1", "169.254.1.1", "198.18.0.1", "224.0.0.1", "255.255.255.255"):
            self.assertTrue(excluded.contains(value), value)
        for value in ("1.1.1.1", "8.8.8.8", "8.12.161.255", "8.12.165.0", "146.82.55.92", "146.82.55.94", "194.77.40.243", "104.16.0.1"):
            self.assertFalse(excluded.contains(value), value)

    def test_formats_comments_and_exact_boundaries(self):
        excluded = targets.Exclusions.from_text("# title\n8.8.8.9/24 # host bits\n9.9.9.9\n11.0.0.2 - 11.0.0.4\n")
        for value in ("8.8.8.0", "8.8.8.255", "9.9.9.9", "11.0.0.2", "11.0.0.4"):
            self.assertTrue(excluded.contains(value), value)
        for value in ("8.8.7.255", "8.8.9.0", "9.9.9.8", "9.9.9.10", "11.0.0.1", "11.0.0.5"):
            self.assertFalse(excluded.contains(value), value)

    def test_bad_files_fail_with_line_numbers(self):
        for value in ("bad", "1.1.1.1/33", "1.1.1.1/032", "1.1.1.1/00", "::1", "::/0", "1.1.1.3-1.1.1.2", "1.1.1.1-", "1.1.1.1-2.2.2.2-3.3.3.3"):
            with self.assertRaisesRegex(ValueError, "line 2"):
                targets.Exclusions.from_text("# title\n" + value)

    def test_generation_excludes_rules_and_validates_ports(self):
        excluded = targets.load_exclusions()
        rows = list(targets.generate_targets(500, (443, 587, 21), excluded, random.Random(7)))
        self.assertEqual(len(rows), 1500)
        for row in rows:
            ip = ipaddress.IPv4Address(row["ip"])
            self.assertTrue(ip.is_global and not ip.is_multicast, str(ip))
            self.assertFalse(excluded.contains(ip))
            self.assertIn(row["port"], (443, 587, 21))
        self.assertEqual(targets.parse_ports("443,587,21,443"), (443, 587, 21))
        for value in ("", "0", "-1", "65536", "443,", "x"):
            with self.assertRaises(ValueError):
                targets.parse_ports(value)

    def test_narrow_remaining_space_is_sampled_directly(self):
        excluded = targets.Exclusions.from_text("0.0.0.0-8.8.8.7\n8.8.8.10-255.255.255.255\n")
        rows = list(targets.generate_targets(100, (443,), excluded, random.Random(9)))
        self.assertEqual({row["ip"] for row in rows}, {"8.8.8.8", "8.8.8.9"})

    def test_allowed_ranks_preserve_ipv4_extremes(self):
        excluded = targets.Exclusions.from_text("0.0.0.1-255.255.255.254\n")
        self.assertEqual(excluded.available, 2)
        rng = Mock()
        rng.randrange.return_value = 0
        self.assertEqual(str(excluded.random_address(rng)), "0.0.0.0")
        rng.randrange.return_value = 1
        self.assertEqual(str(excluded.random_address(rng)), "255.255.255.255")

    def test_cli_uses_bundled_data_outside_repo_and_is_additive(self):
        with tempfile.TemporaryDirectory() as folder:
            extra = Path(folder) / "extra.conf"
            extra.write_text("0.0.0.0-8.8.8.7\n8.8.8.9-255.255.255.255\n")
            result = subprocess.run([sys.executable, str(SCRIPT), "--count", "3", "--ports", "443", "--excludefile", str(extra)], cwd=folder, text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([json.loads(row) for row in result.stdout.splitlines()], [{"ip": "8.8.8.8", "port": 443}] * 3)

    def test_cli_fails_before_output_on_invalid_or_missing_exclusions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "extra.conf"
            for content in ("bad\n", "0.0.0.0/0\n", "0.0.0.0-127.255.255.255\n128.0.0.0-255.255.255.255\n"):
                path.write_text(content)
                result = subprocess.run([sys.executable, str(SCRIPT), "--count", "1", "--excludefile", str(path)], text=True, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
            path.unlink()
            result = subprocess.run([sys.executable, str(SCRIPT), "--excludefile", str(path)], text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def test_missing_bundled_data_stops_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            output, error = io.StringIO(), io.StringIO()
            with patch.object(targets, "DEFAULT_EXCLUSIONS", Path(folder) / "missing.conf"):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                    with self.assertRaises(SystemExit) as stopped:
                        targets.main(["--count", "1"])
            self.assertEqual(stopped.exception.code, 2)
            self.assertEqual(output.getvalue(), "")
            self.assertIn("missing.conf", error.getvalue())


if __name__ == "__main__":
    unittest.main()
