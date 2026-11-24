"""Snapshot/guard checks using tiny synthetic bytes; no downloads or database."""

import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scanner_preflight import guard_scanner, scan_check, snapshot_identity


class ScannerPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "db").mkdir()
        (self.root / "policy" / "content").mkdir(parents=True)
        self.metadata = {"Version": 2, "UpdatedAt": datetime.now(UTC).isoformat()}
        (self.root / "db" / "metadata.json").write_text(json.dumps(self.metadata))
        (self.root / "db" / "trivy.db").write_bytes(b"synthetic-database")
        (self.root / "policy" / "metadata.json").write_text(
            json.dumps({"MajorVersion": 2, "DownloadedAt": datetime.now(UTC).isoformat()})
        )
        (self.root / "policy" / "content" / "synthetic.rego").write_text("package synthetic\n")

    def tearDown(self):
        self.temporary.cleanup()

    def test_every_database_check_and_metadata_byte_is_pinned(self):
        identity = snapshot_identity(self.root)
        self.assertEqual(identity, snapshot_identity(self.root))
        self.assertEqual(len(identity["files"]), 4)
        self.assertEqual(identity["bytes"], sum(item["bytes"] for item in identity["files"].values()))
        for name in identity["files"]:
            with self.subTest(name=name):
                target = self.root / name
                original = target.read_bytes()
                target.write_bytes(original + b" ")
                self.assertNotEqual(snapshot_identity(self.root)["sha256"], identity["sha256"])
                target.write_bytes(original)

    def test_old_future_or_naive_advisory_metadata_is_refused(self):
        for date in (
            datetime.now(UTC) - timedelta(days=2),
            datetime.now(UTC) + timedelta(hours=1),
            datetime.now(UTC).replace(tzinfo=None),
        ):
            with self.subTest(date=date):
                (self.root / "db" / "metadata.json").write_text(
                    json.dumps({**self.metadata, "UpdatedAt": date.isoformat()})
                )
                with self.assertRaises(ValueError):
                    snapshot_identity(self.root)

    def test_missing_checks_cannot_silently_use_embedded_fallback(self):
        (self.root / "policy" / "metadata.json").unlink()
        with self.assertRaisesRegex(ValueError, "embedded checks"):
            snapshot_identity(self.root)

    def test_old_or_empty_checks_are_refused(self):
        checks = self.root / "policy" / "metadata.json"
        original = checks.read_text()
        checks.write_text(
            json.dumps(
                {"MajorVersion": 2, "DownloadedAt": (datetime.now(UTC) - timedelta(days=2)).isoformat()}
            )
        )
        with self.assertRaisesRegex(ValueError, "within 24 hours"):
            snapshot_identity(self.root)
        checks.write_text(original)
        (self.root / "policy" / "content" / "synthetic.rego").unlink()
        with self.assertRaisesRegex(ValueError, "checks are missing"):
            snapshot_identity(self.root)

    def test_symlinks_and_cache_overflow_are_rejected(self):
        (self.root / "policy" / "content" / "link").symlink_to(self.root / "db" / "trivy.db")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            snapshot_identity(self.root)
        (self.root / "policy" / "content" / "link").unlink()
        with patch("scanner_preflight.CACHE_LIMIT", 1), self.assertRaisesRegex(ValueError, "3 GiB"):
            snapshot_identity(self.root)

    def fake_engine(self, function):
        engine = SimpleNamespace(trivy=function)
        config = SimpleNamespace(trivy_cache_dir=Path("/original-cache"))
        modules = {
            "code_mortis.core.config": SimpleNamespace(settings=lambda: config),
            "code_mortis.security_scans": SimpleNamespace(engine=engine),
        }
        return engine, config, patch.dict(sys.modules, modules)

    def scanner_result(self):
        return {
            "metadata": {
                "database_fresh": True,
                "checks_present": True,
                "scanners": ["vuln", "misconfig", "secret"],
            },
            "problems": [],
        }

    def test_guard_calls_original_scanner_and_retains_observed_identity(self):
        calls = []

        def original(*args, **kwargs):
            calls.append((args, kwargs))
            return self.scanner_result()

        identity = snapshot_identity(self.root)
        engine, config, modules = self.fake_engine(original)
        with modules:
            with guard_scanner(identity, self.root) as state:
                self.assertEqual(state, {"validated": False, "error": None})
                result = engine.trivy("source", 300, stopped=False)
                self.assertEqual(config.trivy_cache_dir, self.root)
                self.assertEqual(state, {"validated": True, "error": None})
            self.assertEqual(config.trivy_cache_dir, Path("/original-cache"))
            self.assertIs(engine.trivy, original)
        self.assertEqual(calls, [(("source", 300), {"stopped": False})])
        self.assertEqual(result["metadata"]["evaluation_snapshot"]["before"], identity["sha256"])
        self.assertEqual(result["metadata"]["evaluation_snapshot"]["after"], identity["sha256"])

    def test_changed_initial_snapshot_is_rejected_before_scanning(self):
        def original(*args, **kwargs):
            self.fail("Mismatching scanner bytes must not execute")

        identity = snapshot_identity(self.root)
        (self.root / "db" / "trivy.db").write_bytes(b"changed")
        engine, _config, modules = self.fake_engine(original)
        with (
            modules,
            guard_scanner(identity, self.root),
            self.assertRaisesRegex(ValueError, "frozen identity"),
        ):
            engine.trivy()

    def test_changed_checks_during_scan_are_rejected_before_ai(self):
        def original(*args, **kwargs):
            (self.root / "policy" / "content" / "synthetic.rego").write_text("changed")
            return self.scanner_result()

        identity = snapshot_identity(self.root)
        engine, _config, modules = self.fake_engine(original)
        with (
            modules,
            guard_scanner(identity, self.root),
            self.assertRaisesRegex(ValueError, "inference forbidden"),
        ):
            engine.trivy()

    def test_missing_vulnerability_scanner_is_never_accepted_as_complete(self):
        def original(*args, **kwargs):
            return {
                "metadata": {
                    "database_fresh": False,
                    "checks_present": True,
                    "scanners": ["misconfig", "secret"],
                }
            }

        identity = snapshot_identity(self.root)
        engine, _config, modules = self.fake_engine(original)
        with (
            modules,
            guard_scanner(identity, self.root),
            self.assertRaisesRegex(ValueError, "fresh complete"),
        ):
            engine.trivy()


    def test_successful_scanner_retains_missing_cgroup_metrics_as_unknown(self):
        calls = []
        def scan(*args):
            calls.append(args)
            return self.scanner_result()

        engine, _, modules = self.fake_engine(scan)
        engine.Snapshot = lambda *args: SimpleNamespace(populate=lambda: None)
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if path.parent == Path("/sys/fs/cgroup"):
                if path.name == "cpu.stat":
                    return "1" * 5000
                raise FileNotFoundError(path)
            return original_read(path, *args, **kwargs)

        with modules, patch.dict(sys.modules, {
            "code_mortis.core": SimpleNamespace(source=SimpleNamespace(git=lambda *a: "a" * 40)),
            "code_mortis.core.process": SimpleNamespace(child_environment=dict),
        }), patch.object(Path, "read_text", read):
            result = scan_check(self.root, snapshot_identity(self.root))
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["cgroup"], {"cpu.stat": "1" * 4096, "memory.peak": None,
                                           "memory.events": None, "pids.current": None})


if __name__ == "__main__":
    unittest.main()
