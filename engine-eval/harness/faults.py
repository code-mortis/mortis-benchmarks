"""Explicit frozen reliability fixtures over the production workflow runtime.

GitHub and scanner outputs are synthetic. Source reads, scanner subprocesses,
HTTP inference, workflow persistence and accounting remain executable boundaries.
This does not establish live-provider, real-Trivy or GitHub integration.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import prepare
import runtime

CASES = ("pr-12", "sec-07", "sec-08")
ROOT = Path(__file__).resolve().parent


def verify_fixture(case, export):
    """Bind an executable export to the unchanged original corpus."""
    frozen = json.loads((ROOT / "pilot_manifest.json").read_text())
    expected = next(row for row in frozen["cases"] if row["case_id"] == case["case_id"])
    runtime.require(case["case_id"] in CASES, "Not a reliability fixture")
    runtime.require(case["evaluation_track"] == "reliability_fixture", "Wrong evaluation track")
    for key in ("case_digest", "base", "head", "selected_paths", "expected_assigned_units"):
        runtime.require(case[key] == expected[key], "Frozen fixture identity changed: " + key)
    context = json.loads((export / "context.json").read_text())
    original = json.loads((ROOT / "pilot" / case["case_id"] / "input.json").read_text())
    runtime.require(hashlib.sha256(runtime.canonical(original)).hexdigest() == expected["hashes"]["input"],
                    "Original fixture changed")
    runtime.require(context["selection"]["paths"] == sorted(original["selection"]["paths"]),
                    "Export assignment changed")
    runtime.require(context["selection"]["unavailable"] == original["selection"]["unavailable"],
                    "Export availability changed")
    runtime.require(context["head_sha"] == case["head"]["commit"], "Export revision changed")
    for revision in ("base", "head"):
        for path, blob in expected[revision]["blobs"].items():
            content = prepare.git(export / "repo", "cat-file", "blob", expected[revision]["commit"] + ":" + path)
            runtime.require(hashlib.sha256(content).hexdigest() == blob["sha256"], "Export source changed")
    return original


class FaultGitHub(runtime.SyntheticGitHub):
    fault_events = None

    @contextmanager
    def review_snapshot(self, *args, **kwargs):
        from code_mortis.core import source

        with super().review_snapshot(*args, **kwargs) as snapshot:
            repo, env, _, _ = snapshot
            # The frozen worker assignment never had a Git object. Fail source
            # acquisition rather than inventing source or certifying its absence.
            coordinator = source.read_source(repo, env, self.case["head"]["commit"], "src/coordinator.py", args[5])
            runtime.require(hashlib.sha256(coordinator.encode()).hexdigest()
                            == self.case["head"]["blobs"]["src/coordinator.py"]["sha256"], "Available source changed")
            try:
                source.read_source(repo, env, self.case["head"]["commit"], "src/worker.py", args[5])
            except ValueError:
                self.fault_events.append({"available": "src/coordinator.py", "unavailable": "src/worker.py",
                                          "boundary": "git_object_read", "selected_units": 2})
                raise
            raise AssertionError("Unavailable selected worker unexpectedly became readable")
            yield snapshot  # pragma: no cover - retain contextmanager protocol


@contextmanager
def scanner_fault(case, original, directory):
    """Run a synthetic scanner executable; keep production freshness/normalization."""
    from code_mortis.core import process
    from code_mortis.core.config import settings
    from code_mortis.core.db import now

    cache = directory / "scanner-cache"
    (cache / "db").mkdir(parents=True)
    age = json.loads(original["head"]["scanner-report.json"])["advisory_age_hours"] if case["case_id"] == "sec-07" else 1
    (cache / "db" / "metadata.json").write_text(json.dumps({"UpdatedAt": (now() - timedelta(hours=age)).isoformat()}))
    scanner = directory / "synthetic_scanner.py"
    scanner.write_text(
        "import json,sys\n"
        "args=sys.argv[1:]\n"
        "if '--version' in args: print('Version: ' + args[-1])\n"
        "elif '--download-db-only' in args: sys.exit(1)\n"
        "elif '--format' in args:\n"
        " print(json.dumps({'SchemaVersion':2,'Results': "
        + ("[{'Target':'package-lock.json','Class':'lang-pkgs','Type':'npm','Packages':[]}]" if case["case_id"] == "sec-07" else "[]")
        + "}))\n"
    )
    calls = []
    command = process.command

    def dispatch(args, cwd, env, *positional, **kwargs):
        if args[0] != settings().trivy_binary and "code_mortis.security_scans.scanner" not in args:
            return command(args, cwd, env, *positional, **kwargs)
        calls.append(list(map(str, args)))
        stopped = kwargs.get("stopped", lambda: False)
        runtime.require(not stopped(), "Scanner fixture stopped before process dispatch")
        selected = [*args, settings().trivy_version] if "--version" in args else args
        result = subprocess.run([sys.executable, str(scanner), *map(str, selected)], cwd=cwd, env=env,
                                capture_output=True, text=True, timeout=kwargs.get("timeout") or 30, check=False)
        return result.returncode, result.stdout, result.stderr

    with patch.object(settings(), "trivy_cache_dir", cache), patch.object(process, "command", dispatch):
        yield calls


def execute_fixture(manifest, case, export, arm, credentials, options, attempt_id):
    from code_mortis.core.db import engine

    runtime.require(arm in {"ocr", "mortis"}, "Invalid fixture arm")
    runtime.require(engine().url.database in {"mortis_test", "mortis_eval"}, "Fault fixtures require an isolated test/evaluation database")
    endpoint = urlsplit(manifest["connection"]["base_url"])
    runtime.require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1" and endpoint.port,
                    "Fault fixtures require an explicit synthetic loopback provider")
    original = verify_fixture(case, export)
    with ExitStack() as stack:
        calls, events = [], []
        if case["case_id"] == "pr-12":
            stack.enter_context(patch.object(FaultGitHub, "fault_events", events))
            stack.enter_context(patch.object(runtime, "SyntheticGitHub", FaultGitHub))
        else:
            calls = stack.enter_context(scanner_fault(case, original, export.parent))
        result = runtime.execute(manifest, case, export, arm, credentials, options, attempt_id)
    result["fixture"] = {
        "case_id": case["case_id"], "arm": arm, "case_digest": case["case_digest"],
        "evaluation_track": "reliability_fixture", "scanner_commands": calls,
        "fault_events": events,
        "source_failure": "src/worker.py source and patch unavailable" if case["case_id"] == "pr-12" else None,
        "evidence_kind": "production_workflow_synthetic_external_boundaries",
        "limitations": ["No live provider, real Trivy or GitHub account integration.",
                        "pr-12 rejects the entire unavailable snapshot; partial-result recovery is a separate test."],
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("CM_OCR_ISOLATED_RUNTIME") != "true":
        parser.error("The six-arm suite must run inside an isolated Docker worker with pytest available; host OCR configuration is forbidden.")
    args.output.mkdir(parents=True, exist_ok=False)
    environment = {**os.environ, "CM_FAULT_EVIDENCE_DIR": str(args.output.resolve())}
    result = subprocess.run(["uv", "run", "--offline", "--no-sync", "python", "-m", "pytest", "-q", "tests/test_engine_fault_fixtures.py"],
                            cwd=ROOT.parent.parent / "backend", env=environment, check=False)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    raise SystemExit("This historical OCR/native evaluation is retired. Saved evidence and offline scoring remain available; new execution is disabled.")
