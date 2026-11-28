"""Offline probes for scan coverage and saved finding history.

Print one JSON result per probe. Exit 1 when any intended contract fails.
All repositories, state, model messages, and scanner responses are synthetic.
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from mortis_engine import findings
from mortis_engine.history import History
from mortis_engine.security_scans import engine, service


def repository(root, files):
    root.mkdir()
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }

    def git(*args):
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture",
             "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
            cwd=root, env=env, check=True, capture_output=True,
        )

    git("init", "-q")
    for path, content in files.items():
        (root / path).write_text(content, encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "Fixture")
    return root


def clean_scanner(item, timeout, stopped):
    return {"findings": [], "targets": {}, "problems": [], "metadata": {"database_fresh": True}}


class CleanSession:
    async def ask(self, stage, key, *, validate, **options):
        assert stage == "security_analysis"
        return validate({"findings": [], "required_paths": []})


def assessment_coverage(root):
    repo = repository(root / "assessment", {
        "app.py": "enabled = False\n",
        "support.md": "Fixture evidence for the independent assessment.\n",
    })
    read_source = engine.Snapshot.source

    def fail_requested_read(item, path, sha=None):
        if path == "support.md":
            raise ValueError("The fixture evidence cannot be read.")
        return read_source(item, path, sha)

    class Session:
        assessment_passes = 0
        received_unavailable_feedback = False

        async def ask(self, stage, key, *, context, validate, **options):
            if stage == "security_analysis":
                reference = next(
                    ref for ref, citation in context["citation_sources"].items()
                    if citation["path"] == "app.py"
                )
                proposal = {
                    "title": "Fixture concern", "category": "policy", "severity": "high",
                    "path": "app.py", "explanation": "Fixture concern for independent assessment.",
                    "trigger": "Synthetic input.", "impact": "Synthetic effect.",
                    "remediation": "Review the fixture.", "verification": "Check the fixture.",
                    "evidence": [{"source_id": reference, "start_line": 1, "end_line": 1}],
                }
                return validate({"findings": [proposal], "required_paths": []})

            assert stage == "security_assessment"
            self.assessment_passes += 1
            if self.assessment_passes == 1:
                assert "support.md" in context["available_paths"]
                assert "support.md" not in context["sources"]["current"]
                required_paths = ["support.md"]
                verdict = "uncertain"
            else:
                assert self.assessment_passes == 2
                self.received_unavailable_feedback = (
                    context["validation_feedback"]["required_paths"] == ["support.md"]
                )
                assert self.received_unavailable_feedback
                required_paths = []
                verdict = "rejected"
            return validate({"verdict": verdict, "finding_id": None,
                             "explanation": "Fixture assessment.", "evidence": [],
                             "required_paths": required_paths})

    session = Session()
    with patch.object(engine.Snapshot, "source", fail_requested_read):
        report = asyncio.run(service.scan(repo, session=session, scanner=clean_scanner))
    actual = {
        "unavailable_feedback": session.received_unavailable_feedback,
        "status": report["status"], "grade": report["grade"],
        "assessment_status": report["stages"]["assessment"]["status"],
    }
    expected = {"unavailable_feedback": True, "status": "partial", "grade": None,
                "assessment_status": "partial"}
    return actual, expected


def dependency_coverage(root):
    repo = repository(root / "dependency", {
        "package.json": json.dumps({"name": "fixture", "version": "1.0.0",
                                    "dependencies": {"fixture-js": "1.0.0"}}),
        "requirements.txt": "fixture-python==1.0.0\n",
    })

    def python_only_scanner(item, timeout, stopped):
        report = {"SchemaVersion": 2, "Results": [{
            "Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
            "Packages": [{"Name": "fixture-python", "Version": "1.0.0",
                          "Identifier": {"PURL": "pkg:pypi/fixture-python@1.0.0"}}],
        }]}
        return {**engine.normalize_trivy(item, report), "metadata": {"database_fresh": True}}

    report = asyncio.run(service.scan(repo, session=CleanSession(), scanner=python_only_scanner))
    actual = {"status": report["status"], "grade": report["grade"],
              "npm_coverage_gap": any("package.json" in str(problem) for problem in report["problems"])}
    expected = {"status": "partial", "grade": None, "npm_coverage_gap": True}
    return actual, expected


def forked_history(root):
    repo = repository(root / "history", {"app.py": "enabled = False\n"})
    scope = "refs/heads/fixture"
    issue = {"id": "fixture-finding", "path": "app.py", "kind": "code",
             "title": "Fixture finding", "severity": "high", "state": "open"}

    def report(observations):
        return {"schema_version": "mortis.security/v1", "status": "completed", "findings": observations}

    with History(repo) as history:
        prior = history.begin("scan", scope, {"previous": []})
        history.finish(prior, report([]))

        # Both runs start while the same predecessor is the latest finished run.
        first = history.begin("scan", scope, {"previous": history.previous_ids("scan", scope)[-1:]})
        second = history.begin("scan", scope, {"previous": history.previous_ids("scan", scope)[-1:]})
        assert json.loads(history.row(first)["plan"])["previous"] == [prior]
        assert json.loads(history.row(second)["plan"])["previous"] == [prior]
        history.finish(first, report([issue]))
        history.finish(second, report([]))

        latest = history.previous_ids("scan", scope)[-1]
        assert latest == second
        inherited = findings.scan_history(history, latest)["findings"]

    listed = findings.list_findings(repo, run_id=latest)["findings"]
    actual = {"scan_inherits_open_finding": issue["id"] in {row["id"] for row in inherited},
              "findings_lists_open_finding": issue["id"] in {row["id"] for row in listed}}
    expected = {"scan_inherits_open_finding": True, "findings_lists_open_finding": True}
    return actual, expected


def main():
    cases = (assessment_coverage, dependency_coverage, forked_history)
    passed = True
    with tempfile.TemporaryDirectory(prefix="probe-", dir=Path(__file__).resolve().parent) as temporary:
        root = Path(temporary)
        isolated_env = {"XDG_STATE_HOME": str(root / "state"), "XDG_CONFIG_HOME": str(root / "config")}
        with patch.dict(os.environ, isolated_env):
            for case in cases:
                actual, expected = case(root)
                match = actual == expected
                passed = passed and match
                print(json.dumps({"probe": case.__name__, "pass": match,
                                  "actual": actual, "expected": expected}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
