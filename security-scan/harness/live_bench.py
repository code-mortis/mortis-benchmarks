"""Time unmodified Mortis CLI scan stages on synthetic data using a saved connection.

Run with the engine's Python, a scratch directory and the name of a saved profile.
Put verified Trivy 0.76.2 on PATH. This runner makes live requests.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import subprocess
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from mortis_engine import __version__, operations
from mortis_engine.cli import main
from mortis_engine.security_scans import scanner

FILES = {
    "Dockerfile": "FROM scratch\nUSER root\n",
    "arithmetic.py": "def double(value: int) -> int:\n    return value * 2\n",
}
PROTOCOL = {
    "question": "How much time do a cold scan and warm scans spend in Trivy and AI analysis?",
    "workload": "One root-user Dockerfile and one clean arithmetic file. Fresh repository identity each time, same Git commit and shared isolated scanner cache.",
    "samples": ["cold", "warm-1", "warm-2", "warm-3"],
    "threshold": "Every sample completes two selected semantic files, detects a root-user configuration finding and has no arithmetic.py findings. Descriptive timings only.",
    "limits": {"concurrency": 2, "effort": "medium", "timeout_seconds": 180, "token_budget": 64000, "max_output_tokens": 2048},
    "stop": "Stop on failed scanner or provider transport/auth failure. Do not retry uncertain provider usage.",
}


def git(repo, *args):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_DATE": "2026-01-01T12:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T12:00:00Z"}
    return subprocess.check_output(["git", "-c", "core.hooksPath=" + os.devnull,
        "-c", "commit.gpgsign=false", "-c", "user.name=Bench", "-c", "user.email=bench@example.invalid", *args],
        cwd=repo, env=env, text=True).strip()


def fixture(repo, files):
    repo.mkdir()
    git(repo, "init", "-q", "--initial-branch=main", "--template=")
    for name, content in files.items():
        (repo / name).write_text(content)
    git(repo, "add", "--", *files)
    git(repo, "commit", "-qm", "fixture")
    return git(repo, "rev-parse", "HEAD")


def sample(repo, profile, label, output_cap=2048, *, files=FILES):
    sha = fixture(repo, files)
    phases, commands = {}, []
    original_run, original_command = operations.run, scanner.command
    start = time.monotonic()

    def measured_run(*args, progress, **kwargs):
        def timed(event):
            if phase := event.get("phase"):
                phases.setdefault(phase, round(time.monotonic() - start, 4))
            progress(event)
        return original_run(*args, progress=timed, **kwargs)

    def measured_command(args, *rest):
        begin = time.monotonic()
        result = original_command(args, *rest)
        stage = ("version" if "--version" in args else "db_update" if "--download-db-only" in args
                 else "source_scan" if "--format" in args else "checks_update")
        commands.append({"stage": stage, "seconds": round(time.monotonic() - begin, 4), "returncode": result[0]})
        return result

    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(operations, "run", measured_run), patch.object(scanner, "command", measured_command), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(["scan", "--repo", str(repo), "--connection", profile, "--ref", "HEAD", "--format", "json",
                     "--concurrency", "2", "--effort", "medium", "--timeout-seconds", "180",
                     "--token-budget", "64000", "--max-output-tokens", str(output_cap)])
    row = {"sample": label, "sha": sha, "exit": code, "wall_seconds": round(time.monotonic()-start, 4),
           "phase_start_seconds": phases, "trivy_commands": commands}
    raw = stdout.getvalue()
    (repo.parent / (label + ".json")).write_text(raw)
    (repo.parent / (label + ".stderr")).write_text(stderr.getvalue())
    if not raw.strip():
        return {**row, "status": "preflight_failed"}
    return summarize(row, json.loads(raw))


def summarize(row, report):
    info, cov, usage = report.get("scanner", {}), report["coverage"], report["usage"]
    findings = [{"path": f["path"], "rule": f.get("rule_id"), "severity": f.get("severity"),
                 "source": f.get("sources", []), "title": f["title"]} for f in report["findings"]]
    requests = usage["requests"]
    return {**row, "status": report["status"], "grade": report["grade"], "engine_seconds": report["elapsed_seconds"],
            "model": report.get("model"), "provider": report.get("provider"),
            "database_fresh": info.get("database_fresh"), "database_updated_at": info.get("database", {}).get("UpdatedAt"),
            "selected": cov["selected_files"], "completed": cov["completed_files"], "findings": findings,
            "problems": report["problems"], "trivy_stage": report["stages"]["trivy"].get("status"),
            "requests_by_stage": dict(Counter(x["stage"] for x in requests)),
            "request_status": dict(Counter(x["status"] for x in requests)),
            "request_errors": [x.get("code") for x in requests if x["status"] == "failed"],
            "request_usage": [{"stage": x["stage"], "status": x["status"], "usage": x.get("usage", {})} for x in requests],
            "tokens": usage["total_tokens"], "cost": None}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("profile")
    parser.add_argument("--continue-recorded", action="store_true")
    parser.add_argument("--higher-cap", action="store_true", help="Use the existing warm cache for three new 8192-output-token samples.")
    args = parser.parse_args()
    args.scratch.mkdir(mode=0o700, parents=True, exist_ok=args.continue_recorded or args.higher_cap)
    os.umask(0o077)
    os.environ["XDG_STATE_HOME"] = str((args.scratch / "state").resolve())
    engine_dir = Path(operations.__file__).resolve().parents[2]
    result = {"protocol": PROTOCOL, "engine_version": __version__, "revision": git(engine_dir,"rev-parse","HEAD"),
              "working_diff_sha256": hashlib.sha256(subprocess.check_output(["git","diff","--binary","HEAD"],cwd=engine_dir)).hexdigest(),
              "platform": [platform.system(), platform.release(), platform.machine(), platform.python_version()],
              "fixture_sha256": {f: hashlib.sha256(v.encode()).hexdigest() for f,v in FILES.items()}, "samples": []}
    output = args.scratch / ("higher-cap-results.json" if args.higher_cap else "results.json")
    if args.higher_cap:
        assert not output.exists() and (args.scratch/"results.json").is_file()
        result["protocol"] = {**PROTOCOL, "limits": {**PROTOCOL["limits"], "max_output_tokens": 8192},
                              "samples": ["warm-higher-1","warm-higher-2","warm-higher-3"],
                              "question": "Does a larger output cap allow the same two-file scan to finish with a warm cache?"}
    if args.continue_recorded:
        old = json.loads(output.read_text())
        assert all(old[k] == result[k] for k in ("fixture_sha256", "revision", "working_diff_sha256", "protocol"))
        for row in old["samples"]:
            assert row["status"] in {"completed","partial"} and row["tokens"] is not None
            prior = summarize(row, json.loads((args.scratch / (row["sample"]+".json")).read_text()))
            assert all(code == "output_limit" for code in prior["request_errors"])
            result["samples"].append(prior)
    output.write_text(json.dumps(result, indent=2)+"\n")
    for label in result["protocol"]["samples"][len(result["samples"]):]:
        print("Start", label, flush=True)
        row = sample(args.scratch / ("repo-"+label), args.profile, label, result["protocol"]["limits"]["max_output_tokens"])
        result["samples"].append(row)
        output.write_text(json.dumps(result, indent=2)+"\n")
        print(label, row["status"], row["wall_seconds"], row.get("requests_by_stage"), flush=True)
        if row["status"] in {"preflight_failed", "failed"} or row.get("tokens") is None or any(code != "output_limit" for code in row.get("request_errors", [])):
            break
