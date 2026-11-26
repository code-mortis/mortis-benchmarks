"""Offline benchmark of one duplicate tree lookup in the public review preview."""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from mortis_engine.review import preview_local, source

BASE_GIT = source.git
SAMPLES = 5


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def fixture_git(repo, env, *args):
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()


def fixture(repo, env, size, *, edges=False):
    repo.mkdir()
    fixture_git(repo, env, "init", "--quiet", "--template=", "--object-format=sha1", "-b", "main")
    example = repo / "src"
    example.mkdir()
    for index in range(size):
        file = example / f"module_{index:03}.py"
        file.write_text("".join(f"value_{line:02} = {index + line}\n" for line in range(30)), encoding="utf-8")
    if edges:
        (repo / "obsolete.py").write_text("def removed():\n    return 1\n", encoding="utf-8")
        (repo / "caller.py").write_text("from obsolete import removed\nprint(removed())\n", encoding="utf-8")
    fixture_git(repo, env, "add", "--all")
    fixture_git(repo, env, "commit", "--quiet", "-m", "baseline")
    base = fixture_git(repo, env, "rev-parse", "HEAD")
    for file in sorted(example.iterdir()):
        with file.open("a", encoding="utf-8") as handle:
            handle.write("changed = True\n")
    if edges:
        (example / "module_000.py").chmod(0o755)
        (repo / "módulo con espacio.py").write_text("value = 'é\ufffd'\n", encoding="utf-8")
        (repo / "-literal [x].py").write_text("value = True\n", encoding="utf-8")
        (repo / "binary.py").write_bytes(b"first\x00second\n")
        (repo / "invalid.py").write_bytes(b"value = '\xff'\n")
        (repo / "link.py").symlink_to("caller.py")
        (repo / "obsolete.py").unlink()
    fixture_git(repo, env, "add", "--all")
    fixture_git(repo, env, "commit", "--quiet", "-m", "modified")
    return base, fixture_git(repo, env, "rev-parse", "HEAD")


def reuse_immediate_literal_tree_read(git):
    previous = None

    def call(directory, env, *args, **kwargs):
        nonlocal previous
        prior, previous = previous, None
        if prior is not None and args == prior[2] and directory == prior[0] and env is prior[1]:
            if set(kwargs) == {"stopped"}:
                if kwargs["stopped"]():
                    raise source.ReviewStopped("The review was cancelled.")
                return prior[3]
        value = git(directory, env, *args, **kwargs)
        if (len(args) == 7 and args[:4] == ("--literal-pathspecs", "ls-tree", "-z", "-l")
                and args[5] == "--" and set(kwargs) == {"stopped"} and value):
            previous = directory, env, args[1:], value
        return value

    return call


def invoke(repo, options, arm, counts=None):
    git = BASE_GIT
    if counts is not None:
        def count_git(directory, env, *args, **kwargs):
            command = args[1] if args[0] == "--literal-pathspecs" else args[0]
            counts[command] += 1
            return BASE_GIT(directory, env, *args, **kwargs)
        git = count_git
    if arm == "reuse":
        git = reuse_immediate_literal_tree_read(git)
    with patch.object(source, "git", git):
        return preview_local(repo, **options)


def run_case(repo, options, expected_count=None, *, verify_only=False):
    reports, commands = {}, {}
    for arm in ("current", "reuse"):
        commands[arm] = Counter()
        reports[arm] = invoke(repo, options, arm, commands[arm])
    reference = reports["current"]
    assert reference == reports["reuse"], "instrumented previews differ"
    assert reference["limit_reason"] is None, "review limit reached"
    if expected_count is not None:
        assert reference["totals"]["selected_files"] == expected_count, reference["totals"]
        assert not reference["errors"] and not reference["warnings"], reference
        assert reference["totals"]["units"] == expected_count, reference["totals"]
    else:
        selected_paths = {row["path"] for row in reference["selected_files"] if row["unit_keys"]}
        assert {"-literal [x].py", "módulo con espacio.py", "src/module_000.py"} <= selected_paths, reference
        assert any(row["path"] == "link.py" for row in reference["errors"]), reference
        assert any(row["path"] == "invalid.py" for row in reference["errors"]), reference
        assert any(row["path"] == "binary.py" for row in reference["excluded_files"]), reference
        assert any(row["path"] == "obsolete.py" for row in reference["excluded_files"]), reference
        assert any(row["path"] == "caller.py" for row in reference["affected_callers"]["sites"]), reference

    result = {
        "input": options,
        "preview_sha256": digest(canonical(reference)),
        "preview_totals": reference["totals"],
        "preview_errors": reference["errors"],
        "preview_exclusions": reference["excluded_files"],
        "git_commands": {arm: dict(value) for arm, value in commands.items()},
        "git_total": {arm: value.total() for arm, value in commands.items()},
    }
    result["git_saved"] = result["git_total"]["current"] - result["git_total"]["reuse"]
    if verify_only or expected_count is None:
        return result

    for arm in ("current", "reuse"):
        assert invoke(repo, options, arm) == reference, f"{arm} warm-up preview differs"

    samples, failures = {"current": [], "reuse": []}, []
    order = []
    for sample in range(SAMPLES):
        arms = ("current", "reuse") if sample % 2 == 0 else ("reuse", "current")
        order.append(arms)
        for arm in arms:
            try:
                start = time.perf_counter_ns()
                report = invoke(repo, options, arm)
                elapsed = (time.perf_counter_ns() - start) / 1_000_000
                assert report == reference, "preview differs from reference"
                samples[arm].append(elapsed)
            except (ValueError, TimeoutError, AssertionError) as exc:
                failures.append({"arm": arm, "sample": sample + 1, "error": str(exc)})

    result.update(samples_ms=samples, pair_order=order, failures=failures, incomplete_samples=len(failures))
    if all(samples.values()):
        result["median_ms"] = {arm: statistics.median(times) for arm, times in samples.items()}
        result["range_ms"] = {arm: [min(times), max(times)] for arm, times in samples.items()}
        result["median_reduction_pct"] = (
            (1 - result["median_ms"]["reuse"] / result["median_ms"]["current"]) * 100
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    engine = Path(source.__file__).resolve().parents[3]
    git_env = {
        "PATH": os.pathsep.join(part for part in os.environ.get("PATH", os.defpath).split(os.pathsep)
                                if Path(part).is_absolute()),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        "GIT_AUTHOR_NAME": "Synthetic Benchmark",
        "GIT_COMMITTER_NAME": "Synthetic Benchmark",
        "GIT_AUTHOR_EMAIL": "benchmark@example.invalid",
        "GIT_COMMITTER_EMAIL": "benchmark@example.invalid",
        "LC_ALL": "C",
    }
    extra_hardware = subprocess.run(
        ["sysctl", "-n", "hw.model"], capture_output=True, text=True, check=False,
    ).stdout.strip() if platform.system() == "Darwin" else ""
    report = {
        "evidence": "deterministic offline public Python API benchmark",
        "engine_revision": fixture_git(engine, git_env, "rev-parse", "HEAD"),
        "engine_src_diff_sha256": digest(fixture_git(engine, git_env, "diff", "HEAD", "--", "src").encode()),
        "harness_sha256": digest(Path(__file__).read_bytes()),
        "python": platform.python_version(),
        "git": fixture_git(engine, git_env, "--version"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "model": extra_hardware,
        "logical_cpu_count": os.cpu_count(),
        "samples_per_arm": 0 if args.verify_only else SAMPLES,
        "hardware_cache": "warm, with fresh private snapshot per invocation",
        "provider_cost_tokens": None,
        "cases": {},
    }
    with tempfile.TemporaryDirectory(prefix="mortis-preview-fixtures-") as workdir:
        root = Path(workdir)
        for key in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
            os.environ[key] = str(root / key)
        small_base, small_head = fixture(root / "small", git_env, 4)
        large_base, large_head = fixture(root / "large", git_env, 80)
        edge_base, edge_head = fixture(root / "edge", git_env, 2, edges=True)
        report["cases"]["edge"] = run_case(root / "edge", {"mode": "commits", "base": edge_base, "head": edge_head})
        report["cases"]["commits_4"] = run_case(
            root / "small", {"mode": "commits", "base": small_base, "head": small_head}, 4, verify_only=args.verify_only
        )
        report["cases"]["commits_80"] = run_case(
            root / "large", {"mode": "commits", "base": large_base, "head": large_head}, 80, verify_only=args.verify_only
        )
        report["cases"]["all_80"] = run_case(
            root / "large", {"mode": "all", "head": large_head}, 80, verify_only=args.verify_only
        )
    if not args.verify_only:
        report["passed"] = (
            all(case.get("incomplete_samples", 0) == 0 for case in report["cases"].values())
            and all(report["cases"][key].get("median_reduction_pct", 0) >= 15
                    and report["cases"][key]["git_saved"] == 80 for key in ("commits_80", "all_80"))
        )
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    if report.get("passed") is False:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
