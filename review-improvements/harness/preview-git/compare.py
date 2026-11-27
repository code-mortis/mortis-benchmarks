"""Compare public review previews from two Mortis Engine checkouts."""

import argparse
import hashlib
import json
import os
import platform
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

ARMS = ("baseline", "candidate")
XDG_DIRS = ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME")


def git(checkout, env, *args):
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
         "-c", "protocol.allow=never", *args],
        cwd=checkout, env=env, check=True, capture_output=True,
    ).stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def checkout_identity(checkout, env):
    diff = git(checkout, env, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--binary", "HEAD", "--")
    paths = git(checkout, env, "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "src")
    inventory = []
    for name in sorted(set(paths.split(b"\0")) - {b""}):
        file = checkout / os.fsdecode(name)
        if file.is_symlink():
            kind, digest = "symlink", sha256(os.fsencode(file.readlink()))
        elif file.is_file():
            kind = "executable" if file.stat().st_mode & stat.S_IXUSR else "regular"
            digest = sha256(file.read_bytes())
        else:
            kind, digest = "missing", None
        inventory.append((os.fsdecode(name), kind, digest))
    return {
        "revision": git(checkout, env, "rev-parse", "HEAD").decode().strip(),
        "dirty": bool(git(checkout, env, "status", "--porcelain=v1", "-z", "--untracked-files=normal")),
        "tracked_diff_sha256": sha256(diff),
        "source_inventory_sha256": sha256(encoded(inventory)),
        "source_inventory_entries": len(inventory),
    }


def locate_engine(checkout):
    source = checkout / "src"
    if not (source / "mortis_engine/review/preview.py").is_file():
        raise ValueError("Checkout does not contain Mortis Engine source.")
    sys.path.insert(0, str(source))


def git_subcommand(args):
    if Path(args[0]).name != "git":
        return None
    arguments = iter(args[1:])
    for arg in arguments:
        if arg in {"-c", "-C", "--git-dir", "--work-tree"}:
            next(arguments, None)
        elif not arg.startswith("-"):
            return arg
    return "<unknown>"


def counted_preview(preview_local, repo, options):
    counts = Counter()
    start_process = subprocess.Popen

    def count_process(args, *rest, **kwargs):
        if command := git_subcommand(args):
            counts[command] += 1
        return start_process(args, *rest, **kwargs)

    with patch.object(subprocess, "Popen", count_process):
        preview = preview_local(repo, **options)
    return {"preview": preview, "git_commands": dict(counts)}


def run_worker(checkout):
    locate_engine(checkout)
    from mortis_engine.review import preview_local

    preview_source = Path(sys.modules[preview_local.__module__].__file__).resolve()
    if not preview_source.is_relative_to(checkout / "src/mortis_engine"):
        raise ValueError("Worker imported the wrong checkout.")
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        repo, options, operation = request["repo"], request["options"], request["operation"]
        result = {}
        try:
            if operation == "count":
                result = counted_preview(preview_local, repo, options)
            elif operation == "measure":
                started = time.perf_counter_ns()
                result["preview"] = preview_local(repo, **options)
                result["elapsed_ms"] = (time.perf_counter_ns() - started) / 1_000_000
            else:
                result["preview"] = preview_local(repo, **options)
        except Exception as error:
            result = {"error": type(error).__name__}
        print(json.dumps(result, ensure_ascii=True), flush=True)


class WorkerError(ValueError):
    pass


def read_worker(process):
    line = process.stdout.readline()
    if not line:
        raise WorkerError("worker exited")
    try:
        result = json.loads(line)
    except json.JSONDecodeError as error:
        raise WorkerError("invalid worker response") from error
    if "error" in result:
        raise WorkerError(result["error"])
    return result


@contextmanager
def worker(checkout, env, cwd):
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker", str(checkout)],
        cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
    )
    try:
        if read_worker(process) != {"ready": True}:
            raise WorkerError("worker startup failed")

        def call(repo, options, operation):
            message = {"repo": str(repo), "options": options, "operation": operation}
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
            return read_worker(process)

        yield call
    finally:
        process.stdin.close()
        process.stdout.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def edge_guards(preview):
    selected = {row["path"] for row in preview["selected_files"] if row["unit_keys"]}
    errors = {row["path"] for row in preview["errors"]}
    exclusions = {row["path"]: row["reason"] for row in preview["excluded_files"]}
    callers = {site["path"] for site in preview.get("affected_callers", {}).get("sites", [])}
    return (
        {"-literal [x].py", "módulo con espacio.py", "src/module_000.py"} <= selected
        and {"link.py", "invalid.py"} <= errors
        and exclusions.get("binary.py") == "binary"
        and exclusions.get("obsolete.py") == "deleted"
        and "caller.py" in callers
    )


def run_case(repo, options, expected_count, workers, sample_count):
    result = {"input": options, "failures": []}
    failures = result["failures"]
    counted = {}
    for arm in ARMS:
        try:
            counted[arm] = workers[arm](repo, options, "count")
        except WorkerError as error:
            failures.append({"arm": arm, "phase": "count", "check": str(error)})
    if failures:
        return result
    reference = counted["baseline"]["preview"]
    reference_json = encoded(reference)
    parity = reference_json == encoded(counted["candidate"]["preview"])
    if not parity:
        failures.append({"check": "full preview parity"})
    if reference["limit_reason"] is not None:
        failures.append({"check": "no plan limit"})
    if expected_count is None:
        if not edge_guards(reference):
            failures.append({"check": "edge guards"})
    elif (
        reference["errors"] or reference["warnings"]
        or reference["totals"]["selected_files"] != expected_count
        or reference["totals"]["units"] != expected_count
    ):
        failures.append({"check": "expected workload coverage"})

    commands = {arm: value["git_commands"] for arm, value in counted.items()}
    totals = {arm: sum(counts.values()) for arm, counts in commands.items()}
    saved = totals["baseline"] - totals["candidate"]
    trees_saved = commands["baseline"].get("ls-tree", 0) - commands["candidate"].get("ls-tree", 0)
    result.update(
        preview_sha256=sha256(reference_json),
        preview_totals=reference["totals"],
        git_commands=commands,
        git_total=totals,
        git_saved=saved,
        ls_tree_saved=trees_saved,
        full_preview_parity=parity,
    )
    expected_saved = 5 if expected_count is None else expected_count
    other_commands = [
        {key: count for key, count in commands[arm].items() if key != "ls-tree"} for arm in ARMS
    ]
    if saved != expected_saved or trees_saved != expected_saved or other_commands[0] != other_commands[1]:
        failures.append({"check": "one ls-tree process saved per admitted blob"})
    if failures or not sample_count or expected_count is None:
        return result

    for arm in ARMS:
        try:
            preview = workers[arm](repo, options, "verify")["preview"]
        except WorkerError as error:
            failures.append({"arm": arm, "phase": "warm-up", "check": str(error)})
            continue
        if encoded(preview) != reference_json:
            failures.append({"arm": arm, "check": "warm-up preview parity"})
    if failures:
        return result

    samples = {arm: [] for arm in ARMS}
    orders = []
    for sample in range(sample_count):
        order = ARMS if sample % 2 == 0 else ARMS[::-1]
        orders.append(order)
        for arm in order:
            try:
                measured = workers[arm](repo, options, "measure")
            except WorkerError as error:
                failures.append({"arm": arm, "sample": sample + 1, "check": str(error)})
                continue
            if encoded(measured["preview"]) != reference_json:
                failures.append({"arm": arm, "sample": sample + 1, "check": "timed preview parity"})
                continue
            samples[arm].append(measured["elapsed_ms"])
    result.update(samples_ms=samples, pair_order=orders, incomplete_samples=len(failures))
    if all(samples.values()):
        medians = {arm: statistics.median(times) for arm, times in samples.items()}
        result.update(
            median_ms=medians,
            range_ms={arm: [min(times), max(times)] for arm, times in samples.items()},
            median_reduction_pct=100 * (1 - medians["candidate"] / medians["baseline"]),
        )
    return result


def isolated_env(root):
    env = {key: os.environ[key] for key in ("SYSTEMROOT",) if key in os.environ}
    env["PATH"] = os.pathsep.join(
        part for part in os.environ.get("PATH", os.defpath).split(os.pathsep) if Path(part).is_absolute()
    )
    for key in (*XDG_DIRS, "TMPDIR"):
        directory = root / key
        directory.mkdir()
        env[key] = str(directory)
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_AUTHOR_DATE="2026-01-01T00:00:00Z",
        GIT_COMMITTER_DATE="2026-01-01T00:00:00Z",
        GIT_AUTHOR_NAME="Synthetic Benchmark",
        GIT_COMMITTER_NAME="Synthetic Benchmark",
        GIT_AUTHOR_EMAIL="benchmark@example.invalid",
        GIT_COMMITTER_EMAIL="benchmark@example.invalid",
        LC_ALL="C",
    )
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output filename")
    checkouts = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    locate_engine(checkouts["baseline"])
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from run import SAMPLES, fixture

    sample_count = 0 if args.verify_only else SAMPLES
    with tempfile.TemporaryDirectory(prefix="mortis-preview-comparison-", dir=args.output.parent) as temp:
        root = Path(temp)
        env = isolated_env(root)
        revisions = {arm: checkout_identity(path, env) for arm, path in checkouts.items()}
        small, large, edge = root / "small", root / "large", root / "edge"
        small_base, small_head = fixture(small, env, 4)
        large_base, large_head = fixture(large, env, 80)
        edge_base, edge_head = fixture(edge, env, 2, edges=True)
        workloads = {
            "edge": (edge, {"mode": "commits", "base": edge_base, "head": edge_head}, None),
            "commits_4": (small, {"mode": "commits", "base": small_base, "head": small_head}, 4),
            "commits_80": (large, {"mode": "commits", "base": large_base, "head": large_head}, 80),
            "all_80": (large, {"mode": "all", "head": large_head}, 80),
        }
        with ExitStack() as stack:
            workers = {arm: stack.enter_context(worker(path, env, root)) for arm, path in checkouts.items()}
            cases = {
                name: run_case(repo, options, count, workers, sample_count)
                for name, (repo, options, count) in workloads.items()
            }
        checkout_stable = revisions == {arm: checkout_identity(path, env) for arm, path in checkouts.items()}
        git_version = git(root, env, "--version").decode().strip()

    timing_passed = None if args.verify_only else all(
        cases[key].get("median_reduction_pct", 0) >= 15 for key in ("commits_80", "all_80")
    )
    passed = checkout_stable and all(not case["failures"] for case in cases.values()) and timing_passed is not False
    report = {
        "evidence": "offline public Python API benchmark comparing actual Engine source",
        "engine": revisions,
        "checkout_stable": checkout_stable,
        "harness_sha256": {
            name: sha256(Path(__file__).with_name(name).read_bytes()) for name in ("compare.py", "run.py")
        },
        "python": platform.python_version(),
        "git": git_version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "samples_per_arm": sample_count,
        "provider_cost_tokens": None,
        "cases": cases,
        "timing_threshold_passed": timing_passed,
        "passed": passed,
    }
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        run_worker(Path(sys.argv[2]))
    else:
        main()
