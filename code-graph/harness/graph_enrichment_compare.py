"""Compare Engine graph enrichment from two local checkouts with replayed parser facts."""

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
from pathlib import Path

SOURCE_SCOPE = ("src/mortis_engine", "pyproject.toml", "uv.lock")
TRACED_WORKLOADS = ("single_assignment", "many_assignments")


def worker(checkout):
    import time
    import tracemalloc
    from importlib.metadata import distributions

    from graph_enrichment import (
        SAMPLES,
        WARMUPS,
        WORKLOADS,
        arms,
        code_graph,
        git,
        hardware,
        json_bytes,
        sha,
        snapshot,
        verify_controls,
        workload,
    )

    source = checkout / "src/mortis_engine/code_graph/__init__.py"
    if source.resolve() != Path(code_graph.__file__).resolve():
        raise ValueError("Loaded graph enrichment from outside the selected Engine checkout")

    def identity():
        tracked = git(checkout, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD", "--", *SOURCE_SCOPE)
        untracked = sorted(git(checkout, "ls-files", "--others", "--exclude-standard", "-z", "--",
                               *SOURCE_SCOPE).decode().strip("\0").split("\0"))
        new_files = [(path, sha((checkout / path).read_bytes())) for path in untracked if path]
        return {
            "revision": git(checkout, "rev-parse", "HEAD").decode().strip(),
            "worktree_diff_sha256": sha(tracked + b"\0" + json_bytes(new_files)),
            "code_graph_module_sha256": sha(source.read_bytes()),
            "working_tree": bool(tracked or new_files),
        }

    def send(data):
        print(json.dumps(data, ensure_ascii=False), flush=True)

    dependencies = {
        item.name.lower(): item.version for item in distributions() if item.name.lower() != "mortis-engine"
    }
    send({
        "source": identity(),
        "environment": {
            "python": platform.python_version(), "implementation": sys.implementation.name,
            "dependencies": dict(sorted(dependencies.items())),
        },
        "host": {**hardware(), "git": git(checkout, "--version").decode().strip(), "os_release": platform.release()},
        "fixture_harness_sha256": sha(Path(__file__).with_name("graph_enrichment.py").read_bytes()),
        "protocol": {"workloads": list(WORKLOADS), "warmups": WARMUPS, "samples": SAMPLES},
        "controls": verify_controls(vars(code_graph).copy()),
    })
    for line in sys.stdin:
        action, name = json.loads(line)
        try:
            if action == "load":
                fixture = snapshot(*workload(*WORKLOADS[name]))
                run, metadata, request_mock, parser_mock = arms(vars(code_graph).copy(), fixture)
                send({
                    **metadata, "max_context_bytes": code_graph.MAX_BYTES_PER_RUN,
                    "first_source_size": fixture[0].files[0].size_bytes,
                })
            elif action == "identity":
                send(identity())
            else:
                with request_mock, parser_mock:
                    if action == "trace":
                        tracemalloc.start()
                        try:
                            output = run("baseline")
                            _, peak = tracemalloc.get_traced_memory()
                        finally:
                            tracemalloc.stop()
                        metrics = {"peak_bytes": peak}
                    elif action == "measure":
                        start = time.perf_counter_ns()
                        output = run("baseline")
                        metrics = {"elapsed_ms": (time.perf_counter_ns() - start) / 1_000_000}
                    else:
                        raise ValueError("Unknown worker action")
                send({"output": json_bytes(output).decode(), **metrics})
        except Exception as error:
            send({"error": type(error).__name__})


def start_worker(checkout, python):
    # Keep the interpreter executable's virtualenv path even when it is a symlink.
    argv = [str(python.absolute()), "-B", "-s", str(Path(__file__).resolve()), "--worker", str(checkout)]
    env = {**os.environ, "PYTHONPATH": str(checkout / "src"), "PYTHONHASHSEED": "0"}
    return subprocess.Popen(
        argv, cwd=checkout, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding="utf-8",
    )


def receive(process):
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("Engine benchmark worker exited before sending a result")
    return json.loads(line)


def request(process, action, name=None):
    process.stdin.write(json.dumps([action, name]) + "\n")
    process.stdin.flush()
    return receive(process)


def workload_metadata(workers, name):
    baseline = request(workers["baseline"], "load", name)
    candidate = request(workers["candidate"], "load", name)
    if "error" in baseline or "error" in candidate or baseline != candidate:
        raise ValueError(f"Could not load matching fixtures for {name}")
    return baseline


def measure(workers, name, metadata, protocol):
    import hashlib

    warmups = protocol["warmups"]
    samples = {arm: [] for arm in workers}
    errors = []
    reference = None
    for pair in range(warmups + protocol["samples"]):
        order = workers if pair % 2 == 0 else reversed(workers)
        for arm in order:
            result = request(workers[arm], "measure")
            if "error" not in result:
                output = result["output"]
                if arm == "baseline" and reference is None:
                    graph, status = json.loads(output)
                    if not graph or status["status"] != "ready":
                        result["error"] = "Fixture did not produce supporting source"
                    elif name in {"medium", "many_assignments"} and not (
                        0 <= metadata["max_context_bytes"] - status["source_bytes"] < metadata["first_source_size"]
                    ):
                        result["error"] = "Fixture did not reach the graph's run-wide byte budget"
                    else:
                        reference = output
                if "error" not in result and output != reference:
                    result["error"] = "Output differs from the baseline reference"
            if "error" in result:
                errors.append({
                    "arm": arm, "pair": pair, "phase": "warmup" if pair < warmups else "sample",
                    "error": result["error"],
                })
            elif pair >= warmups:
                samples[arm].append(result["elapsed_ms"])
    statistics_by_arm = {
        arm: {"count": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}
        for arm, values in samples.items() if values
    }
    reduction = (
        100 * (1 - statistics_by_arm["candidate"]["median"] / statistics_by_arm["baseline"]["median"])
        if statistics_by_arm.keys() == workers.keys() else None
    )
    threshold = -10 if name in {"single_assignment", "small"} else 25
    return {
        **metadata, "elapsed_ms": samples, "elapsed_ms_summary": statistics_by_arm,
        "output_sha256": hashlib.sha256(reference.encode()).hexdigest() if reference is not None else None,
        "median_reduction_percent": reduction, "threshold_reduction_percent": threshold,
        "passes": not errors and reduction is not None and reduction >= threshold,
        "errors": errors, "failed_calls": len(errors),
    }


def collect(workers, check_only):
    import hashlib

    manifest = {arm: receive(process) for arm, process in workers.items()}
    for field in ("environment", "fixture_harness_sha256", "protocol", "controls"):
        if manifest["baseline"][field] != manifest["candidate"][field]:
            raise ValueError(f"Benchmarked checkouts require matching {field}")
    baseline = manifest["baseline"]
    protocol = baseline["protocol"]
    report = {
        "evidence": "offline deterministic component benchmark with replayed parser transport",
        "timed_component": "mortis_engine.code_graph.enrich",
        "checkouts": {arm: manifest[arm]["source"] for arm in workers},
        "environment": baseline["environment"],
        "configuration": {**baseline["host"], "concurrency": 1, "python_hash_seed": "0"},
        "fixture_harness_sha256": baseline["fixture_harness_sha256"],
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "warmups_per_arm": protocol["warmups"],
        "samples_per_arm": protocol["samples"],
        "controls": baseline["controls"],
        "workloads": {},
        "provider_usage": None,
        "provider_cost": None,
    }
    for name in protocol["workloads"]:
        metadata = workload_metadata(workers, name)
        report["workloads"][name] = metadata if check_only else measure(workers, name, metadata, protocol)
    if not check_only:
        for name in TRACED_WORKLOADS:
            measured = report["workloads"][name]
            if measured["errors"]:
                continue
            workload_metadata(workers, name)
            peaks = {}
            for arm, process in workers.items():
                result = request(process, "trace")
                if ("error" in result or
                    hashlib.sha256(result["output"].encode()).hexdigest() != measured["output_sha256"]):
                    measured["errors"].append({"arm": arm, "phase": "trace", "error": "Traced run failed parity"})
                    measured["failed_calls"] += 1
                    measured["passes"] = False
                else:
                    peaks[arm] = result["peak_bytes"]
            measured["peak_traced_python_bytes"] = peaks
        report["passes"] = all(item["passes"] for item in report["workloads"].values())
    for arm, process in workers.items():
        if request(process, "identity") != manifest[arm]["source"]:
            raise ValueError(f"The {arm} Engine checkout changed during measurement")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-checkout", type=Path, required=True)
    parser.add_argument("--candidate-checkout", type=Path, required=True)
    parser.add_argument("--baseline-python", type=Path)
    parser.add_argument("--candidate-python", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-fixtures-only", action="store_true")
    args = parser.parse_args()
    if args.output is None and not args.check_fixtures_only:
        parser.error("--output is required for measurement")
    baseline = args.baseline_checkout.resolve()
    candidate = args.candidate_checkout.resolve()
    with (
        start_worker(baseline, args.baseline_python or baseline / ".venv/bin/python") as base_worker,
        start_worker(candidate, args.candidate_python or candidate / ".venv/bin/python") as candidate_worker,
    ):
        report = collect({"baseline": base_worker, "candidate": candidate_worker}, args.check_fixtures_only)
    if args.check_fixtures_only:
        print(json.dumps(report, indent=2))
        return 0
    with args.output.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(report, indent=2) + "\n")
    return 0 if report["passes"] else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(Path(sys.argv[2]))
    else:
        sys.exit(main())
