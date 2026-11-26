"""Offline benchmark for the standalone Engine's code-graph enrichment component."""

import argparse
import base64
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

from mortis_engine import code_graph
from mortis_engine.code_graph.contracts import CodeGraphRequest, CodeGraphResult, blob_sha, source_lines
from mortis_engine.code_graph.validation import validate_result

BASELINE = """        for assigned in sorted({unit.path for unit in plan.units}):
            neighbors = set()
            for edge in parsed.imports:
                if edge.target_path and edge.provenance == "relative_path":
                    if edge.file_path == assigned:
                        neighbors.add(edge.target_path)
                    if edge.target_path == assigned:
                        neighbors.add(edge.file_path)
"""
CANDIDATE = """        neighbors_by_path = {path: set() for path in sorted({unit.path for unit in plan.units})}
        for edge in parsed.imports:
            target = edge.target_path
            if target and edge.provenance == "relative_path":
                origin = edge.file_path
                if origin in neighbors_by_path:
                    neighbors_by_path[origin].add(target)
                if target in neighbors_by_path:
                    neighbors_by_path[target].add(origin)
        for assigned, neighbors in neighbors_by_path.items():
"""
OFFSETS_SMALL = (-1, 0, 1, 1, 2)
OFFSETS_LARGE = (-7, -4, -3, -2, -1, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
WORKLOADS = {
    "single_assignment": (1000, 1, OFFSETS_LARGE),
    "small": (100, 25, OFFSETS_SMALL),
    "medium": (1000, 100, OFFSETS_LARGE),
    "many_assignments": (1000, 1000, OFFSETS_LARGE),
}
WARMUPS = 2
SAMPLES = 9


def json_bytes(data):
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(checkout, *args):
    return subprocess.check_output(["git", "-C", str(checkout), *args])


def candidate_function(checkout):
    module = Path("src/mortis_engine/code_graph/__init__.py")
    filename = (checkout / module).resolve()
    if filename != Path(code_graph.__file__).resolve():
        raise ValueError("Use the development environment for the selected Engine checkout")
    source = filename.read_bytes()
    committed = git(checkout, "show", f"HEAD:{module}")
    if source != committed or source.count(BASELINE.encode()) != 1:
        raise ValueError("Baseline code does not match the benchmark's pinned expectation")
    candidate = source.replace(BASELINE.encode(), CANDIDATE.encode())
    namespace = vars(code_graph).copy()
    exec(compile(candidate, "<graph-enrichment-candidate>", "exec"), namespace)
    # Use the shared request mock at call time while retaining the copied implementation.
    return namespace, {
        "base_revision": git(checkout, "rev-parse", "HEAD").decode().strip(),
        "baseline_module_sha256": sha(source),
        "candidate_module_sha256": sha(candidate),
        "replacement_sha256": sha(CANDIDATE.encode()),
        "harness_sha256": sha(Path(__file__).read_bytes()),
        "protocol_sha256": sha(Path(__file__).with_name("graph_enrichment_protocol.md").read_bytes()),
    }


def workload(files, assignments, offsets):
    names = [f"node{i:04}.js" for i in range(files)]
    targets = {
        path: [names[(i + offset) % files] for offset in offsets] + [None]
        for i, path in enumerate(names)
    }
    return targets, set(names[::files // assignments]), {}, {}


def guard_workload():
    targets = {
        "assigned.js": [
            "a-oversize.js", "asset.txt", "b-partial.js", "b-partial.js", "d-parsed.js", "e-parsed.js",
            "assigned.js", None,
        ],
        "isolated.js": [None],
        "a-oversize.js": [],
        "asset.txt": [],
        "b-partial.js": [],
        "c-parsed.js": ["assigned.js"],
        "d-parsed.js": [],
        "e-parsed.js": [],
        "unrelated.js": [None],
        "failed.js": [],
    }
    return (
        targets, {"assigned.js", "isolated.js", "failed.js"},
        {"asset.txt": "unsupported", "b-partial.js": "partial", "failed.js": "failed"},
        {"a-oversize.js": 13 * 1024},
    )


def snapshot(targets, assigned, statuses, extra_bytes):
    manifest, file_results, imports = [], [], []
    for path, neighbors in sorted(targets.items()):
        default_source = "// Synthetic graph source. Acentuación.\n"
        content = default_source.encode()
        for line_number, target in enumerate(neighbors, start=2):
            specifier = "./" + target if target else "external-demo"
            line = f'import "{specifier}";\n'.encode()
            imports.append({
                "file_path": path, "start_byte": len(content), "end_byte": len(content) + len(line) - 1,
                "start_line": line_number, "end_line": line_number, "specifier": specifier,
                "target_path": target, "provenance": "relative_path" if target else "unresolved",
            })
            content += line
        if path in extra_bytes:
            content += b"// " + b"x" * extra_bytes[path] + b"\n"
        if statuses.get(path) == "partial":
            content += b"const example = ;\n"
        metadata = {"path": path, "blob_sha": blob_sha(content), "size_bytes": len(content)}
        result = metadata.copy()
        if PurePosixPath(path).suffix == ".js":
            metadata["content_base64"] = base64.b64encode(content).decode()
        status = statuses.get(path, "parsed")
        result["status"] = status
        if status == "unsupported":
            result["reason"] = "unsupported_language"
        elif status == "failed":
            result.update(language="javascript", reason="parse_error")
        else:
            result.update(language="javascript", line_count=source_lines(content), unresolved_calls=0)
            if status == "partial":
                result["reason"] = "syntax_error"
        manifest.append(metadata)
        file_results.append(result)
    identifiers = json_bytes(manifest)
    commit = hashlib.sha1(identifiers).hexdigest()
    plan = SimpleNamespace(head_sha=commit, units=[SimpleNamespace(path=path) for path in sorted(assigned)])
    request = CodeGraphRequest(repository_id=1, commit_sha=commit, policy_digest=sha(identifiers), files=manifest)
    result = CodeGraphResult(
        **request.model_dump(exclude={"files"}), files=file_results, imports=imports
    )
    validate_result(request, result)
    fixture = {
        "fixture_sha256": sha(json_bytes([request.model_dump(), result.model_dump(), sorted(assigned)])),
        "indexed_files": len(targets),
        "assignments": len(assigned),
        "parser_imports": len(imports),
        "serialized_source_bytes": sum(file.size_bytes for file in request.files if file.content_base64),
    }
    return request, result, plan, fixture


def arms(namespace, make_fixture):
    request, result, plan, metadata = make_fixture

    def fixed_request(*args, **kwargs):
        return request

    def replay_extract(*args, **kwargs):
        return result

    namespace["_request"] = fixed_request
    implementation = {"baseline": code_graph.enrich, "candidate": namespace["enrich"]}

    def run(arm):
        return implementation[arm](None, {}, plan, {"_graph": True}, {})

    return (
        run, metadata, patch.object(code_graph, "_request", fixed_request),
        patch.object(code_graph.transport, "extract", replay_extract),
    )


def verify_controls(namespace):
    run, metadata, request_mock, parser_mock = arms(namespace, snapshot(*guard_workload()))
    with request_mock, parser_mock:
        baseline = run("baseline")
        candidate = run("candidate")
    if json_bytes(baseline) != json_bytes(candidate):
        raise AssertionError("Candidate changed the guard workload output")
    graph, status = baseline
    supporting = graph["assigned.js"]
    checks = {
        "only_assigned_with_eligible_neighbors": set(graph) == {"assigned.js"},
        "three_ordered_sources": [item["path"] for item in supporting["sources"]]
        == ["b-partial.js", "c-parsed.js", "d-parsed.js"],
        "truncation_reported": supporting["truncated"] is True,
        "partial_coverage_reported": supporting["index_status"] == status["status"] == "partial"
        and status["partial_files"] == 1,
        "source_bytes_correct": status["source_bytes"] == sum(
            item["size_bytes"] for item in supporting["sources"]
        ),
    }
    if not all(checks.values()):
        raise AssertionError(f"Guard workload failed: {checks}")
    return {**metadata, "checks": checks, "output_sha256": sha(json_bytes(baseline))}


def measure(name, namespace, make_fixture):
    run, metadata, request_mock, parser_mock = arms(namespace, make_fixture)
    samples = {"baseline": [], "candidate": []}
    errors = []
    reference = None
    with request_mock, parser_mock:
        for pair in range(WARMUPS + SAMPLES):
            order = ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
            for arm in order:
                try:
                    start = time.perf_counter_ns()
                    graph, status = run(arm)
                    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                    output = json_bytes((graph, status))
                    if arm == "baseline" and reference is None:
                        if not graph or status["status"] != "ready":
                            raise AssertionError("Fixture did not produce supporting source")
                        if name in {"medium", "many_assignments"}:
                            source_size = make_fixture[0].files[0].size_bytes
                            remaining = code_graph.MAX_BYTES_PER_RUN - status["source_bytes"]
                            if not 0 <= remaining < source_size:
                                raise AssertionError("Fixture did not reach the graph's run-wide byte budget")
                        reference = output
                    if output != reference:
                        raise AssertionError("Output differs from the baseline reference")
                    if pair >= WARMUPS:
                        samples[arm].append(elapsed_ms)
                except Exception as error:
                    errors.append({
                        "arm": arm, "phase": "warmup" if pair < WARMUPS else "sample",
                        "pair": pair, "type": type(error).__name__, "message": str(error),
                    })
    summary = {
        arm: {"count": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}
        for arm, values in samples.items() if values
    }
    reduction = (
        100 * (1 - summary["candidate"]["median"] / summary["baseline"]["median"])
        if set(summary) == {"baseline", "candidate"} else None
    )
    threshold = -10 if name in {"single_assignment", "small"} else 25
    return {
        **metadata, "elapsed_ms": samples, "elapsed_ms_summary": summary,
        "output_sha256": sha(reference) if reference is not None else None,
        "median_reduction_percent": reduction, "threshold_reduction_percent": threshold,
        "passes": not errors and reduction is not None and reduction >= threshold,
        "errors": errors, "failed_calls": len(errors),
    }


def hardware():
    result = {"machine": platform.machine(), "os": platform.system(), "logical_cpu_count": os.cpu_count()}
    if platform.system() == "Darwin":
        command = ["sysctl", "-n", "machdep.cpu.brand_string", "hw.memsize"]
        try:
            values = subprocess.check_output(command, stderr=subprocess.DEVNULL).decode().splitlines()
        except subprocess.CalledProcessError:
            pass
        else:
            result.update(cpu=values[0], memory_bytes=int(values[1]))
    return result


def traced_peak(namespace, fixture, expected_hash):
    run, _, request_mock, parser_mock = arms(namespace, fixture)
    peaks = {}
    with request_mock, parser_mock:
        for arm in ("baseline", "candidate"):
            tracemalloc.start()
            try:
                output = run(arm)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            if sha(json_bytes(output)) != expected_hash:
                raise AssertionError("Traced run changed the benchmark output")
            peaks[arm] = peak
    return peaks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--engine-checkout", type=Path, default=Path.cwd())
    parser.add_argument("--check-fixtures-only", action="store_true")
    args = parser.parse_args()
    if args.output is None and not args.check_fixtures_only:
        parser.error("--output is required when timing")
    namespace, revisions = candidate_function(args.engine_checkout)
    controls = verify_controls(namespace)
    fixtures = {name: snapshot(*workload(*size)) for name, size in WORKLOADS.items()}
    if args.check_fixtures_only:
        print(json.dumps({"controls": controls, "workloads": {name: data[-1] for name, data in fixtures.items()}}, indent=2))
        return 0
    result = {
        "evidence": "deterministic offline component benchmark with replayed parser transport",
        "timed_component": "mortis_engine.code_graph.enrich",
        "versions": {
            **revisions, "python": platform.python_version(), "pydantic": version("pydantic"),
            "git": git(args.engine_checkout, "--version").decode().strip(), "os_release": platform.release(),
        },
        "configuration": {**hardware(), "concurrency": 1, "python_hash_seed": os.environ.get("PYTHONHASHSEED")},
        "warmups_per_arm": WARMUPS, "samples_per_arm": SAMPLES, "controls": controls,
        "workloads": {name: measure(name, namespace, fixture) for name, fixture in fixtures.items()},
        "provider_usage": None, "provider_cost": None,
    }
    result["passes"] = all(item["passes"] for item in result["workloads"].values())
    for name in ("single_assignment", "many_assignments"):
        measured = result["workloads"][name]
        if not measured["errors"]:
            measured["peak_traced_python_bytes"] = traced_peak(namespace, fixtures[name], measured["output_sha256"])
    with args.output.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(result, indent=2) + "\n")
    return 0 if result["passes"] else 1


if __name__ == "__main__":
    sys.exit(main())
