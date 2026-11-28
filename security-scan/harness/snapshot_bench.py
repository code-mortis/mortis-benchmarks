"""Compare current security snapshot population with OID-based blob reads."""

import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from mortis_engine.review import file_policy, source
from mortis_engine.security import digest
from mortis_engine.security_scans import engine


ROOT = Path(__file__).resolve().parent
SIZES = (20, 100)
SAMPLES_PER_ARM = 4
FILE_BYTES = 8192
THRESHOLDS = {
    "minimum_samples_per_arm": 3,
    "minimum_git_process_reduction_percent": 40.0,
    "maximum_median_elapsed_regression_percent": 10.0,
    "correctness_guard": "inventory, exclusions, problems, and materialized-byte digest must match exactly",
}


def run_git(repository, *args):
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    ).stdout.strip()


def fixture_content(index):
    prefix = f"# generated security snapshot benchmark file {index:04d}\n"
    seed = hashlib.sha256(f"mortis-snapshot-{index}".encode()).hexdigest()
    repeated = (seed * ((FILE_BYTES // len(seed)) + 1)).encode()[: FILE_BYTES - len(prefix)]
    return prefix.encode() + repeated


def make_repository(root, file_count):
    repository = root / "repo"
    repository.mkdir()
    run_git(repository, "init", "--quiet")
    for index in range(file_count):
        path = repository / "src" / f"module_{index:04d}.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_content(index))
    (repository / "src" / "binary.dat").write_bytes(b"\x00binary\xfffixture")
    excluded = repository / "node_modules" / "generated" / "ignored.js"
    excluded.parent.mkdir(parents=True)
    excluded.write_text("generated directory guard\n", encoding="utf-8")
    (repository / "src" / "link.py").symlink_to("module_0000.py")
    run_git(repository, "add", "--all")
    run_git(repository, "-c", "user.name=Snapshot Benchmark", "-c", "user.email=benchmark@example.invalid",
            "commit", "--quiet", "-m", "synthetic snapshot fixture")
    return repository, run_git(repository, "rev-parse", "HEAD")


def populate_by_oid(item):
    """Benchmark-only prototype with the production population rules."""
    entries = engine.git_source.git(item.git, item.env, "ls-tree", "-r", "-l", "-z", item.sha,
                                    stopped=item.stopped)
    total = 0
    for entry in entries.split("\0"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        engine.relative_path(path)
        mode, kind, blob, size = metadata.split()
        if any(part in engine.EXCLUDED for part in Path(path).parts):
            item.excluded.append({"path": path, "reason": "Generated, dependency or cache directory"})
            continue
        if mode not in {"100644", "100755"} or kind != "blob":
            item.excluded.append({"path": path, "reason": "Symlink or submodule is not followed"})
            continue
        byte_count = int(size)
        if byte_count > 4_000_000:
            item.problems.append({"path": path, "reason": "File exceeds the 4 MB evidence limit"})
            continue
        total += byte_count
        if total > 500_000_000:
            raise ValueError("The repository exceeds the 500 MB security snapshot limit.")
        try:
            content = engine.git_source.read_pinned_blob(item.git, item.env, blob, byte_count, item.stopped)
        except ValueError:
            item.excluded.append({"path": path, "reason": "Binary or unsupported text encoding"})
            continue
        target = item.files / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        item.inventory[path] = {
            "sha": blob,
            "hash": digest(content),
            "lines": len(content.splitlines()),
            "code": (Path(path).suffix.lower() in engine.CODE_EXTENSIONS
                     or Path(path).name.lower() in {"dockerfile", "containerfile"})
                    and not file_policy.excluded(path, item.policy)
                    and not any(part in engine.PROTECTED for part in Path(path).parts)
                    and Path(path).name not in engine.INSTRUCTION_FILES,
        }
        name = Path(path).name
        if (".generated." in name or ".min." in name
                or name.endswith((".pb.go", "_pb2.py", "_pb2_grpc.py"))
                or name in {"package-lock.json", "npm-shrinkwrap.json"}):
            item.inventory[path]["code"] = False
            item.excluded.append({"path": path, "reason": "Generated code or resolved dependency data is checked by Trivy, not AI"})
        elif not item.inventory[path]["code"]:
            item.excluded.append({"path": path, "reason": "No AI analysis for this file type or protected instruction path; Trivy may inspect it as data"})


def materialized_digest(directory):
    digest_value = hashlib.sha256()
    total = 0
    for path in sorted((directory / "files").rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(directory / "files").as_posix().encode()
        content = path.read_bytes()
        digest_value.update(len(relative).to_bytes(4, "big"))
        digest_value.update(relative)
        digest_value.update(len(content).to_bytes(8, "big"))
        digest_value.update(content)
        total += len(content)
    return digest_value.hexdigest(), total


def run_once(repository, sha, arm):
    with source.local_repository(repository) as (git_repo, env), tempfile.TemporaryDirectory(
            prefix="mortis-snapshot-bench-") as temporary:
        item = engine.Snapshot(Path(temporary), sha, env, lambda: False, git=git_repo, key=b"k" * 32)
        item.policy = file_policy.policy({})
        calls = []
        original_git = engine.git_source.git

        def counted_git(directory, git_env, *args, **kwargs):
            calls.append(tuple(args))
            return original_git(directory, git_env, *args, **kwargs)

        start = time.perf_counter()
        with patch.object(engine.git_source, "git", counted_git):
            if arm == "current":
                item.populate()
            else:
                populate_by_oid(item)
        elapsed = time.perf_counter() - start
        contents_digest, materialized_bytes = materialized_digest(Path(temporary))
        result = {
            "elapsed_seconds": elapsed,
            "git_processes": len(calls),
            "inventory_digest": digest(json.dumps(item.inventory, sort_keys=True)),
            "excluded_digest": digest(json.dumps(item.excluded, sort_keys=True)),
            "problems_digest": digest(json.dumps(item.problems, sort_keys=True)),
            "materialized_digest": contents_digest,
            "materialized_bytes": materialized_bytes,
            "inventory_files": len(item.inventory),
            "excluded_entries": len(item.excluded),
            "problems": len(item.problems),
        }
        return result


def median(values):
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def summarize(samples):
    elapsed = [sample["elapsed_seconds"] for sample in samples]
    processes = [sample["git_processes"] for sample in samples]
    output_keys = tuple(key for key in samples[0] if key not in {"elapsed_seconds", "git_processes"})
    return {
        "sample_count": len(samples),
        "elapsed_seconds": {"median": median(elapsed), "min": min(elapsed), "max": max(elapsed), "samples": elapsed},
        "git_processes": {"median": median(processes), "min": min(processes), "max": max(processes), "samples": processes},
        "output": {key: samples[0][key] for key in (
            "inventory_digest", "excluded_digest", "problems_digest", "materialized_digest",
            "materialized_bytes", "inventory_files", "excluded_entries", "problems")},
        "all_samples_match_output": all(
            {key: sample[key] for key in output_keys} == {key: samples[0][key] for key in output_keys}
            for sample in samples),
    }


def main():
    source_hashes = {}
    for relative in ("src/mortis_engine/security_scans/engine.py", "src/mortis_engine/review/source.py"):
        source_hashes[relative] = hashlib.sha256((Path.cwd() / relative).read_bytes()).hexdigest()
    revision = run_git(Path.cwd(), "rev-parse", "HEAD")
    results = []
    for file_count in SIZES:
        with tempfile.TemporaryDirectory(prefix="mortis-scan-fixture-", dir=ROOT) as temporary:
            repository, fixture_sha = make_repository(Path(temporary), file_count)
            warm_current = run_once(repository, fixture_sha, "current")
            warm_oid = run_once(repository, fixture_sha, "oid")
            correctness_keys = (
                "inventory_digest", "excluded_digest", "problems_digest", "materialized_digest", "materialized_bytes")
            warm_equal = all(warm_current[key] == warm_oid[key] for key in correctness_keys)
            if not warm_equal:
                raise RuntimeError(f"Correctness guard failed for {file_count} source files")
            samples = {"current": [], "oid": []}
            for sample_index in range(SAMPLES_PER_ARM):
                arms = ("current", "oid") if sample_index % 2 == 0 else ("oid", "current")
                for arm in arms:
                    samples[arm].append(run_once(repository, fixture_sha, arm))
            summarized = {arm: summarize(rows) for arm, rows in samples.items()}
            equal_samples = all(
                all(samples["current"][index][key] == samples["oid"][index][key] for key in correctness_keys)
                for index in range(SAMPLES_PER_ARM)
            )
            baseline_processes = summarized["current"]["git_processes"]["median"]
            candidate_processes = summarized["oid"]["git_processes"]["median"]
            process_reduction = 100 * (baseline_processes - candidate_processes) / baseline_processes
            baseline_elapsed = summarized["current"]["elapsed_seconds"]["median"]
            candidate_elapsed = summarized["oid"]["elapsed_seconds"]["median"]
            elapsed_change = 100 * (candidate_elapsed - baseline_elapsed) / baseline_elapsed
            passed = (equal_samples
                      and process_reduction >= THRESHOLDS["minimum_git_process_reduction_percent"]
                      and elapsed_change <= THRESHOLDS["maximum_median_elapsed_regression_percent"])
            results.append({
                "fixture_files": file_count,
                "fixture_commit": fixture_sha,
                "guard_outputs_equal": equal_samples,
                "git_process_reduction_percent": process_reduction,
                "median_elapsed_change_percent": elapsed_change,
                "thresholds_passed": passed,
                "arms": summarized,
            })
    result = {
        "schema_version": "mortis.security.snapshot-benchmark/v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "offline deterministic component benchmark of snapshot population only",
        "baseline": "current Snapshot.populate using read_source path lookup and blob read",
        "candidate": "benchmark-only population prototype reusing the OID from ls-tree",
        "protocol": {
            "predeclared_thresholds": THRESHOLDS,
            "sizes": list(SIZES),
            "source_file_bytes": FILE_BYTES,
            "samples_per_arm_per_size": SAMPLES_PER_ARM,
            "warmup_runs_per_arm_per_size": 1,
            "order": "alternating arm order for each sample pair after warmups",
            "git_process_count": "count of git_source.git calls, each of which launches one Git subprocess",
            "guards": ["valid UTF-8 regular files", "NUL-containing binary file", "node_modules exclusion", "symlink exclusion"],
            "included_in_timing": ["Git tree listing", "Git blob reads", "snapshot file writes", "inventory and exclusion construction"],
            "excluded_from_timing": ["fixture creation", "isolated local_repository preparation", "temporary directory setup", "materialized output hashing"],
        },
        "environment": {
            "engine_revision": revision,
            "engine_source_sha256": source_hashes,
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "git": run_git(Path.cwd(), "--version"),
        },
        "runs": results,
        "overall_thresholds_passed": all(row["thresholds_passed"] for row in results),
        "limitations": [
            "Synthetic committed files only, with no Trivy, provider, or end-to-end scan time.",
            "Four samples per arm provide a local timing comparison, not a production performance guarantee.",
            "The candidate is a benchmark-only prototype and does not modify engine source.",
        ],
    }
    output = ROOT / "snapshot-results.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "result_file": str(output),
        "overall_thresholds_passed": result["overall_thresholds_passed"],
        "runs": [{
            "fixture_files": row["fixture_files"],
            "guard_outputs_equal": row["guard_outputs_equal"],
            "git_process_reduction_percent": row["git_process_reduction_percent"],
            "median_elapsed_change_percent": row["median_elapsed_change_percent"],
            "current_median_seconds": row["arms"]["current"]["elapsed_seconds"]["median"],
            "oid_median_seconds": row["arms"]["oid"]["elapsed_seconds"]["median"],
            "current_git_processes": row["arms"]["current"]["git_processes"]["median"],
            "oid_git_processes": row["arms"]["oid"]["git_processes"]["median"],
        } for row in results],
    }, indent=2))


if __name__ == "__main__":
    main()
