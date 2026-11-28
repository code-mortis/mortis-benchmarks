"""Score saved security benchmark evidence without loading Mortis or calling a provider."""

import argparse
import json
from pathlib import Path


def score(directory):
    def load(name):
        return json.loads((directory / name).read_text(encoding="utf-8"))

    checks = {}
    probe_names = {"assessment_coverage", "dependency_coverage", "forked_history"}
    probes = [json.loads(line) for line in (directory / "probe-results.jsonl").read_text().splitlines()]
    if len(probes) != len(probe_names) or {row["probe"] for row in probes} != probe_names:
        raise ValueError("Missing or duplicate coverage probes")
    for row in probes:
        checks[row["probe"]] = row["actual"] == row["expected"]

    for cap, name, labels in (
        (2048, "live-cap-2048.json", ["cold", "warm-1", "warm-2", "warm-3"]),
        (8192, "higher-cap-results.json", ["warm-higher-1", "warm-higher-2", "warm-higher-3"]),
    ):
        data = load(name)
        if data["protocol"]["limits"]["max_output_tokens"] != cap:
            raise ValueError(f"Wrong output cap in {name}")
        samples = data["samples"]
        checks[f"live_{cap}"] = [row["sample"] for row in samples] == labels and all(
            row["status"] == "completed" and row["exit"] == 0 and row["selected"] == row["completed"] == 2
            and any(f["path"] == "Dockerfile" and f["rule"] == "DS-0002" for f in row["findings"])
            and all(f["path"] != "arithmetic.py" for f in row["findings"]) for row in samples
        )

    mixed = load("mixed-results.json")
    checks["mixed_manifest"] = mixed["status"] == "partial" and mixed["grade"] is None and mixed["has_npm_gap"]
    osv = load("osv-result.json")["cases"]
    mortis = load("dependency-results.json")
    expected = {"affected": True, "updated": False}
    by_case = {row["case"]: row for row in osv}
    by_sample = {row["sample"]: row for row in mortis}
    checks["dependency_comparison"] = (
        len(osv) == len(mortis) == 2 and set(by_case) == expected.keys()
        and set(by_sample) == {"dep-" + case for case in expected}
        and all(by_case[case]["sha256"] == by_sample["dep-" + case]["fixture_sha256"]
                and by_case[case]["package_matches"] == 1 and by_case[case]["status"] == "pass"
                and by_case[case]["target_advisory_found"] is affected
                and by_sample["dep-" + case]["status"] == "completed"
                and by_sample["dep-" + case]["target_found"] is affected for case, affected in expected.items())
    )
    snap = load("snapshot-results.json")["runs"]
    checks["snapshot_prototype"] = sorted(row["fixture_files"] for row in snap) == [20, 100] and all(
        row["guard_outputs_equal"] and row["git_process_reduction_percent"] >= 40
        and row["median_elapsed_change_percent"] <= 10 for row in snap
    )
    prompts = load("prompt-results.json")["runs"]
    amplification = {row["source_files"]: row["source_bytes_across_requests"] / row["unique_corpus_source_bytes_by_path"]
                     for row in prompts}
    if sorted(amplification) != [1, 8, 16, 17] or len(prompts) != 4:
        raise ValueError("Missing or duplicate prompt measurements")
    return {"checks": checks, "passed": all(checks.values()), "observed_source_replication": amplification}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    try:
        result = score(args.results)
    except (OSError, KeyError, ValueError, TypeError, ZeroDivisionError) as error:
        parser.exit(2, f"Incomplete or invalid benchmark evidence: {error}\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
