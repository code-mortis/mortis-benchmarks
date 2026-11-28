"""Compare Mortis findings with OSV-Scanner for the same two lockfiles."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from live_bench import sample


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch", type=Path, help="Private live-benchmark scratch directory with populated scanner cache")
    parser.add_argument("fixtures", type=Path, help="Directory with the comparison protocol and lockfiles")
    parser.add_argument("profile")
    args = parser.parse_args()
    os.umask(0o077)
    protocol = json.loads((args.fixtures / "protocol.json").read_text())
    state = args.scratch.resolve() / "state"
    assert (state / "mortis/trivy/db/metadata.json").is_file()
    os.environ["XDG_STATE_HOME"] = str(state)
    results = []
    for case in protocol["cases"]:
        data = (args.fixtures / case["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == case["sha256"]
        label = "dep-" + case["case"]
        row = sample(args.scratch / ("repo-" + label), args.profile, label, files={"package-lock.json": data.decode()})
        matched = any(f["rule"] in protocol["advisory_ids"] for f in row.get("findings", []))
        row.update(fixture_sha256=case["sha256"], target_found=matched,
                   passed=row["status"] == "completed" and matched == case["target_advisory_expected"])
        results.append(row)
    (args.scratch / "dependency-results.json").write_text(json.dumps(results, indent=2)+"\n")
    print([(r["sample"],r["status"],r["target_found"],r["tokens"]) for r in results])
    # A standalone manifest with no matching npm lock is an unresolved inventory.
    files = {"requirements.txt": "mortis-audit-fixture==1.0.0\n",
             "package.json": '{"name":"mortis-audit","version":"1.0.0","dependencies":{"minimist":"1.2.5"}}\n'}
    mixed = sample(args.scratch / "repo-mixed", args.profile, "mixed", 8192, files=files)
    mixed["fixture_sha256"] = {key: hashlib.sha256(value.encode()).hexdigest() for key,value in files.items()}
    mixed["expected"] = "partial with an explicit npm coverage gap and unavailable grade"
    mixed["has_npm_gap"] = any("package.json" in str(problem) for problem in mixed.get("problems", []))
    (args.scratch / "mixed-results.json").write_text(json.dumps(mixed, indent=2)+"\n")
    print("Mixed manifests", mixed["status"], mixed.get("grade"), mixed["has_npm_gap"])


if __name__ == "__main__":
    main()
