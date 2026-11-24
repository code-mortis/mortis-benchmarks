"""Freeze/export original pilot fixtures. No model, application DB, or network access.

Only input.json enters exported repositories. Truth and oracles stay with the scorer.
Oracles are trusted, authored tests; this script does not execute fixture source.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
PILOT = ROOT / "pilot"
MANIFEST = ROOT / "pilot_manifest.json"
EXPECTED_IDS = [f"pr-{i:02}" for i in range(1, 13)] + [
    f"sec-{i:02}" for i in range(1, 9)
]


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def safe_path(path):
    parts = PurePosixPath(path).parts
    if (
        not parts
        or path != str(PurePosixPath(path))
        or path.startswith("/")
        or "\\" in path
    ):
        raise ValueError(f"Invalid fixture path: {path!r}")
    if any(
        part.lower() in {"..", ".git"}
        or ":" in part
        or any(ord(c) < 32 or ord(c) == 127 for c in part)
        for part in parts
    ):
        raise ValueError(f"Unsafe fixture path: {path!r}")
    return path


def load_case(folder):
    case = json.loads((folder / "input.json").read_text())
    truth = json.loads((folder / "truth.json").read_text())
    if set(case) != {
        "case_id",
        "family_id",
        "workload",
        "split",
        "provenance",
        "context",
        "base",
        "head",
        "selection",
        "graph",
    }:
        raise ValueError(f"Unexpected input fields: {folder.name}")
    assert case["case_id"] == truth["case_id"] == folder.name
    assert re.fullmatch(r"(?:pr|sec)-\d{2}", case["case_id"])
    assert case["workload"] == ("pr" if folder.name.startswith("pr-") else "security")
    assert case["split"] == "pilot" and case["provenance"] == "original_synthetic"
    for files in (case["base"], case["head"], truth["control"]):
        for path, source in files.items():
            safe_path(path)
            assert isinstance(source, str) and "\0" not in source
            assert not any(
                parent.as_posix() in files for parent in PurePosixPath(path).parents
            )
    selection = case["selection"]
    selected = selection["paths"]
    excluded = {
        safe_path(item["path"]) for item in selection["excluded"] if item["reason"]
    }
    unavailable = {
        safe_path(item["path"]) for item in selection["unavailable"] if item["reason"]
    }
    assert len(selected) == len(set(selected)) and not set(selected) & excluded
    assert unavailable <= set(selected)
    assert excluded <= case["base"].keys() | case["head"].keys()
    for path in selected:
        safe_path(path)
        assert path in case["base"] or path in case["head"] or path in unavailable
    assert truth["expected"] in {"defect", "clean", "incomplete"}
    assert bool(truth["defects"]) == (truth["expected"] == "defect")
    assert truth["oracle_head"] is (truth["expected"] != "defect")
    assert truth["oracle_control"] is True
    for defect in truth["defects"]:
        assert all(
            defect.get(k)
            for k in (
                "id",
                "severity",
                "cause",
                "trigger",
                "consequence",
                "boundary",
                "locations",
                "evidence",
                "proof",
            )
        )
        assert defect["severity"] in {"low", "medium", "high", "critical"}
        for location in defect["locations"]:
            source = case["head"][location["path"]]
            assert location["path"] in selected and location["path"] not in unavailable
            assert (
                1
                <= location["start_line"]
                <= location["end_line"]
                <= len(source.splitlines())
            )
    return case, truth


def git(repo, *args, data=None):
    # Ignore developer Git filters, hooks, signing and templates; fixture trees are ordinary files.
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Mortis pilot",
        "GIT_AUTHOR_EMAIL": "pilot@example.invalid",
        "GIT_COMMITTER_NAME": "Mortis pilot",
        "GIT_COMMITTER_EMAIL": "pilot@example.invalid",
        "GIT_AUTHOR_DATE": "1794009600 +0000",
        "GIT_COMMITTER_DATE": "1794009600 +0000",
    }
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.autocrlf=false",
            "-c",
            "commit.gpgSign=false",
            "-C",
            str(repo),
            *args,
        ],
        input=data,
        env=env,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def revision(repo, files, parent=None):
    git(repo, "read-tree", "--empty")
    blobs = {}
    for path, source in sorted(files.items()):
        blob = (
            git(repo, "hash-object", "-w", "--stdin", data=source.encode())
            .decode()
            .strip()
        )
        git(repo, "update-index", "--add", "--cacheinfo", "100644", blob, path)
        blobs[path] = {
            "git_blob": blob,
            "sha256": digest(source.encode()),
            "bytes": len(source.encode()),
        }
    tree = git(repo, "write-tree").decode().strip()
    args = ["commit-tree", tree] + (["-p", parent] if parent else [])
    commit = git(repo, *args, data=b"Pilot source snapshot\n").decode().strip()
    return {"commit": commit, "tree": tree, "blobs": blobs}


def prepare_case(folder, output):
    case, truth = load_case(folder)
    repo = output / folder.name / "repo"
    repo.mkdir(parents=True)
    git(
        repo,
        "init",
        "--quiet",
        "--object-format=sha1",
        "--template=",
        "--initial-branch=head",
    )
    base = revision(repo, case["base"])
    head = revision(repo, case["head"], base["commit"])
    git(repo, "update-ref", "refs/heads/base", base["commit"])
    git(repo, "update-ref", "refs/heads/head", head["commit"])
    git(repo, "reset", "--quiet", "--hard", head["commit"])
    diff = git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--find-renames",
        base["commit"],
        head["commit"],
    )
    (repo.parent / "change.diff").write_bytes(diff)
    # Context is a task input, not an oracle. The scorer manifest never enters the repository.
    (repo.parent / "context.json").write_bytes(
        canonical(
            {
                "case_id": case["case_id"],
                "workload": case["workload"],
                "context": case["context"],
                "selection": {**case["selection"], "paths": sorted(case["selection"]["paths"])},
                "graph": case["graph"],
                "base_sha": base["commit"],
                "head_sha": head["commit"],
                "merge_base_sha": base["commit"],
            }
        )
        + b"\n"
    )
    hashes = {
        "input": digest(canonical(case)),
        "truth": digest(canonical(truth)),
        "oracle": digest((folder / "oracle.py").read_bytes()),
    }
    return {
        "case_id": case["case_id"],
        "family_id": case["family_id"],
        "workload": case["workload"],
        "split": "pilot",
        "evaluation_track": "reliability_fixture" if truth["expected"] == "incomplete" else "quality_microcase",
        "repository_id": "synthetic://mortis-engine-pilot-v1/" + case["case_id"],
        "hashes": hashes,
        "case_digest": digest(canonical(hashes)),
        "base": base,
        "head": head,
        "merge_base_sha": base["commit"],
        "default_branch_sha": head["commit"],
        "diff_sha256": digest(diff),
        "selected_paths": sorted(case["selection"]["paths"]),
        "expected_assigned_units": len(case["selection"]["paths"]),
        "scanner_inventory_paths": sorted(case["head"]) if case["workload"] == "security" else [],
        "selection_contract": (
            "injected_unavailable_assignment_not_git_selected_scope"
            if case["selection"]["unavailable"] else "analysis_paths_separate_from_scanner_inventory"
        ),
        "unavailable": case["selection"]["unavailable"],
        "excluded": case["selection"]["excluded"],
    }


def build(output):
    folders = sorted(
        path
        for path in PILOT.iterdir()
        if path.is_dir() and not path.name.startswith("__")
    )
    assert [path.name for path in folders] == EXPECTED_IDS
    records = [prepare_case(folder, output) for folder in folders]
    assert len({case["family_id"] for case in records}) == len(records)
    adjudication = json.loads((ROOT / "reviews/adjudication.json").read_text())
    decisions = {item["case_id"]: item for item in adjudication["cases"]}
    peers = {}
    for path in sorted((ROOT / "reviews").glob("reviewer-*.json")):
        review = json.loads(path.read_text())
        initial = ROOT / "reviews" / review["retained_initial_record"]
        assert digest(initial.read_bytes()) == review["retained_initial_sha256"]
        for item in review.get("cases", review.get("reviewed_cases", [])):
            assert item["case_id"] not in review["authored_excluded"]
            peers.setdefault(item["case_id"], {})[review["reviewer_id"]] = item["input_sha256"]
    for record in records:
        decision = decisions[record["case_id"]]
        assert decision["status"] == "accepted"
        assert len(peers[record["case_id"]]) == 2
        assert sorted(peers[record["case_id"]]) == decision["reviewers"]
        assert set(peers[record["case_id"]].values()) == {record["hashes"]["input"]}
        for kind in ("input", "truth", "oracle"):
            assert decision[kind + "_sha256"] == record["hashes"][kind]
    selection_evidence = json.loads((ROOT / "selection_evidence.json").read_text())
    previews = {item["case_id"]: item for item in selection_evidence["cases"]}
    for record in records:
        if record["workload"] == "pr":
            observed = previews[record["case_id"]]
            assert observed["input_sha256"] == record["hashes"]["input"]
            if record["evaluation_track"] == "quality_microcase":
                assert record["selected_paths"] == sorted(observed["actual_paths"])
    content = {
        "schema": "mortis-engine-pilot/v1",
        "protocol": "mortis-engine-eval/v1.1",
        "source_baseline": "9d91f04e964953e350b64c96bf34c50a17a69439",
        "provenance": "original_synthetic",
        "external_model_calls": 0,
        "cases": records,
        "profile_sha256": digest(canonical(json.loads((ROOT / "pilot_profile.json").read_text()))),
        "review_sha256": {path.name: digest(path.read_bytes()) for path in sorted((ROOT / "reviews").glob("*.json"))},
        "selection_evidence_sha256": digest((ROOT / "selection_evidence.json").read_bytes()),
    }
    content["corpus_digest"] = digest(canonical(content))
    return content


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--freeze",
        action="store_true",
        help="Explicitly rewrite the frozen scorer manifest",
    )
    parser.add_argument(
        "--export",
        type=Path,
        help="Create truth-free source repositories in a NEW directory",
    )
    args = parser.parse_args()
    if args.export and args.export.exists():
        parser.error("Export destination already exists; refusing to overwrite it")
    with tempfile.TemporaryDirectory(prefix="mortis-pilot-") as tmp:
        output = Path(tmp)
        result = build(output)
        if args.freeze:
            MANIFEST.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        elif result != json.loads(MANIFEST.read_text()):
            raise ValueError(
                "Pilot drift: review changed inputs/truth/oracles before explicitly refreezing"
            )
        if args.export:
            shutil.copytree(output, args.export)
    print(
        f"Verified {len(result['cases'])} cases; corpus {result['corpus_digest']}; external model calls: 0"
    )


if __name__ == "__main__":
    main()
