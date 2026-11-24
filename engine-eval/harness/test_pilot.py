"""Offline fixture checks; intentionally outside the database-backed backend suite."""

import copy
import json
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare


class PilotTests(unittest.TestCase):
    def test_head_and_control_oracles(self):
        for case_id in prepare.EXPECTED_IDS:
            with self.subTest(case=case_id):
                folder = prepare.PILOT / case_id
                case, truth = prepare.load_case(folder)
                check = runpy.run_path(str(folder / "oracle.py"))["check"]
                self.assertIs(check(copy.deepcopy(case["head"])), truth["oracle_head"])
                self.assertIs(check(copy.deepcopy(truth["control"])), True)

    def test_frozen_sources_export_without_truth(self):
        frozen = json.loads(prepare.MANIFEST.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            self.assertEqual(prepare.build(output), frozen)
            for case in frozen["cases"]:
                folder = output / case["case_id"]
                repo = folder / "repo"
                self.assertEqual(
                    {p.name for p in folder.iterdir()},
                    {"repo", "context.json", "change.diff"},
                )
                context = json.loads((folder / "context.json").read_text())
                self.assertEqual(
                    set(context),
                    {
                        "case_id",
                        "workload",
                        "context",
                        "selection",
                        "graph",
                        "base_sha",
                        "head_sha",
                        "merge_base_sha",
                    },
                )
                tracked = (
                    prepare.git(repo, "ls-tree", "-r", "--name-only", "head")
                    .decode()
                    .splitlines()
                )
                self.assertEqual(sorted(tracked), sorted(case["head"]["blobs"]))
                for path, blob in case["head"]["blobs"].items():
                    self.assertEqual(
                        prepare.digest((repo / path).read_bytes()), blob["sha256"]
                    )
                base = prepare.git(repo, "merge-base", "base", "head").decode().strip()
                self.assertEqual(base, case["merge_base_sha"])

    def test_unsafe_export_paths_are_rejected(self):
        for path in (
            "",
            ".",
            "/absolute",
            "../escape",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            ".git/config",
            ".GIT/config",
            "a\0b",
            "a\x7fb",
            "C:/file",
        ):
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                prepare.safe_path(path)

    def test_stale_case_adjudication_is_rejected(self):
        frozen = json.loads(prepare.MANIFEST.read_text())
        for kind in ("input", "truth", "oracle"):
            records = {item["case_id"]: copy.deepcopy(item) for item in frozen["cases"]}
            records["pr-01"]["hashes"][kind] = "0" * 64
            with (
                self.subTest(changed=kind),
                tempfile.TemporaryDirectory() as tmp,
                patch.object(
                    prepare,
                    "prepare_case",
                    side_effect=lambda folder, output, snapshot=records: snapshot[
                        folder.name
                    ],
                ),
                self.assertRaises(AssertionError),
            ):
                prepare.build(Path(tmp))

    def test_input_rejects_truth_injection_and_bad_locations(self):
        source = prepare.PILOT / "pr-01"
        case, truth = prepare.load_case(source)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "pr-01"
            folder.mkdir()
            (folder / "truth.json").write_text(json.dumps(truth))
            (folder / "input.json").write_text(json.dumps({**case, "truth": truth}))
            with self.assertRaises(ValueError):
                prepare.load_case(folder)
            (folder / "input.json").write_text(json.dumps(case))
            truth["defects"][0]["locations"][0]["end_line"] = 1_000_000
            (folder / "truth.json").write_text(json.dumps(truth))
            with self.assertRaises(AssertionError):
                prepare.load_case(folder)

    def test_defect_citations_require_selected_available_source(self):
        case, truth = prepare.load_case(prepare.PILOT / "pr-01")
        for selection in (
            {"paths": [], "excluded": [], "unavailable": []},
            {
                "paths": ["billing.py"],
                "excluded": [],
                "unavailable": [{"path": "billing.py", "reason": "source_unavailable"}],
            },
            {
                "paths": ["billing.py"],
                "excluded": [],
                "unavailable": [{"path": "missing.py", "reason": "source_unavailable"}],
            },
        ):
            with (
                self.subTest(selection=selection),
                tempfile.TemporaryDirectory() as tmp,
            ):
                folder = Path(tmp) / "pr-01"
                folder.mkdir()
                (folder / "input.json").write_text(
                    json.dumps({**case, "selection": selection})
                )
                (folder / "truth.json").write_text(json.dumps(truth))
                with self.assertRaises(AssertionError):
                    prepare.load_case(folder)


if __name__ == "__main__":
    unittest.main()
