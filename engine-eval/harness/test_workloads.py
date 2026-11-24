"""Deterministic response fixtures leave all required semantic stages runnable."""

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import workloads


class WorkloadsTests(unittest.TestCase):
    def request(self, properties, context):
        return {"text": {"format": {"schema": {"properties": {name: {} for name in properties}}}},
                "input": [{"role": "user", "content": "# evidence\n\n" + json.dumps(context) + "\nsource block"}]}

    def test_security_analysis_emits_only_on_assigned_file(self):
        for path, count in (("app.py", 1), ("history.py", 0), ("module_1.py", 0)):
            context = {"path": path, "citation_sources": {"source_1": {"revision": "current", "path": "app.py"}}}
            phase, result = workloads.response(self.request(["findings"], context), True)
            value = json.loads(result["output"][0]["content"][0]["text"])
            self.assertEqual(phase, "analysis")
            self.assertEqual(len(value["findings"]), count)
            if count:
                self.assertEqual(value["findings"][0]["evidence"], [{"source_id": "source_1", "start_line": 2, "end_line": 2}])

    def test_security_history_requires_both_original_and_current_citations(self):
        context = {"citation_sources": {f"source_{index}": {"revision": revision, "path": "history.py"}
                                       for index, revision in enumerate(("current", "original"))}}
        phase, result = workloads.response(self.request(["original_issue_present"], context), True)
        value = json.loads(result["output"][0]["content"][0]["text"])
        self.assertEqual(phase, "verification")
        self.assertEqual(value["verdict"], "still_present")
        self.assertTrue(value["original_issue_present"])
        self.assertEqual(len(value["evidence"]), 2)
        self.assertNotIn("dismissal_recommended", value)

    def test_pr_analysis_cites_revision_bound_source_catalog(self):
        context = {"assigned_units": [{"key": "unit-1", "path": "app.py"}], "task_key": "task-1", "citation_sources": [
            {"source_id": "source_1", "revision": "a" * 40, "path": "app.py"}]}
        _, result = workloads.response(self.request(["completed_units"], context), False)
        value = json.loads(result["output"][0]["content"][0]["text"])
        self.assertEqual(value["findings"][0]["evidence"], [{"source_id": "source_1", "start_line": 3, "end_line": 3}])

    def test_pr_verification_does_not_send_security_only_fields(self):
        context = {"citation_sources": {"source_1": {"revision": "current", "path": "history.py"}}}
        _, result = workloads.response(self.request(["original_issue_present"], context), False)
        value = json.loads(result["output"][0]["content"][0]["text"])
        self.assertNotIn("required_paths", value)
        self.assertEqual(value["required_sources"], [])
        self.assertFalse(value["dismissal_recommended"])

    def test_ocr_shared_only_group_does_not_emit_app_comment(self):
        for paths, count in ((["shared.py"], 0), (["app.py", "shared.py"], 1)):
            content = "<review_files>" + "".join(f'<file path="{path}">diff</file>' for path in paths) + "</review_files>"
            body = {"input": [{"role": "user", "content": content}], "tools": [{"name": "code_comment"}, {"name": "task_done"}]}
            _, result = workloads.response(body, False)
            self.assertEqual(sum(item.get("name") == "code_comment" for item in result["output"]), count)
            self.assertEqual(workloads.ocr_review_paths(body), set(paths))

    def test_shared_assignment_never_emits_app_finding(self):
        context = {"assigned_units": [{"key": "shared-unit", "path": "shared.py"}], "task_key": "task-1",
                   "citation_sources": [{"source_id": "app-source", "path": "app.py", "revision": "a" * 40}]}
        _, result = workloads.response(self.request(["completed_units"], context), False)
        value = json.loads(result["output"][0]["content"][0]["text"])
        self.assertEqual(value["completed_units"], ["shared-unit"])
        self.assertEqual(value["findings"], [])

    def test_profiles_keep_two_assigned_pr_sources_and_clean_single_file_controls(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            history = workloads.fixture(Path(temporary) / "history/pr-100", "pr")
            self.assertEqual(history["selected_paths"], ["app.py", "shared.py"])
            for workload in ("pr", "security"):
                case = workloads.fixture(Path(temporary) / workload / "pr-100", workload, "clean")
                self.assertEqual(case["selected_paths"], ["app.py"])
                self.assertEqual(case["historical_findings"], [])

    def test_neutral_binding_is_reproducible_and_pins_actual_stage_counts(self):
        import tempfile
        settings = SimpleNamespace(encryption_key="workload-test-only")
        with tempfile.TemporaryDirectory() as temporary, patch(
            "code_mortis.security_scans.engine.settings", return_value=settings
        ):
            for workload in ("pr", "security"):
                for profile in ("clean", "history"):
                    name = "pr-100" if workload == "pr" else "sec-100"
                    first = workloads.workload_binding(Path(temporary) / "first" / workload / profile / name, workload, profile)
                    second = workloads.workload_binding(Path(temporary) / "second" / workload / profile / name, workload, profile)
                    self.assertEqual(first, second)
                    self.assertNotIn("analysis_engine", first["settings"])
                    self.assertEqual(first["fixture_sha256"], workloads.runtime.fingerprint(first["case"]))
                    self.assertEqual(first["expected_work"]["findings"], 0 if profile == "clean" else 2 if workload == "security" else 1)
                    self.assertEqual(first["expected_work"]["source_files"], 1 if profile == "clean" else 9 if workload == "security" else 2)

    def test_fixture_is_reproducible_and_has_nine_real_security_tasks(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            first = workloads.fixture(Path(temporary) / "one/sec-100", "security")
            second = workloads.fixture(Path(temporary) / "two/sec-100", "security")
        self.assertEqual(first, second)
        self.assertEqual(first["expected_assigned_units"], 9)
        self.assertEqual(len(first["historical_findings"]), 1)


if __name__ == "__main__":
    unittest.main()
