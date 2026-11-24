"""Offline scorer checks; no application DB, provider or new dependencies."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import score
from prepare import canonical, digest


class ScoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.cases = score.load_corpus()

    def results(self, case_ids=("pr-01", "pr-06")):
        attempts = []
        for case_id in case_ids:
            case = self.cases[case_id]
            for arm in score.ARMS:
                attempts.append({
                    "attempt_id": f"{case_id}-{arm}-1", "case_id": case_id, "arm": arm,
                    "repetition": 1, "graph": "off", "cache": "cold", "case_digest": case["case_digest"],
                    "identity": dict.fromkeys(score.PROTOCOL["pair_identity"], "a" * 64),
                    "status": "complete", "findings": [],
                    "coverage": {"assigned_units": case["expected_assigned_units"], "validated_units": case["expected_assigned_units"]},
                    "timing_ms": {"terminal": 100, "first_validated": 75},
                    "stages": {} if case["workload"] == "pr" else {stage: {"status": "completed"} for stage in ("snapshot", "trivy", "analysis", "assessment", "verification", "report")},
                    "summary": {"status": "completed"} if case["workload"] == "pr" else None,
                    "progress": {"analysis_status": "completed", "verification": dict.fromkeys(("selected", "completed", "failed", "skipped", "uncertain", "pending", "sync_failed"), 0)},
                    "candidates": [],
                    "report": {"coverage": {"trivy": {"evaluation_snapshot": {"before": "c" * 64, "after": "c" * 64}}}},
                    "usage": dict.fromkeys(score.USAGE_FIELDS, 0), "outcomes": [],
                })
        return {
            "schema": "mortis-engine-eval-results/v1", "corpus_digest": self.manifest["corpus_digest"],
            "protocol_sha256": score.PROTOCOL_SHA256, "attempts": attempts,
            "scanner_snapshot": {"sha256": "c" * 64},
            "planned_attempts": [{field: attempt[field] for field in ("case_id", "arm", "repetition", "graph", "cache")} for attempt in attempts],
        }

    def judgment(self, results, verdict="match"):
        packet, _ = score.blind(results)
        return {
            "schema": "mortis-engine-judgments/v1", "packet_sha256": digest(canonical(packet)),
            "reviewer_id": "independent-reviewer", "reviewer_kind": "agent", "arm_blinded": True, "independent": True,
            "judgments": [{
                "blind_id": item["blind_id"], "verdict": verdict,
                "defect_id": "pr-01-d1" if verdict == "match" else None,
                "semantic": dict.fromkeys(score.SEMANTIC_FIELDS, verdict == "match"),
                "citation_bounds_valid": True, "rationale": "Inspected cause, trigger, consequence and exact source evidence.",
            } for item in packet["items"]],
        }

    def test_protocol_seal_and_outputs_are_create_only(self):
        seal = score.freeze()
        self.assertEqual(seal["protocol_sha256"], score.PROTOCOL_SHA256)
        self.assertEqual(seal["corpus_digest"], self.manifest["corpus_digest"])
        self.assertEqual(seal["scorer_sha256"], digest(Path(score.__file__).read_bytes()))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seal.json"
            score.write_new(path, seal)
            with self.assertRaises(FileExistsError):
                score.write_new(path, seal)
            self.assertEqual(json.loads(path.read_text()), seal)

    def test_default_schedule_preserves_all_unstarted_arms_and_false_negatives(self):
        results = self.results()
        del results["planned_attempts"]
        results["attempts"] = []
        report = score.score(results)
        self.assertEqual(len(report["attempt_inventory"]), 40)
        self.assertEqual(len(report["reliability_fixtures"]), 6)
        self.assertTrue(all(item["status"] == "not_started" for item in report["attempt_inventory"]))
        for workload in ("pr", "security"):
            metrics = report["quality"][f"{workload}/off/cold"]["arms"]["mortis"]
            self.assertEqual(metrics["recall"], 0)
            self.assertIsNone(metrics["precision"])
            usage = report["performance"][f"{workload}/off/cold/mortis"]["usage"]["requests"]
            self.assertGreater(usage["unknown_attempts"], 0)
        self.assertEqual(report["acceptance"], "inconclusive")
        self.assertFalse(report["speedup_claim_allowed"])

    def test_path_rule_overlap_does_not_infer_true_positive(self):
        results = self.results()
        results["attempts"][0]["findings"] = [{"finding_id": "f1", "path": "billing.py", "rule_id": "pr-01-d1", "title": "Tax error"}]
        report = score.score(results)
        metrics = report["quality"]["pr/off/cold"]["arms"]["ocr"]
        self.assertEqual((metrics["tp"], metrics["fn"], metrics["pending_findings"]), (0, 1, 1))
        self.assertIsNone(metrics["precision"])

    def test_blind_packet_has_no_arm_identity_private_metadata_or_controls(self):
        results = self.results()
        results["attempts"][0]["findings"] = [{"finding_id": "arm-secret", "title": "Tax error", "provider": "ocr", "internal_engine": "ocr", "evidence": {"sources": ["mortis", "billing.py"], "ai_analysis": {"provider": "private-provider", "request_id": "private-request", "engine": "mortis", "claim": "Tax rounds per line", "quote": "round(amount * rate)"}}}]
        packet, private = score.blind(results)
        rendered = json.dumps(packet)
        for field in ("arm-secret", "internal_engine", "provider", '"control"', "oracle_head", '"arm"', '"identity"'):
            self.assertNotIn(field, rendered)
        self.assertNotIn("private-request", rendered)
        self.assertNotIn('"mortis"', rendered)
        self.assertEqual(packet["items"][0]["finding"]["evidence"]["sources"], ["billing.py"])
        self.assertEqual(packet["items"][0]["finding"]["evidence"]["ai_analysis"]["quote"], "round(amount * rate)")
        self.assertEqual(private["packet_sha256"], digest(canonical(packet)))
        self.assertEqual(next(iter(private["mapping"].values()))["arm"], "ocr")

    def test_semantic_match_duplicate_and_severity_recall(self):
        results = self.results()
        results["attempts"][0]["findings"] = [{"finding_id": "f1", "title": "Tax error"}, {"finding_id": "f2", "title": "Duplicate tax error"}]
        judgment = self.judgment(results)
        report = score.score(results, [judgment])
        metrics = report["quality"]["pr/off/cold"]["arms"]["ocr"]
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (1, 1, 0))
        self.assertEqual(metrics["precision"], .5)
        self.assertEqual(metrics["recall"], 1)
        self.assertEqual(metrics["severity_recall"]["medium"]["recall"], 1)
        self.assertEqual(metrics["citation_bounds_valid_rate"], 1)
        self.assertEqual(metrics["semantic_supported_rate"], 1)

    def test_clean_case_false_positive_and_failure_usage_are_preserved(self):
        results = self.results()
        results["attempts"][2]["findings"] = [{"finding_id": "f1", "title": "Invented bug"}]
        results["attempts"][2]["status"] = "failed"
        results["attempts"][2]["outcomes"] = ["timeout_after_consumption"]
        results["attempts"][2]["usage"].update(requests=2, input_tokens=None)
        report = score.score(results, [self.judgment(results, "false_positive")])
        self.assertEqual(report["quality"]["pr/off/cold"]["arms"]["ocr"]["clean_case_fp_incidence"], 1)
        perf = report["performance"]["pr/off/cold/ocr"]
        self.assertEqual(perf["usage"]["requests"]["observed_sum"], 2)
        self.assertEqual(perf["usage"]["input_tokens"]["unknown_attempts"], 1)
        self.assertEqual(perf["statuses"]["failed"], 1)
        self.assertEqual(perf["timing_ms_all_statuses"]["terminal"]["observed_attempts"], 2)
        self.assertEqual(perf["failed_or_incomplete_durations"][0]["timing_ms"]["terminal"], 100)

    def test_semantic_support_and_blinding_are_mandatory(self):
        results = self.results()
        results["attempts"][0]["findings"] = [{"finding_id": "f1", "title": "Tax error"}]
        judgment = self.judgment(results)
        for change in ("cause", "citation", "blinding", "different_truth", "stale_packet"):
            changed = copy.deepcopy(judgment)
            if change == "cause":
                changed["judgments"][0]["semantic"]["cause"] = False
            elif change == "citation":
                changed["judgments"][0]["citation_bounds_valid"] = False
            elif change == "blinding":
                changed["arm_blinded"] = False
            elif change == "different_truth":
                changed["judgments"][0]["defect_id"] = "pr-02-d1"
            else:
                changed["packet_sha256"] = "0" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                score.score(results, [changed])

    def test_mismatched_pair_cannot_claim_speed_and_bad_schedules_are_rejected(self):
        results = self.results()
        results["attempts"][1]["identity"]["scope_sha256"] = "b" * 64
        report = score.score(results)
        self.assertEqual(report["pair_identity_mismatches"][0]["fields"], ["scope_sha256"])
        self.assertFalse(report["speedup_claim_allowed"])
        self.assertIn("pair_identity_mismatch", report["paired_performance"]["pr/off/cold"]["claim_blockers"])
        for change in ("duplicate", "unpaired", "source_drift", "overcount", "negative_usage"):
            changed = self.results()
            if change == "duplicate":
                changed["attempts"].append(copy.deepcopy(changed["attempts"][0]))
            elif change == "unpaired":
                changed["planned_attempts"].pop()
            elif change == "source_drift":
                changed["attempts"][0]["case_digest"] = "0" * 64
            elif change == "overcount":
                changed["attempts"][0]["coverage"]["validated_units"] += 1
            else:
                changed["attempts"][0]["usage"]["requests"] = -1
            with self.subTest(change=change), self.assertRaises(ValueError):
                score.score(changed)

    def test_bootstrap_is_reproducible_and_degenerate_samples_are_inconclusive(self):
        results = self.results()
        first = score.score(results)["quality"]["pr/off/cold"]["paired_family_bootstrap"]
        second = score.score(results)["quality"]["pr/off/cold"]["paired_family_bootstrap"]
        self.assertEqual(first, second)
        self.assertEqual(first["recall"]["one_sided_95_lower"], 0)
        self.assertIn("tiny_family_sample", first["recall"]["reasons"])
        self.assertIn("degenerate_bootstrap", first["recall"]["reasons"])
        self.assertEqual(first["recall"]["status"], "inconclusive")

    def test_nearest_rank_and_undefined_denominators(self):
        self.assertEqual(score.nearest_rank(list(range(1, 21)), .95), 19)
        self.assertEqual(score.nearest_rank([100, 200], .5), 100)
        self.assertIsNone(score.nearest_rank([], .95))
        self.assertIsNone(score.ratio(0, 0))

    def test_latency_ratio_keeps_repetitions_clustered_and_unknown_usage_blocks_claims(self):
        results = self.results()
        results["attempts"][1]["timing_ms"]["terminal"] = 50
        results["attempts"][3]["timing_ms"]["terminal"] = 50
        results["attempts"][1]["usage"]["input_tokens"] = None
        perf = score.score(results)["paired_performance"]["pr/off/cold"]
        self.assertEqual(perf["terminal_latency_ratios"]["p50"]["mortis_over_ocr"], .5)
        self.assertEqual(perf["terminal_latency_ratios"]["p95"]["status"], "inconclusive")
        self.assertIn("unknown_consumption", perf["claim_blockers"])
        self.assertFalse(perf["speedup_claim_allowed"])

    def test_completed_analysis_with_failed_summary_or_assessment_is_not_required_work_completion(self):
        baseline = self.results(("pr-01",))
        self.assertEqual(score.score(baseline)["paired_performance"]["pr/off/cold"]["eligible_completed_pairs"], 1)
        for change in ("failed_summary", "missing_summary", "failed_candidate", "missing_candidates", "pending_stage", "missing_verification", "uncertain_verification"):
            results = copy.deepcopy(baseline)
            attempt = results["attempts"][1]
            if change == "failed_summary":
                attempt["summary"]["status"] = "failed"
            elif change == "missing_summary":
                del attempt["summary"]
            elif change == "failed_candidate":
                attempt["candidates"] = [{"status": "failed"}]
            elif change == "missing_candidates":
                del attempt["candidates"]
            elif change == "pending_stage":
                attempt["stages"] = {"assessment": {"status": "pending"}}
            elif change == "missing_verification":
                del attempt["progress"]["verification"]
            else:
                attempt["progress"]["verification"].update(selected=1, completed=1, uncertain=1)
            with self.subTest(change=change):
                report = score.score(results)
                perf = report["paired_performance"]["pr/off/cold"]
                self.assertEqual(perf["eligible_completed_pairs"], 0)
                self.assertIn("incomplete_required_workflow", perf["claim_blockers"])
                self.assertIsNone(perf["terminal_latency_ratios"]["p50"]["mortis_over_ocr"])
                self.assertTrue(report["required_work_gaps"])

    def test_missing_or_partial_security_stage_cannot_count_as_complete_latency(self):
        baseline = self.results(("sec-01",))
        self.assertEqual(score.score(baseline)["paired_performance"]["security/off/cold"]["eligible_completed_pairs"], 1)
        for stage in ("snapshot", "trivy", "analysis", "assessment", "verification", "report"):
            results = copy.deepcopy(baseline)
            del results["attempts"][1]["stages"][stage]
            with self.subTest(stage=stage):
                report = score.score(results)
                self.assertEqual(report["paired_performance"]["security/off/cold"]["eligible_completed_pairs"], 0)
                self.assertIn("stage_" + stage + "_not_completed_or_missing", report["required_work_gaps"][0]["gaps"])

    def test_malformed_security_snapshot_evidence_is_incomplete_not_a_scoring_crash(self):
        for path in ((), ("coverage",), ("coverage", "trivy"), ("coverage", "trivy", "evaluation_snapshot")):
            for malformed in (None, [], ["invalid"], "invalid", 1, True):
                with self.subTest(path=path, malformed=malformed):
                    results = self.results(("sec-01",))
                    parent, key = results["attempts"][1], "report"
                    for child in path:
                        parent, key = parent[key], child
                    parent[key] = malformed
                    report = score.score(results)
                    self.assertEqual(report["paired_performance"]["security/off/cold"]["eligible_completed_pairs"], 0)
                    self.assertIn("scanner_snapshot_evidence_missing_or_changed", report["required_work_gaps"][0]["gaps"])

    def test_explicit_database_verification_selection_proves_zero_targets(self):
        results = self.results(("pr-01",))
        for attempt in results["attempts"]:
            del attempt["progress"]["verification"]
            attempt["verification_selection"] = {"observed": True, "selected": 0, "source": "FindingVerification.run_id"}
            attempt["verification_targets"] = []
        self.assertEqual(score.score(results)["paired_performance"]["pr/off/cold"]["eligible_completed_pairs"], 1)
        results["attempts"][1]["verification_selection"]["selected"] = 1
        self.assertEqual(score.score(results)["paired_performance"]["pr/off/cold"]["eligible_completed_pairs"], 0)
        results["attempts"][1]["verification_targets"] = [{"status": "completed", "verdict": "uncertain"}]
        self.assertEqual(score.score(results)["paired_performance"]["pr/off/cold"]["eligible_completed_pairs"], 0)

    def test_security_latency_requires_observed_unchanged_frozen_scanner_snapshot(self):
        baseline = self.results(("sec-01",))
        for change in ("missing_frozen", "missing_observed", "changed_before", "changed_after"):
            results = copy.deepcopy(baseline)
            if change == "missing_frozen":
                del results["scanner_snapshot"]
            elif change == "missing_observed":
                del results["attempts"][1]["report"]
            else:
                results["attempts"][1]["report"]["coverage"]["trivy"]["evaluation_snapshot"]["before" if change == "changed_before" else "after"] = "d" * 64
            with self.subTest(change=change):
                perf = score.score(results)["paired_performance"]["security/off/cold"]
                self.assertEqual(perf["eligible_completed_pairs"], 0)
                self.assertIn("incomplete_required_workflow", perf["claim_blockers"])


if __name__ == "__main__":
    unittest.main()
