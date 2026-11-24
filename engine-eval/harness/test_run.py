"""Docker command and orchestration checks without Docker or provider requests."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class RunTests(unittest.TestCase):
    def inputs(self, root):
        cases = root / "cases"
        cases.mkdir()
        records = []
        for case_id in [f"pr-{i:02}" for i in range(1, 13)] + [f"sec-{i:02}" for i in range(1, 9)]:
            folder = cases / case_id
            folder.mkdir()
            (folder / "repo").mkdir()
            (folder / "context.json").write_text("{}")
            (folder / "change.diff").write_text("")
            records.append({"case_id": case_id, "workload": "pr" if case_id.startswith("pr-") else "security", "evaluation_track": "reliability_fixture" if case_id in {"pr-12", "sec-07", "sec-08"} else "quality_microcase", "case_digest": "a" * 64, "identity": {"scope_sha256": "b" * 64}, "expected_assigned_units": 1})
        credentials = root / "credentials.json"
        credentials.write_text('{"api_key":"dummy-not-real","extra_headers":{}}')
        credentials.chmod(0o600)
        manifest = {"schema": "mortis-engine-live-run/v1", "run_id": "test-only", "source_revision": "a" * 40, "corpus_digest": "a" * 64, "protocol_sha256": "b" * 64, "effective_resources_sha256": "c" * 64, "publication": "disabled_sandbox_adapter_only", "graph": "off", "cache": "cold", "repetition": 1, "cases": records}
        (root / "scanner-cache").mkdir()
        manifest["scanner_snapshot"] = {"schema": "synthetic_test_only", "sha256": "c" * 64}
        return manifest, cases, credentials

    def test_schedule_is_paired_deterministic_and_retains_all_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, _, _ = self.inputs(Path(tmp))
            first = run.schedule(manifest)
            self.assertEqual(first, run.schedule(manifest))
            self.assertEqual(len(first), 40)
            for index in range(0, 40, 2):
                self.assertEqual(first[index]["case_id"], first[index + 1]["case_id"])
                self.assertEqual({first[index]["arm"], first[index + 1]["arm"]}, {"ocr", "mortis"})

    def test_schedule_retains_versioned_graph_cache_and_repetition(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, _, _ = self.inputs(Path(tmp))
            manifest.update(schema="mortis-engine-workflow-run/v2", graph="exact_revision_gap", cache="warm", repetition=3)
            planned = run.schedule(manifest)
            self.assertTrue(all(row["graph"] == "exact_revision_gap" and row["cache"] == "warm"
                                and row["repetition"] == 3 for row in planned))

    def test_inputs_refuse_secrets_truth_symlinks_mutable_images_and_implicit_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, cases, credentials = self.inputs(Path(tmp))
            image = "sha256:" + "d" * 64
            run.validate_inputs(manifest, cases, credentials, image, live=False)
            for changed, selected_image, live in (({**manifest, "truth": {}}, image, False), (manifest, "app:latest", False), (manifest, image, True)):
                with self.assertRaises(ValueError):
                    run.validate_inputs(changed, cases, credentials, selected_image, live=live)
            credentials.chmod(0o644)
            with self.assertRaises(ValueError):
                run.validate_inputs(manifest, cases, credentials, image, live=False)
            credentials.chmod(0o600)
            (cases / "pr-01" / "repo" / "outside").symlink_to(credentials)
            with self.assertRaises(ValueError):
                run.validate_inputs(manifest, cases, credentials, image, live=False)

    def test_parallel_cohort_is_versioned_and_history_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, cases, credentials = self.inputs(Path(tmp))
            image = "sha256:" + "d" * 64
            manifest.update(execution_profile="parallel_queue_v2",
                            queue={"pool": "prefork", "concurrency": 4, "dispatch_interval_seconds": 10})
            with self.assertRaisesRegex(ValueError, "Original pilot"):
                run.validate_inputs(manifest, cases, credentials, image, live=False)
            manifest["schema"] = "mortis-engine-workflow-run/v2"
            manifest["cases"] = [manifest["cases"][0]]
            manifest["cases"][0]["identity"]["history_sha256"] = run.fingerprint([])
            for folder in cases.iterdir():
                if folder.name != "pr-01":
                    shutil.rmtree(folder)
            run.validate_inputs(manifest, cases, credentials, image, live=False)
            manifest["cases"][0]["historical_findings"] = [{"original_sha": "changed"}]
            with self.assertRaisesRegex(ValueError, "history differs"):
                run.validate_inputs(manifest, cases, credentials, image, live=False)

    def test_worker_commands_enforce_isolation_resources_and_secret_separation(self):
        kwargs = {"name": "owned-worker", "network": "owned-network", "image": "sha256:" + "d" * 64, "environment": {"CM_DATABASE_URL": "postgresql://disposable/mortis_eval"}, "manifest_path": Path("/input.json"), "cases": Path("/exports"), "credentials": Path("/private/provider.json"), "workload": "security", "live": False, "case": "sec-01", "arm": "ocr"}
        dry = run.worker_command(**kwargs)
        self.assertIn("--dry-run", dry)
        self.assertNotIn("/private/provider.json", " ".join(dry))
        self.assertIn("--read-only", dry)
        self.assertIn("no-new-privileges:true", dry)
        self.assertIn("ALL", dry)
        self.assertEqual(dry[dry.index("--memory") + 1], str(1024 * run.MIB))
        self.assertEqual(dry[dry.index("--memory-swap") + 1], str(1024 * run.MIB))
        self.assertEqual(dry[dry.index("--pids-limit") + 1], "128")

        self.assertTrue(all(arg.endswith(",readonly") for arg in dry if arg.startswith("type=bind")))
        self.assertFalse(any(arg in {"--privileged", "-v", "--publish", "-p"} for arg in dry))
        live = run.worker_command(**{**kwargs, "live": True})
        self.assertNotIn("--dry-run", live)
        self.assertIn("src=/private/provider.json", " ".join(live))
        migration = run.worker_command(**{**kwargs, "migration": True})
        self.assertNotIn("--mount", migration)
        self.assertEqual(migration[-3:], ["alembic", "upgrade", "head"])
        cached = run.worker_command(**{**kwargs, "scanner_cache": Path("/advisories")})
        self.assertIn("type=bind,src=/advisories,dst=/scanner-cache,readonly", cached)
        self.assertIn("CM_TRIVY_CACHE_DIR=/scanner-cache", cached)
        pr = run.worker_command(**{**kwargs, "scanner_cache": Path("/advisories"), "workload": "pr"})
        self.assertNotIn("CM_TRIVY_CACHE_DIR=/scanner-cache", pr)

    def test_live_quality_track_cannot_claim_quiet_performance_or_change_original_pilot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, cases, credentials = self.inputs(root)
            image = "sha256:" + "d" * 64
            manifest.update(measurement_track="live_quality", performance_claim_allowed=False)
            with self.assertRaisesRegex(ValueError, "Only versioned live-quality"):
                run.validate_inputs(manifest, cases, credentials, image, live=False)
            manifest.update(schema="mortis-engine-workflow-run/v2", execution_profile="parallel_queue_v2",
                            queue={"pool": "prefork", "concurrency": 4, "dispatch_interval_seconds": 10})
            manifest["cases"] = [manifest["cases"][0]]
            manifest["cases"][0]["identity"]["history_sha256"] = run.fingerprint([])
            for folder in cases.iterdir():
                if folder.name != "pr-01":
                    shutil.rmtree(folder)
            manifest.update(live_enabled=True, authorization="owner_selected_pilot", isolation_checks_passed=True,
                            worker_image_id=image, host_quiescence={"verified": False, "reason": "Quality only",
                                "observed_at": "2026-11-08T00:00:00+00:00", "active_container_ids": ["synthetic"]})
            with patch.object(run, "check_scanner_cache", return_value=manifest["scanner_snapshot"]):
                run.validate_inputs(manifest, cases, credentials, image, live=True, scanner_cache=root / "scanner-cache")
                manifest["performance_claim_allowed"] = True
                with self.assertRaisesRegex(ValueError, "timings cannot support performance"):
                    run.validate_inputs(manifest, cases, credentials, image, live=True, scanner_cache=root / "scanner-cache")

    def test_scanner_snapshot_identity_and_disk_bound_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, _, _ = self.inputs(root)
            cache = root / "scanner-cache"
            with patch.object(run, "snapshot_identity", return_value=manifest["scanner_snapshot"]):
                self.assertEqual(run.check_scanner_cache(manifest, cache), manifest["scanner_snapshot"])
            with patch.object(run, "snapshot_identity", return_value={"sha256": "changed"}), self.assertRaises(ValueError):
                run.check_scanner_cache(manifest, cache)
            with patch.object(run, "tree_bytes", return_value=run.CACHE_LIMIT + 1), self.assertRaises(ValueError):
                run.check_scanner_cache(manifest, cache)

    def test_effective_constraints_are_checked_before_dispatch(self):
        limits = run.LIMITS["pr"]
        inspection = {"Image": "sha256:" + "d" * 64, "Config": {"User": f"{os.getuid()}:{os.getgid()}"}, "Mounts": [{"Type": "bind", "Destination": "/cases", "RW": False}], "HostConfig": {"NanoCpus": 4_000_000_000, "Memory": limits["memory"], "MemorySwap": limits["memory"], "PidsLimit": 256, "ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Privileged": False, "PortBindings": {}, "Tmpfs": {"/tmp": f"size={512 * run.MIB}", "/home/mortis/.opencodereview": f"size={64 * run.MIB}"}}}
        with patch.object(run, "command", return_value=json.dumps([inspection])):
            self.assertEqual(run.inspect_constraints("owned", "pr", worker=True)["limits"], limits)
        for field, value in (("MemorySwap", -1), ("ReadonlyRootfs", False), ("PortBindings", {"5432/tcp": [{}]})):
            changed = copy.deepcopy(inspection)
            changed["HostConfig"][field] = value
            with patch.object(run, "command", return_value=json.dumps([changed])), self.assertRaises(ValueError):
                run.inspect_constraints("owned", "pr", worker=True)

    def test_capture_drains_both_streams_and_caps_output(self):
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(run.subprocess, "Popen", side_effect=lambda *args, **kwargs: real_popen([sys.executable, "-c", "import sys;sys.stdout.write('ok');sys.stderr.write('log')"], **kwargs)):
                code, elapsed = run.bounded_capture(["unused"], root / "out", root / "err", timeout=5)
            self.assertEqual(code, 0)
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual((root / "out").read_text(), "ok")
            self.assertEqual((root / "err").read_text(), "log")
            with patch.object(run, "MAX_RESULT", 128), patch.object(run.subprocess, "Popen", side_effect=lambda *args, **kwargs: real_popen([sys.executable, "-c", "print('x'*4096)"], **kwargs)), self.assertRaises(ValueError):
                run.bounded_capture(["unused"], root / "bounded-out", root / "bounded-err", timeout=5)
            self.assertLessEqual((root / "bounded-out").stat().st_size, 128)

    def test_unknown_auth_quota_or_unobserved_consumption_stops_without_retry(self):
        self.assertFalse(run.must_stop({"usage": {"tokens": 10}, "provider_events": []}))
        self.assertFalse(run.must_stop({"status": "validated_offline"}))
        for result in ({"stop_pilot": True}, {"usage": {"tokens": None}}, {"usage": {"tokens": 0}, "provider_events": [{"error_code": "authentication"}]}, {"usage": {"tokens": 0}, "provider_events": [{"error_code": "quota"}]}):
            self.assertTrue(run.must_stop(result))

    def test_quiescence_rejects_external_running_containers_without_stopping_them(self):
        with patch.object(run, "command", return_value="owned\n") as docker:
            run.verify_quiescence(["owned"])
            self.assertEqual(docker.call_args.args[0], ["ps", "--filter", "status=running", "--format", "{{.Names}}"])
        with patch.object(run, "command", return_value="external\n"), self.assertRaises(ValueError):
            run.verify_quiescence(["owned"])

    def test_unknown_live_result_stops_remaining_paid_arms_and_retains_all_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, cases, credentials = self.inputs(root)
            image = "sha256:" + "d" * 64
            manifest.update(live_enabled=True, authorization="owner_selected_pilot", isolation_checks_passed=True, worker_image_id=image, host_quiescence={"verified": True, "verified_at": "2026-11-07T00:00:00+00:00"})
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            created, worker_calls = {}, []
            def docker(args, **kwargs):
                if args[:2] == ["image", "inspect"]:
                    return json.dumps([{"Id": args[2]}])
                if args[0] == "create":
                    created[args[args.index("--name") + 1]] = args
                if args[0] == "inspect":
                    return json.dumps([{"State": {"Running": False, "OOMKilled": False, "ExitCode": 0}}])
                return ""
            def capture(args, out, err, **kwargs):
                selected = created[args[-1]]
                err.write_text("")
                if selected[-3:] == ["alembic", "upgrade", "head"]:
                    out.write_text("migration complete")
                else:
                    worker_calls.append(selected)
                    case_id = Path(selected[selected.index("--case") + 1]).name
                    arm = selected[selected.index("--arm") + 1]
                    item = next(row for row in run.schedule(manifest) if row["case_id"] == case_id and row["arm"] == arm)
                    case = next(row for row in manifest["cases"] if row["case_id"] == case_id)
                    result = run.placeholder(item, case, "unknown_consumption", "failed")
                    result.update(stop_pilot=True, usage={"tokens": None})
                    out.write_text(json.dumps(result))
                return 0, 10
            with patch.object(run, "command", side_effect=docker), patch.object(run, "inspect_constraints", return_value={}), patch.object(run, "wait_ready"), patch.object(run, "bounded_capture", side_effect=capture), patch.object(run, "recover_ledger", return_value={"exported": True, "truncated": False}), patch.object(run, "snapshot_identity", return_value=manifest["scanner_snapshot"]), patch.object(run.shutil, "disk_usage", return_value=type("Disk", (), {"free": 20 * 1024 * run.MIB})()):
                path = run.run(manifest_path, cases, credentials, image, root / "output", live=True, scanner_cache=root / "scanner-cache")
            results = json.loads(path.read_text())
            self.assertEqual(len(worker_calls), 1)
            self.assertEqual(len(results["attempts"]), 40)
            self.assertEqual(sum(item["status"] == "unsupported_fixture" for item in results["attempts"]), 6)
            self.assertEqual(sum(item["status"] == "not_started" for item in results["attempts"]), 33)
            self.assertEqual(results["stopped_reason"], "stopped_after_auth_quota_or_unknown_consumption")

    def test_recovered_started_events_and_reservations_remain_unknown(self):
        document = {
            "schema": "mortis-engine-recovered-ledger/v1",
            "jobs": [{"provider_event_count": 2, "provider_events": [
                {"state": "finished", "forwarded": True, "consumption_unknown": False, "total_tokens": 10},
                {"state": "started", "forwarded": True, "consumption_unknown": True, "total_tokens": None},
            ]}],
            "analysis_plans": [], "analysis_tasks": [], "analysis_budgets": [],
            "analysis_attempts": [
                {"usage_state": "known", "usage_tokens": 7, "reserved_tokens": 20},
                {"usage_state": "reserved", "usage_tokens": None, "reserved_tokens": 200},
            ],
            "row_counts": {"jobs": 1, "analysis_plans": 0, "analysis_tasks": 0, "analysis_attempts": 2, "analysis_budgets": 0},
        }
        summary = run.recovery_summary(document)
        self.assertEqual(summary["provider_known_token_subtotal"], 10)
        self.assertEqual(summary["provider_unknown_events"], 1)
        self.assertEqual(summary["ledger_known_token_subtotal"], 7)
        self.assertEqual(summary["ledger_unknown_reserved_tokens"], 200)
        self.assertFalse(summary["consumption_complete"])
        self.assertFalse(summary["truncated"])
        document["jobs"][0]["provider_event_count"] = 300
        self.assertTrue(run.recovery_summary(document)["truncated"])

    def test_recovery_query_projects_allowlisted_fields_in_read_only_transaction(self):
        sql = run.recovery_query()
        self.assertTrue(sql.startswith("BEGIN READ ONLY; SET LOCAL statement_timeout='5s';"))
        for field in ("provider_events", "usage_tokens", "reserved_tokens", "charged_tokens", "jsonb_typeof", "LIMIT 256", "row_counts"):
            self.assertIn(field, sql)
        for field in ("snapshot", "SELECT *", "api_key", "extra_headers", "request_id", "returned_model", "scope", "dependencies", "result", "client_secret", "private_key", "pg_dump"):
            self.assertNotIn(field, sql)

    def test_export_failure_keeps_only_database_network_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, cases, credentials = self.inputs(root)
            image = "sha256:" + "d" * 64
            manifest.update(live_enabled=True, authorization="owner_selected_pilot", isolation_checks_passed=True, worker_image_id=image, host_quiescence={"verified": True, "verified_at": "2026-11-07T00:00:00+00:00"})
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            seen = []
            def docker(args, **kwargs):
                seen.append(args)
                if args[:2] == ["image", "inspect"]:
                    return json.dumps([{"Id": args[2]}])
                if args[0] == "inspect":
                    return json.dumps([{"State": {"Running": False, "OOMKilled": True, "ExitCode": 137}}])
                return ""
            def capture(args, out, err, **kwargs):
                out.write_text("")
                err.write_text("")
                return (0 if "migrate" in args[-1] else 137), 10
            with patch.object(run, "command", side_effect=docker), patch.object(run, "inspect_constraints", return_value={}), patch.object(run, "wait_ready"), patch.object(run, "bounded_capture", side_effect=capture), patch.object(run, "recover_ledger", side_effect=OSError("unavailable")), patch.object(run, "snapshot_identity", return_value=manifest["scanner_snapshot"]), patch.object(run.shutil, "disk_usage", return_value=type("Disk", (), {"free": 20 * 1024 * run.MIB})()), self.assertRaisesRegex(RuntimeError, "preserved disposable database"):
                run.run(manifest_path, cases, credentials, image, root / "output", live=True, scanner_cache=root / "scanner-cache")
            result = json.loads((root / "output" / "results.json").read_text())
            recovery = result["recovered_ledger"]
            self.assertFalse(recovery["exported"])
            self.assertFalse(recovery["consumption_complete"])
            self.assertTrue(recovery["database_container_preserved"].endswith("-pg"))
            removed = [args[-1] for args in seen if args[:2] == ["rm", "-f"]]
            self.assertNotIn(recovery["database_container_preserved"], removed)
            self.assertTrue(any(name.endswith("-redis") for name in removed))
            self.assertTrue(any("-arm-" in name for name in removed))
            self.assertFalse(any(args[:2] == ["network", "rm"] for args in seen))
            self.assertEqual(len(result["attempts"]), 40)

    def test_orchestration_failure_retains_schedule_and_cleans_only_created_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, cases, credentials = self.inputs(root)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            seen = []
            def docker(args, **kwargs):
                seen.append(args)
                if args[:2] == ["image", "inspect"]:
                    return json.dumps([{"Id": args[2]}])
                if args[:2] == ["network", "create"]:
                    return "created"
                if args[0] == "create":
                    return "created-container"
                return ""
            with patch.object(run, "command", side_effect=docker), patch.object(run, "inspect_constraints", side_effect=ValueError("resource mismatch")), patch.object(run.shutil, "disk_usage", return_value=type("Disk", (), {"free": 20 * 1024 * run.MIB})()), self.assertRaises(ValueError):
                run.run(manifest_path, cases, credentials, "sha256:" + "d" * 64, root / "output")
            result = json.loads((root / "output" / "results.json").read_text())
            self.assertEqual(len(result["planned_attempts"]), 40)
            self.assertEqual(len(result["attempts"]), 40)
            self.assertEqual(result["stopped_reason"], "orchestration_error_ValueError")
            self.assertTrue(any(args[:3] == ["network", "create", "--internal"] for args in seen))
            removed = [args for args in seen if args[:2] in (["rm", "-f"], ["network", "rm"])]
            self.assertEqual(len(removed), 2)
            self.assertTrue(all(args[-1].startswith("mortis-eval-") for args in removed))


if __name__ == "__main__":
    unittest.main()
