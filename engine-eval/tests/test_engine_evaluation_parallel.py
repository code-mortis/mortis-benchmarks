"""Actual isolated Redis/prefork deliveries with synthetic HTTP inference, not live quality evidence."""

import copy
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from redis import Redis
from sqlalchemy import create_engine, select, text
from test_engine_evaluation import HARNESS, ROOT, evaluation, prepare, runtime  # noqa: F401
from test_llm_http import result as wire_result

from code_mortis.core.config import settings
from code_mortis.core.db import engine, now, transaction
from code_mortis.models import Finding, Job, Occurrence, ReviewRun, SecurityScan
from code_mortis.reviews import pipeline
from code_mortis.reviews.context import source_id
from code_mortis.schemas.common import RepoSettings, ReviewComment


def parallel(manifest):
    manifest["schema"] = runtime.WORKFLOW_SCHEMA
    manifest["execution_profile"] = runtime.PARALLEL_PROFILE
    manifest["queue"] = copy.deepcopy(runtime.QUEUE_PROFILE)
    manifest["conditions"] = {"execution_profile": runtime.PARALLEL_PROFILE, "queue": manifest["queue"]}
    manifest["case_deadline_seconds"] = 90


def retain(name, result):
    if destination := os.environ.get("CM_PIPELINE_EVIDENCE_DIR"):
        with (Path(destination) / (name + ".json")).open("x") as output:
            json.dump({"evidence_kind": "controlled_synthetic_workflow_integration",
                       "provider_fixture": {"delay_seconds": 1 if name == "pr-history" else 0,
                                            "synchronization": "first_two_stage_requests_barrier" if name == "pr-history" else
                                            "first_four_requests_barrier" if name == "security-nine-tasks" else "none"},
                       "result": result}, output,
                      indent=2, default=lambda value: value.isoformat())


@pytest.mark.parametrize("changes", [
    {"execution_profile": "unknown"},
    {"queue": runtime.QUEUE_PROFILE},
    {"execution_profile": runtime.PARALLEL_PROFILE, "queue": {**runtime.QUEUE_PROFILE, "concurrency": 8}},
    {"execution_profile": runtime.PARALLEL_PROFILE, "queue": {**runtime.QUEUE_PROFILE, "dispatch_interval_seconds": 0.1}},
])
def test_profile_rejects_unfrozen_execution_conditions(evaluation, changes):  # noqa: F811
    manifest, case, _ = evaluation
    manifest.update(changes)
    with pytest.raises(ValueError):
        runtime.validate_manifest(manifest, case["case_id"], "mortis", live=False)


def test_workflow_manifest_pins_history_and_full_execution_conditions(evaluation):  # noqa: F811
    manifest, case, _ = evaluation
    parallel(manifest)
    effective = {"extra_body": {"reasoning.effort": "medium"}}
    case["identity"]["model_options_sha256"] = runtime.fingerprint(effective)
    case["identity"]["history_sha256"] = runtime.fingerprint([])
    case["identity"]["conditions_sha256"] = runtime.fingerprint({
        **manifest["conditions"], "workload": case["workload"], "provider_options": effective,
    })
    assert runtime.validate_manifest(manifest, case["case_id"], "mortis", live=False) == case
    case["identity"]["history_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="Historical input identity"):
        runtime.validate_manifest(manifest, case["case_id"], "mortis", live=False)


@pytest.mark.parametrize("graph,cache,repetition", [("on", "warm", 2), ("exact_revision_gap", "cold", 3)])
def test_workflow_strata_are_bound_to_conditions(evaluation, graph, cache, repetition):  # noqa: F811
    manifest, case, _ = evaluation
    parallel(manifest)
    manifest.update(graph=graph, cache=cache, repetition=repetition)
    case["identity"]["model_options_sha256"] = runtime.fingerprint({"extra_body": {"reasoning.effort": "medium"}})
    case["identity"]["history_sha256"] = runtime.fingerprint([])
    with pytest.raises(ValueError, match="conditions differ"):
        runtime.validate_manifest(manifest, case["case_id"], "ocr", live=False)
    manifest["conditions"].update(graph=graph, cache=cache, repetition=repetition)
    case["identity"]["conditions_sha256"] = runtime.fingerprint({
        **manifest["conditions"], "workload": "pr", "provider_options": runtime.provider_options(manifest, case),
    })
    assert runtime.validate_manifest(manifest, case["case_id"], "ocr", live=False) == case


@pytest.mark.parametrize("workload", ["pr", "security"])
def test_parallel_profile_seeds_queued_production_job(evaluation, workload):  # noqa: F811
    manifest, case, _ = evaluation
    parallel(manifest)
    case["workload"] = workload
    runtime.create_attempt(manifest, case, "mortis", {"api_key": "synthetic", "extra_headers": {}},
                           RepoSettings(analysis_engine="mortis").model_dump(), "queued-attempt")
    with transaction() as db:
        job = db.get(Job, "queued-attempt")
        assert (job.status, job.attempts, job.lease_until) == ("queued", 0, None)
        row = db.get(ReviewRun if workload == "pr" else SecurityScan, "queued-attempt")
        assert row.status == "queued"
        if workload == "pr":
            assert pipeline.enabled(row)
            assert set(row.stages) == set(pipeline.STAGES)
            assert all(stage["status"] == "pending" for stage in row.stages.values())


@pytest.fixture
def queued_database(monkeypatch, tmp_path):
    """Own a fresh eval DB on the isolated test server; never reset a pre-existing DB."""
    from code_mortis import jobs

    original = engine().url
    assert original.host in {"127.0.0.1", "host.docker.internal"} and original.port == 55439 and original.database == "mortis_test"
    evaluation_url = original.set(database="mortis_eval").render_as_string(hide_password=False)
    admin = create_engine(original.set(database="postgres"), isolation_level="AUTOCOMMIT")
    broker = Redis.from_url("redis://127.0.0.1:56389/13")
    assert broker.dbsize() == 0, "Refuse a nonempty test-only broker database"
    created = False
    try:
        with admin.connect() as connection:
            assert not connection.scalar(text("SELECT 1 FROM pg_database WHERE datname = 'mortis_eval'"))
            connection.execute(text('CREATE DATABASE "mortis_eval"'))
            created = True
        engine().dispose()
        engine.cache_clear()
        with monkeypatch.context() as patcher:
            for name, value in {"database_url": evaluation_url, "redis_url": "redis://127.0.0.1:56389/13",
                                "work_dir": tmp_path / "queued-work", "allow_private_endpoints": True,
                                "trusted_endpoint_hosts": "127.0.0.1"}.items():
                patcher.setattr(settings(), name, value)
            for name, value in {
                "CM_DATABASE_URL": evaluation_url, "CM_REDIS_URL": "redis://127.0.0.1:56389/13",
                "CM_EVAL_DISPOSABLE_DATABASE": "true", "CM_WORK_DIR": str(tmp_path / "queued-work"),
                "CM_ALLOW_PRIVATE_ENDPOINTS": "true", "CM_TRUSTED_ENDPOINT_HOSTS": "127.0.0.1",
                "PYTHONPATH": str(ROOT / "backend"),
            }.items():
                patcher.setenv(name, value)
            for name in ("GITHUB_TOKEN", "GH_TOKEN", "CM_GITHUB_TOKEN"):
                patcher.delenv(name, raising=False)
            command.upgrade(Config("alembic.ini"), "head")
            # Jobs may have been imported before this fixture changed the broker settings.
            dispatch = jobs.execute_job.apply_async
            with jobs.celery.connection_for_write(url=settings().redis_url) as connection:
                patcher.setattr(jobs.execute_job, "apply_async", lambda **kwargs: dispatch(connection=connection, **kwargs))
                launcher = tmp_path / "queue_worker.py"
                launcher.write_text(
                    "import json,sys\nfrom pathlib import Path\n"
                    f"sys.path.insert(0, {str(HARNESS)!r})\n"
                    "import runtime\nruntime.queue_worker(json.loads(Path(sys.argv[2]).read_text()))\n"
                )
                popen = runtime.subprocess.Popen

                def worker_command(arguments, *args, **kwargs):
                    if len(arguments) > 2 and arguments[1:3] == [str(Path(runtime.__file__).resolve()), "--queue-worker"]:
                        arguments = [arguments[0], str(launcher), *arguments[2:]]
                    return popen(arguments, *args, **kwargs)

                patcher.setattr(runtime.subprocess, "Popen", worker_command)
                yield
            engine().dispose()
            engine.cache_clear()
    finally:
        engine.cache_clear()
        if created:
            with admin.connect() as connection:
                connection.execute(text('DROP DATABASE "mortis_eval" WITH (FORCE)'))
        admin.dispose()
        keys = list(broker.scan_iter())
        if keys:
            broker.delete(*keys)
        broker.close()


@pytest.mark.parametrize("history", [False, True])
@pytest.mark.skipif(sys.platform != "linux", reason="The production prefork worker requires Linux fork semantics")
def test_real_prefork_queue_completes_all_stages_and_preserves_history(
    evaluation, queued_database, monkeypatch, history,  # noqa: F811
):
    manifest, case, exported = evaluation
    parallel(manifest)
    options = RepoSettings(analysis_engine="mortis", token_budget=200_000,
                           assessment_token_budget=200_000, verification_token_budget=200_000,
                           summary_token_budget=60_000, timeout_seconds=90, auto_resolve=history).model_dump()
    manifest["settings"] = options
    if history:
        case["historical_findings"] = [{"original_sha": case["base"]["commit"], "snapshot": ReviewComment(
            path="billing.py", content="Synthetic prior report requiring explicit rechecking.",
            start_line=14, end_line=14, existing_code='    taxable = sum(amounts, Decimal("0"))',
        ).model_dump()}]
    phases, requests = [], []
    overlap = threading.Barrier(2, timeout=25) if history else None

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            schema = body["text"]["format"]["schema"]["properties"]
            content = next(item["content"] for item in body["input"] if item.get("role") == "user")
            if "completed_units" in schema:
                supplied = json.loads(content)
                phase = "analysis"
                value = {"task_key": supplied["task_key"],
                         "completed_units": [row["key"] for row in supplied["assigned_units"]], "findings": []}
                if history:
                    value["findings"] = [{
                        "unit_key": supplied["assigned_units"][0]["key"], "path": "billing.py",
                        "start_line": 14, "end_line": 14, "severity": "medium", "category": "correctness",
                        "content": "Rounding each amount changes the aggregate tax.", "suggestion_code": "",
                        "trigger": "Several fractional tax amounts.", "consequence": "Incorrect rounded total.",
                        "evidence": [{"source_id": next(row["source_id"] for row in supplied["citation_sources"] if row["path"] == "billing.py"),
                                      "start_line": 14, "end_line": 14}],
                    }]
            elif "original_issue_present" in schema:
                phase = "verification"
                value = {"verdict": "uncertain", "original_issue_present": False,
                         "explanation": "The historical report does not establish a defect.",
                         "change_explanation": "No supported fix conclusion.", "dismissal_recommended": True,
                         "evidence": [], "required_sources": []}
            elif "relationship" in schema:
                phase = "assessment"
                value = {"verdict": "confirmed", "relationship": "new", "finding_id": None,
                         "explanation": "Rounding differs.", "cause": "Per amount rounding.",
                         "trigger": "Fractional taxes.", "consequence": "Incorrect aggregate.",
                         "history_explanation": "The prior synthetic report did not describe per-item rounding.",
                         "contradicts_prior": False, "changed_conditions": "",
                         "suggestion_supported": False, "required_paths": [],
                         "evidence": [{"source_id": source_id("current", "billing.py"), "start_line": 14, "end_line": 14}]}
            else:
                phase = "summary"
                assert "narrative" in schema
                value = {"narrative": "Tax aggregation changes.", "groups": [
                    {"title": "Billing", "description": "Change tax aggregation.", "paths": ["billing.py"]}]}
            phases.append(phase)
            requests.append(time.monotonic())
            if overlap and phase in {"analysis", "verification", "summary"}:
                if sum(item in {"analysis", "verification", "summary"} for item in phases) <= 2:
                    overlap.wait()
                if phase == "verification":
                    time.sleep(1)
            data = json.dumps(wire_result("openai-responses", content=json.dumps(value))).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    manifest["connection"]["base_url"] = f"http://127.0.0.1:{server.server_port}/v1"
    case["identity"]["model_options_sha256"] = runtime.fingerprint({"extra_body": {"reasoning.effort": "medium"}})
    monkeypatch.syspath_prepend(str(HARNESS))
    try:
        result = runtime.captured_execute(manifest, case, exported, "mortis",
                                          {"api_key": "synthetic-only", "extra_headers": {}}, options,
                                          "12345678-1234-1234-1234-123456789000", fake_provider=True)
        retain("pr-history" if history else "pr-clean", result)
        if not history:
            with transaction() as db:
                original_run = runtime.row_data(db.get(ReviewRun, "12345678-1234-1234-1234-123456789000"))
                original_jobs = {row.id: runtime.row_data(row) for row in db.scalars(select(Job))}
            following = runtime.captured_execute(manifest, case, exported, "mortis",
                                                 {"api_key": "synthetic-only", "extra_headers": {}}, options,
                                                 "12345678-1234-1234-1234-123456789001", fake_provider=True)
            retain("pr-clean-following", following)
            assert following["status"] == "completed", following
            with transaction() as db:
                assert runtime.row_data(db.get(ReviewRun, original_run["id"])) == original_run
                assert {key: runtime.row_data(db.get(Job, key)) for key in original_jobs} == original_jobs
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result["status"] == "completed", result
    assert result["stop_pilot"] is False, result
    assert result["execution_profile"] == runtime.PARALLEL_PROFILE
    assert result["queue_measurement"]["includes_worker_boot"] is True
    assert result["timing_ms"]["terminal"] == result["queue_measurement"]["queue_to_terminal_ms"]
    assert result["summary"]["status"] == "completed"
    assert result["coverage"] == {"assigned_units": 1, "validated_units": 1}
    assert all(value["status"] in pipeline.TERMINAL for value in result["stages"].values())
    assert {row["kind"] for row in result["workflow_jobs"]} >= {"review", "summarize_review", "finalize_review"}
    assert len(result["provider_events"]) == (4 if history else 2)
    assert all(row["state"] == "finished" for row in result["provider_events"])
    assert len(result["ledger"]["attempts"]) == len(result["provider_events"])
    assert result["transport"]["physical_concurrency"]["limit"] == 4
    assert result["transport"]["physical_concurrency"]["peak"] <= 4
    assert len(result["findings"]) == (1 if history else 0)
    if history:
        assert set(phases) == {"analysis", "assessment", "verification", "summary"}
        assert result["transport"]["physical_concurrency"]["peak"] >= 2
        assert max(requests[:3]) - min(requests[:3]) < 20
        assert result["stages"]["assessment"]["status"] == "completed"
        target = result["verification_targets"][0]
        assert target["status"] == "completed" and target["verdict"] == "uncertain"
        with transaction() as db:
            finding = db.get(Finding, target["finding_id"])
            assert finding.status == "open" and finding.desired_status is None
            occurrence = db.get(Occurrence, target["occurrence_id"])
            assert occurrence.snapshot == case["historical_findings"][0]["snapshot"]
    else:
        assert set(phases) == {"analysis", "summary"}
        assert result["stages"]["verification"]["status"] == "skipped"
        assert result["verification_targets"] == []


@pytest.mark.skipif(sys.platform != "linux", reason="The production prefork worker requires Linux fork semantics")
@pytest.mark.parametrize("changed_snapshot", [False, True])
def test_queued_large_security_guards_scanner_before_any_ai(
    evaluation, queued_database, monkeypatch, tmp_path, changed_snapshot,  # noqa: F811
):
    """Synthetic scanner bytes/output, real guard + workflow + HTTP + nine unlimited-budget tasks."""
    manifest, case, _ = evaluation
    parallel(manifest)
    monkeypatch.syspath_prepend(str(HARNESS))
    import scanner_preflight

    export = tmp_path / "sec-100"
    repo = export / "repo"
    repo.mkdir(parents=True)
    prepare.git(repo, "init", "--quiet", "--initial-branch=head", "--template=")
    sources = {f"module_{index}.py": f"def value_{index}():\n    return {index}\n" + "# Ordinary source padding.\n" * 256
               for index in range(9)}
    base = prepare.revision(repo, {"previous.py": "def previous():\n    return 0\n"})
    head = prepare.revision(repo, sources, base["commit"])
    prepare.git(repo, "update-ref", "refs/heads/head", head["commit"])
    prepare.git(repo, "reset", "--quiet", "--hard", head["commit"])
    case.update(case_id="sec-100", workload="security", base=base, head=head,
                merge_base_sha=base["commit"], selected_paths=sorted(sources),
                scanner_inventory_paths=sorted(sources), expected_assigned_units=len(sources))
    manifest["security_limits"] = {"concurrency": 4, "token_budget": None, "timeout_seconds": 90}
    cache = tmp_path / "scanner-cache"
    (cache / "db").mkdir(parents=True)
    (cache / "policy/content").mkdir(parents=True)
    (cache / "db/metadata.json").write_text(json.dumps({"Version": 2, "UpdatedAt": now().isoformat()}))
    (cache / "db/trivy.db").write_bytes(b"Synthetic advisory fixture; never a real Trivy database")
    (cache / "policy/metadata.json").write_text(json.dumps({"MajorVersion": 2, "DownloadedAt": now().isoformat()}))
    (cache / "policy/content/check.rego").write_text("package synthetic\n")
    manifest["scanner_snapshot"] = scanner_preflight.snapshot_identity(cache)
    monkeypatch.setattr(settings(), "trivy_cache_dir", cache)
    if changed_snapshot:
        (cache / "db/trivy.db").write_bytes(b"Changed advisory bytes")
    marker = tmp_path / "synthetic-scanner-executed"
    bootstrap = tmp_path / "security_bootstrap.py"
    bootstrap.write_text(
        "import json,sys\nfrom pathlib import Path\n"
        "from code_mortis.security_scans import engine\n"
        "def synthetic_scan(*args, **kwargs):\n"
        f" Path({str(marker)!r}).write_text('synthetic scanner ran')\n"
        " return {'metadata': {'database_fresh': True, 'checks_present': True, "
        "'scanners': ['vuln','misconfig','secret']}, 'findings': [], 'problems': [], 'targets': {}}\n"
        "engine.trivy=synthetic_scan\n"
        f"sys.path.insert(0,{str(HARNESS)!r})\n"
        "import runtime\nruntime.queue_worker(json.loads(Path(sys.argv[2]).read_text()))\n"
    )
    popen = runtime.subprocess.Popen

    def worker_command(arguments, *args, **kwargs):
        if len(arguments) >= 3 and arguments[2] == "--queue-worker":
            arguments = [arguments[0], str(bootstrap), *arguments[2:]]
        return popen(arguments, *args, **kwargs)

    monkeypatch.setattr(runtime.subprocess, "Popen", worker_command)
    calls = []
    first_wave = threading.Barrier(4, timeout=15)

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            assert marker.is_file(), "AI dispatched before the scanner guard completed"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert body["reasoning"] == {"effort": "high"}
            calls.append(body)
            if len(calls) <= 4:
                first_wave.wait()
            data = json.dumps(wire_result("openai-responses", content=json.dumps({"findings": [], "required_paths": []}))).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    manifest["connection"]["base_url"] = f"http://127.0.0.1:{server.server_port}/v1"
    case["identity"]["model_options_sha256"] = runtime.fingerprint({"extra_body": {"reasoning.effort": "high"}})
    try:
        result = runtime.captured_execute(manifest, case, export, "mortis",
                                          {"api_key": "synthetic-only", "extra_headers": {}},
                                          RepoSettings(analysis_engine="mortis").model_dump(),
                                          "12345678-1234-1234-1234-123456789000", fake_provider=True)
        retain("security-changed-snapshot" if changed_snapshot else "security-nine-tasks", result)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if changed_snapshot:
        assert result["status"] == "failed", result
        assert not calls and not marker.exists()
        assert result["stop_pilot"] is True
        assert result["scanner_guard"] == {"validated": False, "error": "ValueError"}
    else:
        assert result["status"] == "completed", result
        assert len(calls) == 9
        assert result["scanner_guard"] == {"validated": True, "error": None}
        assert result["stop_pilot"] is False
        assert result["coverage"] == {"assigned_units": 9, "validated_units": 9}
        assert result["transport"]["physical_concurrency"] == {"limit": 4, "peak": 4}
        assert len(result["ledger"]["attempts"]) == 9
        assert all(stage["status"] == "completed" for stage in result["stages"].values())
