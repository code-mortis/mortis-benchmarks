"""Mortis frozen reliability fixtures and explicit refusal of retired OCR execution."""

import importlib.util
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from test_llm_http import result as wire_result

from code_mortis.core import analysis
from code_mortis.core.config import settings
from code_mortis.core.db import transaction
from code_mortis.models import AnalysisAttempt, Finding, Job, SecurityFinding, SecurityScan
from code_mortis.schemas.common import RepoSettings

SCRIPTS = Path(__file__).resolve().parents[1] / "harness"


def module(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prepare = module("prepare")
# The standalone script imports its sibling runtime; don't change runtime's gates.
sys.path.insert(0, str(SCRIPTS))
try:
    faults = module("faults")
finally:
    sys.path.remove(str(SCRIPTS))


@pytest.fixture
def provider(monkeypatch):
    state = {"requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            state["requests"].append(json.loads(self.rfile.read(int(self.headers["content-length"]))))
            encoded = json.dumps(state["body"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("CM_TRUSTED_ENDPOINT_HOSTS", "127.0.0.1")
    monkeypatch.setattr(settings(), "trusted_endpoint_hosts", "127.0.0.1")
    state["url"] = f"http://127.0.0.1:{server.server_port}/v1"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("case_id", faults.CASES)
@pytest.mark.parametrize("arm", ["ocr", "mortis"])
def test_frozen_reliability_fixture_never_becomes_clean(tmp_path, monkeypatch, provider, case_id, arm):
    exported = tmp_path / "export"
    case = prepare.prepare_case(prepare.PILOT / case_id, exported)
    if arm == "ocr":
        historical = {"analysis_engine": arm}
        assert analysis.engine_snapshot(historical)["analysis_engine"] == "ocr"
        with pytest.raises(ValueError, match="This saved review engine is retired"):
            analysis.require_execution_engine(historical)
        with pytest.raises(ValidationError):
            RepoSettings(analysis_engine=arm)
        assert not provider["requests"]
        with transaction() as db:
            assert not list(db.scalars(select(Job)))
            assert not list(db.scalars(select(Finding)))
            assert not list(db.scalars(select(SecurityFinding)))
        return
    value = {"findings": [], "required_paths": []}
    provider["body"] = wire_result("openai", content=json.dumps(value))
    monkeypatch.setattr(settings(), "work_dir", tmp_path / "work")
    options = RepoSettings(analysis_engine=arm, concurrency=1, token_budget=200_000,
                           timeout_seconds=120).model_dump()
    manifest = {
        "run_id": "fault-fixtures", "case_deadline_seconds": 120,
        "connection": {"id": "fixture-provider", "name": "Synthetic local HTTP", "kind": "api", "owner_id": None,
                       "provider": "openai", "protocol": "openai", "model": "test-model",
                       "base_url": provider["url"], "options": {}},
        "security_limits": {"concurrency": 1, "token_budget": 200_000, "timeout_seconds": 120},
    }
    identity = case_id + "-" + arm
    result = faults.execute_fixture(manifest, case, exported / case_id, arm,
                                    {"api_key": "synthetic-provider-key", "extra_headers": {}}, options, identity)
    destination = os.environ.get("CM_FAULT_EVIDENCE_DIR")
    # Preserve raw failed/partial outcomes before assertions, without rewriting them.
    if destination:
        with (Path(destination) / (identity + ".json")).open("x") as output:
            json.dump(result, output, sort_keys=True, indent=2, default=lambda value: value.isoformat())
            output.write("\n")
    assert result["status"] in {"failed", "partial"}, result
    assert result["findings"] == [] and result["error"]
    assert result["fixture"]["case_digest"] == case["case_digest"]
    with transaction() as db:
        assert db.scalar(select(Finding)) is None and db.scalar(select(SecurityFinding)) is None
        assert db.get(Job, identity).status in {"failed", "completed"}
        assert not list(db.scalars(select(Job).where(Job.kind.in_(["publish", "resolve", "security_issue"])) ))
        if case_id == "pr-12":
            assert result["fixture"]["fault_events"] == [{"available": "src/coordinator.py", "unavailable": "src/worker.py",
                                                          "boundary": "git_object_read", "selected_units": 2}]
            assert result["coverage"] == {"assigned_units": 2, "validated_units": 0}
            assert not provider["requests"] and not result["ledger"]["attempts"]
            assert result["status"] == "failed"
        else:
            scan = db.get(SecurityScan, identity)
            assert scan.stages["report"]["status"] == "completed"
            if case_id == "sec-07":
                assert scan.status == "partial", scan.error
                assert "older than 24 hours" in scan.error
                assert scan.coverage["trivy"]["database_fresh"] is False
                assert scan.coverage["trivy"]["scanners"] == ["misconfig", "secret"]
                assert "package-lock.json" in scan.coverage["inventory"]
                assert scan.coverage["inventory"]["package-lock.json"]["code"] is False
                assert "package-lock.json" in scan.coverage["targets"]
                assert scan.stages["analysis"]["status"] == "completed"
                assert len(provider["requests"]) == 2
                assert scan.progress["tokens"] == 24
                if arm == "mortis":
                    attempts = list(db.scalars(select(AnalysisAttempt)))
                    assert len(attempts) == 2 and all(row.usage_state == "known" for row in attempts)
                    assert sum(row["charged_tokens"] for row in result["ledger"]["budgets"]) == 24
            else:
                assert scan.grade is None
                assert "No supported security analysis targets" in scan.error
                assert set(scan.coverage["inventory"]) == {"README.md", "guide.mdx"}
                assert all(not item["code"] for item in scan.coverage["inventory"].values())
                assert not scan.coverage["targets"]
                assert not provider["requests"] and not result["ledger"]["attempts"]
            commands = result["fixture"]["scanner_commands"]
            assert len(commands) == 4
            assert any("code_mortis.security_scans.scanner" in call for call in commands)
    # Terminal replay cannot change history or repeat inference/scanning.
    before = len(provider["requests"])
    from code_mortis.reviews import service
    from code_mortis.security_scans import service as security_service

    if case_id == "pr-12":
        service.perform_review(identity, identity + ":1")
    else:
        security_service.perform(identity, identity + ":1")
    assert len(provider["requests"]) == before
    if destination:
        with (Path(destination) / (identity + ".checks.json")).open("x") as output:
            json.dump({"checks_passed": True, "provider_requests": len(provider["requests"]),
                       "terminal_replay": "no repeated inference",
                       "evidence_scope": "synthetic reliability fixture; not held-out quality or live integration"}, output)
            output.write("\n")
