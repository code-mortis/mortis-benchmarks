"""Evaluation worker boundaries; these are offline checks, not quality evidence."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

import code_mortis

ROOT = Path(code_mortis.__file__).resolve().parents[2]
HARNESS = Path(__file__).resolve().parents[1] / "harness"


def module(name):
    spec = importlib.util.spec_from_file_location(name, HARNESS / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime = module("runtime")
prepare = module("prepare")


@pytest.fixture
def evaluation(tmp_path, monkeypatch):
    exported = tmp_path / "export"
    case = prepare.prepare_case(prepare.PILOT / "pr-01", exported)
    allowed = {
        "case_id",
        "family_id",
        "workload",
        "case_digest",
        "base",
        "head",
        "merge_base_sha",
        "selected_paths",
        "expected_assigned_units",
        "diff_sha256",
        "evaluation_track",
        "scanner_inventory_paths",
    }
    case = {key: value for key, value in case.items() if key in allowed}
    case["context_sha256"] = hashlib.sha256((exported / "pr-01/context.json").read_bytes()).hexdigest()
    case["identity"] = {
        key: "c" * 64
        for key in (
            "source_sha256",
            "scope_sha256",
            "settings_sha256",
            "effective_resources_sha256",
            "conditions_sha256",
        )
    }
    manifest = {
        "schema": runtime.SCHEMA,
        "run_id": "offline-check",
        "source_revision": "a" * 40,
        "corpus_digest": "b" * 64,
        "protocol_sha256": "d" * 64,
        "publication": "disabled_sandbox_adapter_only",
        "graph": "off",
        "repetition": 1,
        "cache": "cold",
        "connection": {
            "id": "evaluation",
            "name": "Synthetic provider",
            "provider": "openai",
            "protocol": "openai-responses",
            "base_url": "https://example.invalid/v1",
            "model": "synthetic",
            "options": {},
            "kind": "api",
            "owner_id": None,
        },
        "spending": {
            "mode": "explicit_owner_uncapped",
            "aggregate_usd_cap": None,
            "aggregate_token_cap": None,
            "aggregate_request_cap": None,
            "stop_on_unknown_usage": True,
        },
        "price_snapshot": {"observed_date": "2026-11-07"},
        "effective_resources_sha256": "e" * 64,
        "settings": {"effort": "medium"},
        "security_limits": {"concurrency": 4},
        "provider_reasoning_by_workload": {"pr": "medium", "security": "high"},
        "cases": [case],
    }
    monkeypatch.setenv("CM_EVAL_RUN_ID", manifest["run_id"])
    monkeypatch.setenv("CM_EVAL_SOURCE_REVISION", manifest["source_revision"])
    return manifest, case, exported / "pr-01"


def test_worker_validates_frozen_export_without_credentials(evaluation, monkeypatch):
    from code_mortis.schemas.common import RepoSettings

    manifest, case, exported = evaluation
    monkeypatch.delenv("CM_EVAL_CREDENTIALS_FILE", raising=False)
    assert runtime.validate_manifest(manifest, "pr-01", "mortis", live=False) == case
    context = runtime.checked_case(exported, case, RepoSettings().model_dump())
    assert context["head_sha"] == case["head"]["commit"]


@pytest.mark.parametrize(
    "mutation", ["run", "revision", "truth", "spending", "graph", "publication", "scope", "live"]
)
def test_worker_rejects_changed_or_unauthorized_manifest(evaluation, mutation):
    manifest, _, _ = evaluation
    manifest = copy.deepcopy(manifest)
    if mutation == "run":
        manifest["run_id"] = "another-run"
    elif mutation == "revision":
        manifest["source_revision"] = "f" * 40
    elif mutation == "truth":
        manifest["cases"][0]["truth"] = {"defects": []}
    elif mutation == "spending":
        manifest["spending"].pop("aggregate_token_cap")
    elif mutation == "scope":
        manifest["cases"][0]["expected_assigned_units"] += 1
    elif mutation in {"graph", "publication"}:
        manifest[mutation] = "enabled"
    with pytest.raises(ValueError):
        runtime.validate_manifest(manifest, "pr-01", "ocr", live=mutation == "live")


def test_worker_rejects_changed_source_before_inference(evaluation):
    from code_mortis.schemas.common import RepoSettings

    _, case, exported = evaluation
    case["head"]["blobs"][case["selected_paths"][0]]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="blob inventory"):
        runtime.checked_case(exported, case, RepoSettings().model_dump())


def test_worker_hashes_binary_revision_assets_without_treating_them_as_source(evaluation):
    from code_mortis.core.process import child_environment

    _, _, exported = evaluation
    content = b"\x00\xff\x80binary asset\r\n"
    root, env = exported / "repo", child_environment()
    blob = subprocess.check_output(["git", "hash-object", "-w", "--stdin"],
                                   cwd=root, env=env, input=content).decode().strip()
    assert runtime.blob_inventory(root, env, blob) == {
        "git_blob": blob, "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content),
    }


def test_worker_rejects_scope_mismatch_before_inference(evaluation):
    from code_mortis.schemas.common import RepoSettings

    _, case, exported = evaluation
    case["selected_paths"] = []
    with pytest.raises(ValueError, match="scope mismatch"):
        runtime.checked_case(exported, case, RepoSettings().model_dump())


def test_worker_rejects_executable_git_metadata(evaluation):
    from code_mortis.schemas.common import RepoSettings

    _, case, exported = evaluation
    with (exported / "repo/.git/config").open("a") as config:
        config.write('\n[filter "unsafe"]\n smudge = echo unexpected\n')
    with pytest.raises(ValueError, match="Git configuration"):
        runtime.checked_case(exported, case, RepoSettings().model_dump())


@pytest.mark.parametrize("kind", ["file", "nonempty_directory", "empty_directory"])
def test_worker_validates_git_hooks_path(evaluation, kind):
    from code_mortis.schemas.common import RepoSettings

    _, case, exported = evaluation
    hooks = exported / "repo/.git/hooks"
    assert not hooks.exists()
    if kind == "file":
        hooks.write_text("invalid hooks path")
    else:
        hooks.mkdir()
        if kind == "nonempty_directory":
            (hooks / "pre-commit").write_text("exit 1")
    if kind == "empty_directory":
        assert runtime.checked_case(exported, case, RepoSettings().model_dump())["head_sha"] == case["head"]["commit"]
    else:
        with pytest.raises(ValueError, match="Export must not contain Git hooks"):
            runtime.checked_case(exported, case, RepoSettings().model_dump())


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://localhost/mortis",
        "postgresql+psycopg://localhost/mortis_test",
        "sqlite:///mortis_eval",
    ],
)
def test_worker_refuses_production_or_test_database(monkeypatch, url):
    monkeypatch.setenv("CM_DATABASE_URL", url)
    monkeypatch.setenv("CM_EVAL_DISPOSABLE_DATABASE", "true")
    with pytest.raises(ValueError, match="mortis_eval"):
        runtime.validate_environment()


def test_worker_forbids_all_github_writes_and_other_identities(evaluation):
    _, case, exported = evaluation
    adapter = runtime.SyntheticGitHub(case, 42, "mortis-eval/pr-01", exported / "repo")
    for method, path, token in (
        ("POST", "/repos/mortis-eval/pr-01/pulls/1/reviews", runtime.TOKEN),
        ("GET", "/repos/real/project/pulls/1", runtime.TOKEN),
        ("GET", "/repos/mortis-eval/pr-01", "real-token"),
    ):
        with pytest.raises(ValueError):
            adapter.request(method, path, token)
    assert (
        adapter.request("GET", "/repos/mortis-eval/pr-01/pulls/1", runtime.TOKEN)["head"]["sha"]
        == case["head"]["commit"]
    )


def test_worker_credentials_never_accept_public_file(tmp_path, monkeypatch):
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"api_key": "synthetic-only", "extra_headers": {}}))
    credentials.chmod(0o644)
    monkeypatch.setenv("CM_EVAL_CREDENTIALS_FILE", str(credentials))
    with pytest.raises(ValueError, match="private"):
        runtime.read_credentials()
    credentials.chmod(0o600)
    assert runtime.read_credentials()["api_key"] == "synthetic-only"


@pytest.mark.parametrize("arm", ["mortis"])
def test_worker_pins_current_contract_for_new_security_attempt(evaluation, arm):
    from code_mortis.core.db import transaction
    from code_mortis.models import SecurityScan
    from code_mortis.schemas.common import RepoSettings
    from code_mortis.security_scans import engine as security_engine

    manifest, case, _ = evaluation
    manifest["case_deadline_seconds"] = 1800
    case["workload"] = "security"
    attempt_id = "new-security-" + arm
    runtime.create_attempt(
        manifest, case, arm, {"api_key": "synthetic-only", "extra_headers": {}},
        RepoSettings(analysis_engine=arm).model_dump(), attempt_id,
    )
    with transaction() as db:
        scan = db.get(SecurityScan, attempt_id)
        assert scan.config["analysis_engine"] == arm
        assert scan.config["task_contract"] == security_engine.TASK_CONTRACT


def test_worker_cli_dry_run_never_opens_database_or_credentials(evaluation, monkeypatch, tmp_path, capsys):
    from code_mortis.core import db
    from code_mortis.schemas.common import RepoSettings

    manifest, case, exported = evaluation
    options = RepoSettings().model_dump()
    options["background"] = json.loads((exported / "context.json").read_text())["context"]
    case["identity"]["settings_sha256"] = runtime.fingerprint(
        {
            "settings": {key: value for key, value in options.items() if key != "analysis_engine"},
            "security_limits": manifest["security_limits"],
        }
    )
    case["identity"]["model_options_sha256"] = runtime.fingerprint(
        {"extra_body": {"reasoning.effort": "medium"}}
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setenv("CM_DATABASE_URL", "postgresql+psycopg://synthetic@localhost/mortis_eval")
    monkeypatch.setenv("CM_EVAL_DISPOSABLE_DATABASE", "true")
    monkeypatch.setenv("CM_EVAL_MANIFEST_SHA256", hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "CM_GITHUB_TOKEN", "CM_EVAL_CREDENTIALS_FILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(db, "transaction", lambda: pytest.fail("Offline validation opened the database"))
    monkeypatch.setattr(
        "sys.argv",
        [
            "runtime.py",
            "--manifest",
            str(manifest_path),
            "--case",
            str(exported),
            "--arm",
            "mortis",
            "--output",
            "-",
            "--dry-run",
        ],
    )
    runtime.main()
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "validated_offline"
    assert result["external_model_requests"] == 0


@pytest.mark.parametrize(
    "validated,error,stop", [(True, None, False), (False, None, True), (True, "ValueError", True)]
)
def test_security_capture_stops_on_missing_or_failed_scanner_validation(
    evaluation, monkeypatch, validated, error, stop
):
    from contextlib import contextmanager
    from types import SimpleNamespace

    manifest, case, exported = evaluation
    case["workload"] = "security"
    case["identity"]["model_options_sha256"] = runtime.fingerprint(
        {"extra_body": {"reasoning.effort": "high"}}
    )
    manifest["scanner_snapshot"] = {"schema": "mortis-engine-scanner-snapshot/v1"}
    state = {"validated": validated, "error": error}

    @contextmanager
    def guard(snapshot, path):
        assert snapshot == manifest["scanner_snapshot"] and path == Path("/scanner-cache")
        yield state

    monkeypatch.syspath_prepend(str(HARNESS))
    monkeypatch.setitem(sys.modules, "scanner_preflight", SimpleNamespace(guard_scanner=guard))
    monkeypatch.setattr(
        runtime,
        "execute",
        lambda *args, **kwargs: {
            "status": "completed",
            "usage": {"tokens": 0},
            "timing_ms": {"terminal": 1},
            "outcomes": [],
        },
    )
    result = runtime.captured_execute(
        manifest,
        case,
        exported,
        "mortis",
        {"api_key": "synthetic-only", "extra_headers": {}},
        {},
        "synthetic-capture-check",
    )
    assert result["stop_pilot"] is stop
    assert result["scanner_guard"] == state
    assert bool(result["outcomes"]) is stop
    assert result["usage"]["requests"] == 0 and result["usage"]["tokens"] == 0


@pytest.mark.parametrize(
    "validated",
    [
        {"kind": "final", "completed_units": ["assigned-unit"], "comments": []},
        {"kind": "validated", "result": {"findings": [], "required_paths": []}},
        {"kind": "validated", "result": {"verdict": "uncertain", "required_sources": []}},
    ],
)
def test_first_validated_ignores_intermediate_and_rejected_task_results(monkeypatch, validated):
    from types import SimpleNamespace

    from code_mortis.core import analysis

    clock = {"now": 0.0}
    accepted = {"value": True}
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: clock["now"]))
    monkeypatch.setattr(analysis, "finish_task", lambda *args, **kwargs: accepted["value"])
    measured = runtime.Measurements()
    with measured.installed():
        for intermediate in (
            None,
            {},
            {"kind": "feedback", "code": "invalid_result"},
            {"kind": "expansion"},
            {"kind": "incomplete", "code": "source_round_limit"},
            {"kind": "invalid", "feedback": {}},
            {"kind": "unknown"},
            {"kind": "validated", "result": {"findings": [], "required_paths": ["helper.py"]}},
            {
                "kind": "validated",
                "result": {
                    "verdict": "uncertain",
                    "required_sources": [{"revision": "current", "path": "helper.py"}],
                },
            },
        ):
            clock["now"] += 1
            assert analysis.finish_task(object(), usage_tokens=0, result=intermediate)
            assert measured.first_validated is None
        accepted["value"] = False
        assert not analysis.finish_task(object(), usage_tokens=0, result=validated)
        assert measured.first_validated is None
        accepted["value"] = True
        clock["now"] = 10
        assert analysis.finish_task(object(), usage_tokens=0, result=validated)
        assert measured.first_validated == 10_000
        clock["now"] = 20
        assert analysis.finish_task(object(), usage_tokens=0, result=validated)
        assert measured.first_validated == 10_000
