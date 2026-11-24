"""Visible controlled workload fixtures; execute inside an isolated evaluation container.

Real queue/stages/Git/parser/Trivy/persistence; zero-delay synthetic HTTP answers.
This inventory is performance evidence only, never model-quality ground truth.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import runtime

MODEL = "synthetic-workload-model"
KEY = "synthetic-workload-key"


def git(root, *args):
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "Controlled workload", "GIT_COMMITTER_NAME": "Controlled workload",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_AUTHOR_DATE": "1794009600 +0000", "GIT_COMMITTER_DATE": "1794009600 +0000"}
    return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                                   env=env, text=True, stderr=subprocess.DEVNULL).strip()


def fixture(folder, workload, profile="history"):
    """Build a reproducible neutral source export with no scoring packet or hooks."""
    from code_mortis.core.process import child_environment
    from code_mortis.schemas.common import ReviewComment
    from code_mortis.schemas.security import SecurityProposal

    root = folder / "repo"
    root.mkdir(parents=True)
    git(root, "init", "--quiet", "--template=")
    sources = {"app.py": "from .shared import factor\ndef limit():\n    return 1\n",
               "shared.py": "factor = 1\n", "history.py": "def legacy(raw):\n    return eval(raw)\n"}
    if profile == "clean":
        sources = {"app.py": "def limit():\n    return 1\n"}
    if workload == "security" and profile == "history":
        sources.update({f"module_{n}.py": f"def value_{n}():\n    return {n}\n" + "# Ordinary padding.\n" * 256
                        for n in range(6)})
        sources["app.py"] = "def evaluate(raw):\n    return str(raw)\n" + "# Ordinary padding.\n" * 256
        sources["history.py"] += "# Ordinary padding.\n" * 256
        sources["shared.py"] += "# Ordinary padding.\n" * 256

    def revision(values):
        for name, value in values.items():
            (root / name).write_text(value)
        git(root, "add", ".")
        git(root, "commit", "--quiet", "-m", "Controlled source")
        commit = git(root, "rev-parse", "HEAD")
        blobs = {}
        for row in git(root, "ls-tree", "-r", commit).splitlines():
            meta, path = row.split("\t", 1)
            blobs[path] = runtime.blob_inventory(root, child_environment(), meta.split()[2])
        return {"commit": commit, "tree": git(root, "rev-parse", commit + "^{tree}"), "blobs": blobs}

    base = revision(sources)
    sources["app.py"] = sources["app.py"].replace("return 1", "return 0").replace("return str(raw)", "return eval(raw)")
    if workload == "pr" and profile == "history":
        sources["shared.py"] = "factor = 2\n"
    head = revision(sources)
    git(root, "branch", "-f", "head", head["commit"])
    selected = sorted(sources) if workload == "security" or profile == "clean" else ["app.py", "shared.py"]
    context = {"case_id": folder.name, "workload": workload, "base_sha": base["commit"], "head_sha": head["commit"],
               "context": "Controlled visible workload; no provider delay.", "selection": {"paths": selected, "unavailable": []}}
    (folder / "context.json").write_bytes(runtime.canonical(context))
    (folder / "change.diff").write_text(git(root, "diff", base["commit"], head["commit"]) + "\n")
    if workload == "security":
        history = SecurityProposal(title="Historical dynamic evaluation", category="injection", severity="medium",
            path="history.py", explanation="Dynamic input reaches eval.", trigger="Untrusted Python expression.",
            impact="Expression execution.", remediation="Remove dynamic evaluation.", verification="Inspect original/current source.",
            evidence=[{"revision": "current", "path": "history.py", "start_line": 2, "end_line": 2,
                       "quote": "    return eval(raw)"}]).model_dump()
    else:
        history = ReviewComment(path="history.py", content="Historical dynamic evaluation.",
            start_line=2, end_line=2, existing_code="    return eval(raw)").model_dump()
    return {"case_id": folder.name, "workload": workload, "family_id": "visible-workload-" + workload,
            "base": base, "head": head, "merge_base_sha": base["commit"], "selected_paths": selected,
            "expected_assigned_units": len(selected), "scanner_inventory_paths": sorted(sources),
            "context_sha256": hashlib.sha256((folder / "context.json").read_bytes()).hexdigest(),
            "diff_sha256": hashlib.sha256((folder / "change.diff").read_bytes()).hexdigest(),
            "historical_findings": [{"original_sha": base["commit"], "snapshot": history}] if profile == "history" else [], "identity": {}}


def workload_binding(folder, workload, profile):
    """Freeze neutral source/settings identities without database or provider execution."""
    from code_mortis.schemas.common import RepoSettings

    runtime.require(workload in {"pr", "security"} and profile in {"clean", "history"}, "Unknown workload fixture")
    case = fixture(folder, workload, profile)
    options = RepoSettings(token_budget=None, assessment_token_budget=None, verification_token_budget=None,
        summary_token_budget=None, auto_resolve=True, timeout_seconds=1800, summary_timeout_seconds=1800).model_dump()
    runtime.checked_case(folder, case, options)
    model_options = {"prompt_token_ceiling": 500000, "timeout_sec": 60,
                     "extra_body": {"reasoning.effort": "high" if workload == "security" else "medium"}}
    case["identity"]["model_options_sha256"] = runtime.fingerprint(model_options)
    history = profile == "history"
    return {"case": case, "fixture_sha256": runtime.fingerprint(case),
        "settings": {key: value for key, value in options.items() if key != "analysis_engine"},
        "security_limits": {"timeout_seconds": 1800, "token_budget": None, "concurrency": 4},
        "model_options": model_options, "execution_profile": runtime.PARALLEL_PROFILE, "queue": dict(runtime.QUEUE_PROFILE),
        "expected_work": {"findings": (2 if workload == "security" else 1) if history else 0,
            "assessment_candidates": int(history), "historical_verification_targets": int(history),
            "source_files": case["expected_assigned_units"],
            "security_analysis_tasks": case["expected_assigned_units"] if workload == "security" else 0}}


def supplied_context(body):
    """Both engines provide JSON metadata before verbatim numbered source blocks."""
    for message in body.get("input", []):
        if message.get("role") != "user":
            continue
        content = message.get("content", "")
        if isinstance(content, list):
            content = "\n".join(item.get("text", "") for item in content)
        for index, char in enumerate(content):
            if char == "{":
                try:
                    value, _ = json.JSONDecoder().raw_decode(content[index:])
                except ValueError:
                    continue
                if isinstance(value, dict) and ("citation_sources" in value or "assigned_units" in value):
                    return value
    return {}


def ocr_review_paths(body):
    paths = set()
    for message in body.get("input", []):
        content = message.get("content", "")
        if isinstance(content, list):
            content = "\n".join(item.get("text", "") for item in content)
        if isinstance(content, str) and "<review_files>" in content:
            block = content.split("<review_files>", 1)[1].split("</review_files>", 1)[0]
            paths.update(re.findall(r'<file path="([^"]+)">', block))
    return paths


def response(body, security, *, clean=False, selected_paths=None):
    from code_mortis.reviews.context import source_id

    tools = {tool.get("function", tool)["name"]: tool.get("function", tool) for tool in body.get("tools", [])}
    schema = body.get("text", {}).get("format", {}).get("schema", {})
    direct = bool(schema)
    if not schema:
        schema = tools.get("task_done", {}).get("parameters", {}).get("properties", {}).get("result", {})
    properties = schema.get("properties", {})
    context = supplied_context(body)
    catalog = context.get("citation_sources", {})

    def citations(path, revisions=("current",), line=2):
        if isinstance(catalog, list):
            return [{"source_id": row["source_id"], "start_line": line, "end_line": line}
                    for row in catalog if row["path"] == path][:len(revisions)]
        return [{"source_id": key, "start_line": line, "end_line": line}
                for key, row in catalog.items() if row["path"] == path and row["revision"] in revisions][:len(revisions)]

    if "narrative" in properties:
        phase, value = "summary", {"narrative": "The application limit changes.", "groups": [
            {"title": "Application", "description": "Change the limit.", "paths": selected_paths or ["app.py"]}]}
    elif "original_issue_present" in properties:
        phase = "verification"
        value = {"verdict": "still_present", "original_issue_present": True,
                 "explanation": "The original and current source both evaluate input.", "change_explanation": "The relevant line is unchanged.",
                 "evidence": citations("history.py", ("original", "current")), "required_paths": []}
        if not security:
            value["dismissal_recommended"] = False
            value.pop("required_paths")
            value["required_sources"] = []
    elif "relationship" in properties:
        phase = "assessment"
        value = {"verdict": "confirmed", "relationship": "new", "finding_id": None,
            "explanation": "The limit is zero.", "cause": "Zero return.", "trigger": "Allocate an item.",
            "consequence": "Nothing is allocated.", "history_explanation": "Separate historical issue.",
            "contradicts_prior": False, "changed_conditions": "", "suggestion_supported": False,
            "required_paths": [], "evidence": [{"source_id": source_id("current", "app.py"), "start_line": 3, "end_line": 3}]}
    elif security and "verdict" in properties:
        phase, value = "assessment", {"verdict": "confirmed", "finding_id": None,
            "explanation": "Input is evaluated.", "evidence": citations("app.py"), "required_paths": []}
    elif security and "findings" in properties:
        phase = "analysis"
        proposal = {"title": "Dynamic input evaluation", "category": "injection", "severity": "medium", "path": "app.py",
            "explanation": "Input reaches eval.", "trigger": "Untrusted expression.", "impact": "Expression execution.",
            "remediation": "Remove eval.", "verification": "Inspect source.", "evidence": citations("app.py")}
        assigned = context.get("path", context.get("assigned_path"))
        value = {"findings": [proposal] if assigned == "app.py" and not clean else [], "required_paths": []}
    elif "completed_units" in properties:
        phase = "analysis"
        assigned = next((unit for unit in context["assigned_units"] if unit.get("path") == "app.py"), None)
        value = {"task_key": context["task_key"], "completed_units": [unit["key"] for unit in context["assigned_units"]],
            "findings": [{"unit_key": assigned["key"] if assigned else "unassigned", "path": "app.py", "start_line": 3, "end_line": 3,
                "severity": "medium", "category": "correctness", "content": "The limit returns zero.", "existing_code": "    return 0",
                "suggestion_code": "    return 1", "trigger": "Allocate an item.", "consequence": "Nothing is allocated.",
                "evidence": citations("app.py", line=3)}] if assigned and not clean else []}
    else:
        phase, value = "analysis" if "code_comment" in tools else "review", None
    output = []
    if value is not None and direct:
        output = [{"type": "message", "role": "assistant", "status": "completed",
                   "content": [{"type": "output_text", "text": json.dumps(value)}]}]
    elif value is not None:
        output = [{"type": "function_call", "id": "fc_result", "call_id": "call_result", "name": "task_done",
                   "arguments": json.dumps({"state": "DONE", "result": value}), "status": "completed"}]
    elif "task_done" in tools:
        if "code_comment" in tools and "app.py" in ocr_review_paths(body) and not clean and not any(item.get("type") == "function_call_output" for item in body.get("input", [])):
            output.append({"type": "function_call", "id": "fc_comment", "call_id": "call_comment", "name": "code_comment",
                "arguments": json.dumps({"comments": [{"path": "app.py", "severity": "medium", "category": "correctness",
                    "content": "The limit returns zero.", "existing_code": "    return 0", "suggestion_code": "    return 1"}]}),
                "status": "completed"})
        output.append({"type": "function_call", "id": "fc_done", "call_id": "call_done", "name": "task_done",
                       "arguments": json.dumps({"state": "DONE"}), "status": "completed"})
    else:
        output = [{"type": "message", "role": "assistant", "status": "completed", "content": [
            {"type": "output_text", "text": '[{"label":"Application","files":["app.py"]}]'}]}]
    return phase, {"id": "resp_workload", "object": "response", "status": "completed", "model": MODEL,
                   "output": output, "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}


def graph_workload(args):
    """Separate graph-worker capacity probe using real parser HTTP and durable jobs."""
    from code_mortis import jobs
    from code_mortis.code_graph import service as graphs
    from code_mortis.core.db import transaction
    from code_mortis.models import (
        CodeGraphFile,
        CodeGraphSnapshot,
        ReviewRun,
        SecurityScan,
    )
    from code_mortis.schemas.common import RepoSettings
    from sqlalchemy import func, select

    with tempfile.TemporaryDirectory(prefix="graph-capacity-source-") as temporary:
        folder = Path(temporary) / "pr-200"
        case = fixture(folder, "pr")
        root = folder / "repo"
        for index in range(120):
            (root / f"capacity_{index}.py").write_text("from .shared import factor\n" + "\n".join(
                f"def calculate_{index}_{number}(value):\n    return value * factor + {number}\n" for number in range(80)))
        git(root, "add", ".")
        git(root, "commit", "--quiet", "-m", "Visible graph capacity sources")
        case["head"] = {"commit": git(root, "rev-parse", "HEAD"), "tree": git(root, "rev-parse", "HEAD^{tree}")}
        manifest = {"run_id": os.environ["CM_EVAL_RUN_ID"], "execution_profile": runtime.PARALLEL_PROFILE,
            "queue": dict(runtime.QUEUE_PROFILE), "case_deadline_seconds": 1800,
            "connection": {"id": str(uuid4()), "name": "Synthetic graph fixture", "provider": "custom",
                "protocol": "openai-responses", "model": MODEL, "base_url": "http://127.0.0.1:1/v1",
                "options": {}, "kind": "api", "owner_id": None}}
        attempt = str(uuid4())
        repository_id, full_name = runtime.create_attempt(manifest, case, "mortis",
            {"api_key": KEY, "extra_headers": {}}, RepoSettings(auto_resolve=True).model_dump(), attempt)
        adapter = runtime.SyntheticGitHub(case, repository_id, full_name, root)
        if args.wait_for_mixed_work:
            deadline = time.monotonic() + 120
            while True:
                with transaction() as db:
                    active_pr = db.scalar(select(ReviewRun.id).where(ReviewRun.id != attempt, ReviewRun.status == "running").limit(1))
                    active_scan = db.scalar(select(SecurityScan.id).where(SecurityScan.status == "running").limit(1))
                if active_pr and active_scan:
                    break
                assert time.monotonic() < deadline, "No simultaneous active PR/security workflows to overlap"
                time.sleep(.02)
        started = time.monotonic()
        with adapter.installed():
            graphs.configure(repository_id, repository_id, enabled=True)
            identity = graphs.enqueue_snapshot(repository_id, case["head"]["commit"])
            with transaction() as db:
                job = db.get(CodeGraphSnapshot, identity).job_id
            jobs.execute_job(job)
            with transaction() as db:
                row = db.get(CodeGraphSnapshot, identity)
                result = {"schema": "mortis-controlled-graph-capacity/v1", "started_monotonic": started,
                    "finished_monotonic": time.monotonic(), "snapshot": runtime.row_data(row),
                    "files": db.scalar(select(func.count()).select_from(CodeGraphFile).where(CodeGraphFile.snapshot_id == identity)),
                    "source_tree": case["head"]["tree"], "real_parser_http": True, "external_calls": 0,
                    "overlap_trigger": {"active_pr": active_pr, "active_scan": active_scan} if args.wait_for_mixed_work else None,
                    "cgroup": runtime.cgroup_metrics()}
        encoded = json.dumps(result, default=lambda value: value.isoformat())
        args.output.write_text(encoded)
        print(encoded, flush=True)
        assert row.status in graphs.USABLE and result["files"] == 123, result


def main():
    from alembic import command
    from alembic.config import Config
    from code_mortis.core.config import settings

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", choices=["pr", "security", "graph"], required=True)
    parser.add_argument("--fixture-profile", choices=["history", "clean"], default="history")
    parser.add_argument("--graph", choices=["off", "on", "exact_revision_gap"], default="off")
    parser.add_argument("--cache", choices=["cold", "warm"], default="cold")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--arm", choices=["ocr", "mortis", "both"], default="both")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-migration", action="store_true")
    parser.add_argument("--wait-for-mixed-work", action="store_true")
    args = parser.parse_args()
    runtime.require(1 <= args.repetitions <= 100, "Invalid repetition count")
    runtime.require(not args.output.exists(), "Never replace workload evidence")
    runtime.validate_environment()
    if not args.skip_migration:
        command.upgrade(Config("alembic.ini"), "head")
    settings().code_graph_store_dir = settings().work_dir / "graph-objects"
    os.environ["CM_CODE_GRAPH_STORE_DIR"] = str(settings().code_graph_store_dir)
    if args.workload == "graph":
        graph_workload(args)
        return
    observed, errors = [], []
    response_lock = threading.Lock()

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert self.path == "/v1/responses" and body["model"] == MODEL
                assert self.headers["Authorization"] == "Bearer " + KEY
                phase, result = response(body, args.workload == "security", clean=args.fixture_profile == "clean",
                                         selected_paths=server.selected_paths)
                if any(item.get("name") == "code_comment" for item in result["output"]):
                    with response_lock:
                        if server.finding_emitted:
                            result["output"] = [item for item in result["output"] if item.get("name") != "code_comment"]
                        server.finding_emitted = True
                observed.append({"phase": phase, "citation_sources": supplied_context(body).get("citation_sources"),
                                 "response": result,
                                 "ocr_assigned_paths": sorted(ocr_review_paths(body))})
                encoded = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except Exception as exc:
                errors.append(type(exc).__name__)
                raise

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    server.finding_emitted = False
    server.selected_paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    records = []
    try:
        with tempfile.TemporaryDirectory(prefix="controlled-source-") as temporary:
            folder = Path(temporary) / ("sec-100" if args.workload == "security" else "pr-100")
            binding = workload_binding(folder, args.workload, args.fixture_profile)
            case = binding["case"]
            server.selected_paths = case["selected_paths"]
            options = {**binding["settings"], "analysis_engine": "ocr"}
            manifest = {"run_id": os.environ["CM_EVAL_RUN_ID"], "execution_profile": runtime.PARALLEL_PROFILE,
                "queue": dict(runtime.QUEUE_PROFILE), "graph": args.graph, "cache": args.cache,
                "case_deadline_seconds": 1800, "provider_reasoning_by_workload": {"pr": "medium", "security": "high"},
                "connection": {"id": "controlled-workload", "name": "Synthetic", "provider": "custom", "protocol": "openai-responses",
                    "model": MODEL, "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                    "options": {"prompt_token_ceiling": 500000, "timeout_sec": 60}, "kind": "api", "owner_id": None},
                "security_limits": binding["security_limits"]}
            if args.workload == "security":
                manifest["scanner_snapshot"] = json.loads(Path("/snapshot.json").read_text())
            schedule = [(r, a) for r in range(1, args.repetitions + 1) for a in
                        (("ocr", "mortis") if r % 2 else ("mortis", "ocr")) if args.arm in {"both", a}]
            result = {"schema": "mortis-controlled-workloads/v1", "configured_provider_delay_ms": 0, "external_calls": 0,
                "graph": args.graph, "cache": args.cache, "fixture_profile": args.fixture_profile, "fixture_sha256": binding["fixture_sha256"], "case": case, "binding": binding,
                "cache_semantics": "fresh logical workspace; host page cache uncontrolled" if args.cache == "cold" else
                    "equal source Git-object pre-read before either arm; no inference/result cache; host page cache uncontrolled",
                "arms": records, "errors": errors, "performance_acceptance": False}
            def retain():
                encoded = json.dumps(result, sort_keys=True, default=lambda value: value.isoformat())
                args.output.write_text(encoded)
                print(encoded, flush=True)

            retain()
            if args.cache == "warm":
                # Prime equal source reads before either arm; retain all warmup work separately.
                primed = [path for path in sorted((folder / "repo/.git/objects").rglob("*")) if path.is_file()]
                for path in primed:
                    path.read_bytes()
                result["cache_priming"] = {"files": len(primed), "bytes": sum(path.stat().st_size for path in primed),
                                           "scope": "same frozen Git export before either arm", "outside_queue_timing": True}
                retain()
            for repetition, arm in schedule:
                options["analysis_engine"] = arm
                before = len(observed)
                server.finding_emitted = False
                attempt = runtime.captured_execute(manifest, case, folder, arm,
                    {"api_key": KEY, "extra_headers": {}}, options, str(uuid4()), fake_provider=True)
                from code_mortis.core.db import transaction
                from code_mortis.models import (
                    Finding,
                    Occurrence,
                    SecurityFinding,
                    SecurityOccurrence,
                    SecurityScan,
                )
                from sqlalchemy import select

                with transaction() as db:
                    if args.fixture_profile == "clean":
                        preserved = not attempt.get("verification_targets") and not case["historical_findings"]
                    elif args.workload == "pr":
                        history_rows = [(db.get(Finding, row["finding_id"]), db.get(Occurrence, row["occurrence_id"]))
                                        for row in attempt["verification_targets"]]
                        preserved = bool(history_rows) and all(finding.status == "open" and finding.desired_status is None
                            and occurrence.snapshot == case["historical_findings"][0]["snapshot"]
                            for finding, occurrence in history_rows)
                    else:
                        repository_id = db.get(SecurityScan, attempt["job"]["id"]).repository_id
                        old = db.scalar(select(SecurityFinding).where(SecurityFinding.repository_id == repository_id,
                            SecurityFinding.title == case["historical_findings"][0]["snapshot"]["title"]))
                        occurrence = db.scalar(select(SecurityOccurrence).where(SecurityOccurrence.finding_id == old.id,
                            SecurityOccurrence.scan_id == old.first_scan_id)) if old else None
                        preserved = bool(old and occurrence and old.state == "open" and not old.issue.get("desired_state")
                            and occurrence.snapshot["source_sha"] == case["base"]["commit"]
                            and all(occurrence.snapshot[key] == value for key, value in case["historical_findings"][0]["snapshot"].items()))
                attempt["history_preservation"] = {"applicable": args.fixture_profile == "history",
                    "original_occurrence_unchanged": preserved if args.fixture_profile == "history" else None,
                    "finding_remains_open": preserved if args.fixture_profile == "history" else None,
                    "source_commit": case["base"]["commit"]}
                records.append({"arm": arm, "repetition": repetition, "phases": observed[before:], "result": attempt})
                retain()
                assert attempt["status"] == "completed", attempt
                assert preserved, attempt
                assert attempt["coverage"] == {"assigned_units": case["expected_assigned_units"],
                                                "validated_units": case["expected_assigned_units"]}, attempt
                assert not attempt["stop_pilot"], attempt
                assert (len(attempt["findings"]) == 0 if args.fixture_profile == "clean" else len(attempt["findings"]) >= 1), attempt
                candidates = len(attempt["candidates"]) if args.workload == "pr" else attempt["stages"]["assessment"]["total"]
                assert candidates == (0 if args.fixture_profile == "clean" else 1), attempt
                required = {"analysis"} if args.fixture_profile == "clean" else {"analysis", "assessment", "verification"}
                assert required <= {row["phase"] for row in observed[before:]}, attempt
                assert attempt["usage"]["tokens"] == 15 * len(attempt["provider_events"]), attempt
                if args.workload == "pr":
                    assert attempt["summary"]["status"] == "completed", attempt
                    if args.fixture_profile == "history":
                        assert attempt["stages"]["verification"]["status"] == "completed", attempt
                        assert len(attempt["verification_targets"]) >= 1, attempt
                        assert all(row["status"] == "completed" and row["verdict"] == "still_present"
                                   for row in attempt["verification_targets"]), attempt
                else:
                    assert attempt["scanner_guard"] == {"validated": True, "error": None}, attempt
                    assert attempt["stages"]["verification"]["findings"] == (0 if args.fixture_profile == "clean" else 1), attempt
            print(json.dumps({"output": str(args.output), "completed": len(records), "errors": errors}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit("This historical OCR/native evaluation is retired. Saved evidence and offline scoring remain available; new execution is disabled.")
