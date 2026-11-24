"""Run one synthetic paired-pilot arm through production workflows in a disposable database.

This worker accepts only the neutral runtime manifest and exported Git/context inputs.
It never imports the corpus preparation, truth, or scoring modules. GitHub acquisition
and authorization use a constrained local adapter; every GitHub write is forbidden.
"""

import argparse
import configparser
import copy
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import ExitStack, contextmanager, nullcontext
from datetime import timedelta
from pathlib import Path
from threading import Lock
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import uuid4

SCHEMA = "mortis-engine-live-run/v1"
WORKFLOW_SCHEMA = "mortis-engine-workflow-run/v2"
TOKEN = "synthetic-evaluation-github-token"
MAX_PROVIDER_EVENTS = 256
PARALLEL_PROFILE = "parallel_queue_v2"
LEGACY_PROFILE = "retained_sequential_v1"
QUEUE_PROFILE = {"pool": "prefork", "concurrency": 4, "dispatch_interval_seconds": 10}


def execution_profile(manifest):
    profile = manifest.get("execution_profile", LEGACY_PROFILE)
    require(profile in {LEGACY_PROFILE, PARALLEL_PROFILE}, "Unknown execution profile")
    if profile == PARALLEL_PROFILE:
        require(manifest.get("queue") == QUEUE_PROFILE, "Parallel queue resource/settings mismatch")
    else:
        require("queue" not in manifest, "Legacy timings cannot include queue settings")
    return profile


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_manifest(manifest, case_id, arm, *, live):
    """Fail before importing database/model code or opening provider credentials."""
    profile = execution_profile(manifest)
    require(manifest.get("schema") == (WORKFLOW_SCHEMA if profile == PARALLEL_PROFILE else SCHEMA),
            "Runtime schema/execution profile mismatch")
    require(
        not set(manifest) & {"truth", "oracle", "defects", "control", "adjudication"},
        "Scorer-only content cannot enter the execution worker",
    )
    require(arm in {"ocr", "mortis"}, "Unsupported engine arm")
    require(
        re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", manifest.get("run_id", "")),
        "Invalid evaluation run identity",
    )
    require(
        manifest["run_id"] == os.environ.get("CM_EVAL_RUN_ID"),
        "Evaluation run identity does not match environment",
    )
    require(
        manifest.get("source_revision") == os.environ.get("CM_EVAL_SOURCE_REVISION"),
        "Worker source revision mismatch",
    )
    for key in ("corpus_digest", "protocol_sha256", "source_revision"):
        length = 40 if key == "source_revision" else 64
        require(
            re.fullmatch(rf"[0-9a-f]{{{length}}}", manifest.get(key, "")),
            f"Invalid {key}",
        )
    require(
        manifest.get("publication") == "disabled_sandbox_adapter_only",
        "Publication must be disabled",
    )
    if profile == PARALLEL_PROFILE:
        require(manifest.get("graph") in {"off", "on", "exact_revision_gap"}, "Unknown graph stratum")
        require(manifest.get("cache") in {"cold", "warm"}, "Unknown source-cache stratum")
        require(type(manifest.get("repetition")) is int and 1 <= manifest["repetition"] <= 100,
                "Invalid paired repetition")
    else:
        require(manifest.get("graph") == "off", "This paired pilot supports only graph-off scope")
        require(manifest.get("repetition") == 1, "The frozen pilot has one paired repetition")
        require(manifest.get("cache") == "cold", "This worker requires a cold source workspace")
    connection = manifest.get("connection", {})
    require(
        connection.get("kind") == "api" and connection.get("owner_id") is None,
        "Only shared API connections are permitted",
    )
    require(
        set(connection)
        <= {
            "id",
            "name",
            "provider",
            "protocol",
            "model",
            "base_url",
            "options",
            "kind",
            "owner_id",
        },
        "Secret or unknown connection fields",
    )
    require(
        all(
            isinstance(connection.get(k), str) and connection[k]
            for k in ("id", "name", "provider", "protocol", "model", "base_url")
        ),
        "Incomplete connection binding",
    )
    require(isinstance(connection.get("options"), dict), "Missing frozen connection options")
    spending = manifest.get("spending", {})
    require(
        spending.get("mode") == "explicit_owner_uncapped",
        "This pilot requires its explicit owner spending selection",
    )
    require(
        all(
            k in spending and spending[k] is None
            for k in (
                "aggregate_usd_cap",
                "aggregate_token_cap",
                "aggregate_request_cap",
            )
        ),
        "Uncapped aggregate policy must be explicit",
    )
    require(
        spending.get("stop_on_unknown_usage") is True,
        "Unknown usage must stop dispatch",
    )
    require(
        manifest.get("price_snapshot") and manifest.get("effective_resources_sha256"),
        "Missing frozen price/resource snapshot",
    )
    require(
        manifest.get("settings") and manifest.get("security_limits"),
        "Missing frozen workflow limits",
    )
    require(
        manifest.get("provider_reasoning_by_workload") == {"pr": "medium", "security": "high"},
        "Missing frozen paired provider reasoning settings",
    )
    cases = [row for row in manifest.get("cases", []) if row.get("case_id") == case_id]
    require(len(cases) == 1, "Case identity is missing or duplicated")
    case = cases[0]
    require(
        set(case)
        <= {
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
            "context_sha256",
            "identity",
            "evaluation_track",
            "scanner_inventory_paths",
            "historical_findings",
        },
        "Runtime case contains unexpected or scorer-only fields",
    )
    require(
        case.get("evaluation_track") == "quality_microcase",
        "Reliability fixtures must use the separate injection harness",
    )
    require(case.get("workload") in {"pr", "security"}, "Unknown case workload")
    pattern = r"(?:pr|sec)-\d{2,4}" if profile == PARALLEL_PROFILE else r"(?:pr|sec)-\d{2}"
    require(re.fullmatch(pattern, case_id), "Invalid synthetic case identity")
    require(
        len(set(case["selected_paths"])) == len(case["selected_paths"]),
        "Duplicate selected paths",
    )
    require(
        case["expected_assigned_units"] == len(case["selected_paths"]),
        "Invalid frozen coverage denominator",
    )
    history = case.get("historical_findings", [])
    require(isinstance(history, list) and len(history) <= 100, "Invalid historical finding inventory")
    if profile == PARALLEL_PROFILE:
        require(isinstance(manifest.get("cases"), list) and 1 <= len(manifest["cases"]) <= 1000,
                "Queued workflow cohort must contain 1–1000 cases")
        conditions = manifest.get("conditions", {})
        require(conditions.get("execution_profile") == profile and conditions.get("queue") == QUEUE_PROFILE,
                "Queued workflow conditions must freeze profile and queue")
        require(all(conditions.get(key, default) == manifest[key] for key, default in
                    (("graph", "off"), ("cache", "cold"), ("repetition", 1))),
                "Graph/cache/repetition conditions differ from manifest")
        require(case["identity"].get("history_sha256") == fingerprint(history), "Historical input identity mismatch")
        require(case["identity"].get("conditions_sha256") == fingerprint({
            **conditions, "workload": case["workload"], "provider_options": provider_options(manifest, case),
        }), "Queued workflow condition identity mismatch")
    if history:
        require(profile == PARALLEL_PROFILE, "History requires the parallel profile")
        from code_mortis.schemas.common import ReviewComment
        from code_mortis.schemas.security import SecurityProposal

        for item in history:
            require(set(item) == {"original_sha", "snapshot"}, "Unexpected historical finding fields")
            require(item["original_sha"] == case["base"]["commit"], "Historical source must be the frozen base revision")
            snapshot = item["snapshot"]
            contract = ReviewComment if case["workload"] == "pr" else SecurityProposal
            require(isinstance(snapshot, dict) and set(snapshot) == set(contract.model_fields), "Historical snapshot must be complete")
            contract.model_validate(snapshot, strict=True)
        require(len({fingerprint(item["snapshot"]) for item in history}) == len(history), "Duplicate historical findings")
        if case["workload"] == "pr":
            require(manifest["settings"].get("auto_resolve") is True, "Historical verification must retain auto_resolve")
    if live:
        require(
            manifest.get("live_enabled") is True and manifest.get("authorization") == "owner_selected_pilot",
            "Live pilot has no explicit run authorization",
        )
        require(
            manifest.get("isolation_checks_passed") is True,
            "Fake-provider isolation checks must pass before live inference",
        )
    return case


def validate_environment():
    from sqlalchemy.engine import make_url

    url = make_url(os.environ.get("CM_DATABASE_URL", ""))
    require(
        url.get_backend_name() == "postgresql" and url.database == "mortis_eval",
        "Evaluation requires the separate mortis_eval PostgreSQL database",
    )
    require(
        os.environ.get("CM_EVAL_DISPOSABLE_DATABASE") == "true",
        "Disposable database acknowledgement is required",
    )
    require(
        not any(os.environ.get(k) for k in ("GITHUB_TOKEN", "GH_TOKEN", "CM_GITHUB_TOKEN")),
        "GitHub credentials are forbidden in evaluation workers",
    )


def read_credentials():
    path = Path(os.environ["CM_EVAL_CREDENTIALS_FILE"])
    require(
        path.is_file() and not path.is_symlink(),
        "Credentials must be a private regular file",
    )
    require(
        stat.S_IMODE(path.stat().st_mode) & 0o077 == 0,
        "Credentials file permissions must be private",
    )
    credentials = json.loads(path.read_text())
    require(set(credentials) == {"api_key", "extra_headers"}, "Unexpected credential fields")
    require(
        isinstance(credentials["api_key"], str) and credentials["api_key"],
        "Missing provider credential",
    )
    require(
        isinstance(credentials["extra_headers"], dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in credentials["extra_headers"].items()),
        "Invalid provider extra headers",
    )
    return credentials


def provider_options(manifest, case):
    options = copy.deepcopy(manifest["connection"]["options"])
    extra = options.get("extra_body", {})
    require(isinstance(extra, dict), "Provider extra_body must be an object")
    options["extra_body"] = {
        **extra,
        "reasoning.effort": manifest["provider_reasoning_by_workload"][case["workload"]],
    }
    require(
        case["identity"]["model_options_sha256"] == fingerprint(options),
        "Effective provider model options mismatch",
    )
    return options


def blob_inventory(root, env, blob):
    """Hash inert Git bytes; excluded binary assets still belong to revision identity."""
    from code_mortis.core import source

    require(re.fullmatch(r"[0-9a-f]{40}", blob), "Invalid Git blob identity")
    size = int(source.git(root, env, "cat-file", "-s", blob).strip())
    require(0 <= size <= 512 * 1024 * 1024, "Blob exceeds the export size ceiling")
    digest, observed = hashlib.sha256(), 0
    with tempfile.TemporaryFile() as output:
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "cat-file", "blob", blob],
                       cwd=root, env=env, stdout=output, stderr=subprocess.DEVNULL,
                       check=True, timeout=180)
        require(output.tell() == size, "Git blob size mismatch")
        output.seek(0)
        while chunk := output.read(65536):
            digest.update(chunk)
            observed += len(chunk)
    return {"git_blob": blob, "sha256": digest.hexdigest(), "bytes": observed}


def checked_case(export, case, options):
    from code_mortis.core import source
    from code_mortis.core.process import child_environment
    from code_mortis.reviews import planning
    from code_mortis.security_scans.engine import Snapshot

    require(
        export.is_dir() and export.name == case["case_id"],
        "Export path must name the frozen case",
    )
    require(
        {p.name for p in export.iterdir()} == {"repo", "context.json", "change.diff"},
        "Only exported source/context/diff may enter the worker",
    )
    require(
        not any(p.is_symlink() for p in export.rglob("*")),
        "Export cannot contain symlinks",
    )
    context = json.loads((export / "context.json").read_text())
    require(
        hashlib.sha256((export / "context.json").read_bytes()).hexdigest() == case["context_sha256"],
        "Context identity mismatch",
    )
    require(
        context["case_id"] == case["case_id"] and context["workload"] == case["workload"],
        "Export case identity mismatch",
    )
    require(
        sorted(context["selection"]["paths"]) == sorted(case["selected_paths"]),
        "Export selected scope mismatch",
    )
    require(
        not context["selection"]["unavailable"],
        "Quality arm cannot inject unavailable evidence",
    )
    root, env = export / "repo", child_environment()
    config = configparser.RawConfigParser(strict=True)
    config.read(root / ".git" / "config")
    require(
        config.sections() == ["core"]
        and set(config["core"])
        <= {
            "repositoryformatversion",
            "filemode",
            "bare",
            "logallrefupdates",
            "ignorecase",
            "precomposeunicode",
        },
        "Export Git configuration may not contain executable settings or external includes",
    )
    require(
        not (root / ".git" / "objects" / "info" / "alternates").exists(),
        "Export Git objects must be self-contained",
    )
    hooks = root / ".git" / "hooks"
    require(
        not hooks.exists() or (hooks.is_dir() and not any(hooks.iterdir())),
        "Export must not contain Git hooks",
    )
    for side in ("base", "head"):
        revision = case[side]
        require(context[side + "_sha"] == revision["commit"], "Context revision mismatch")
        require(
            source.git(root, env, "rev-parse", revision["commit"] + "^{tree}").strip() == revision["tree"],
            "Git tree identity mismatch",
        )
        entries = source.git(root, env, "ls-tree", "-r", "-z", revision["commit"]).strip("\n\0").split("\0")
        actual = {}
        for entry in filter(None, entries):
            meta, path = entry.split("\t", 1)
            mode, kind, blob = meta.split()
            source.repository_path(path)
            require(
                mode in {"100644", "100755"} and kind == "blob",
                "Synthetic source must be regular files",
            )
            actual[path] = blob_inventory(root, env, blob)
        require(actual == revision["blobs"], "Git blob inventory mismatch")
    require(
        source.git(root, env, "merge-base", case["base"]["commit"], case["head"]["commit"]).strip()
        == case["merge_base_sha"],
        "Merge-base mismatch",
    )
    require(
        hashlib.sha256((export / "change.diff").read_bytes()).hexdigest() == case["diff_sha256"],
        "Diff identity mismatch",
    )
    for item in case.get("historical_findings", []):
        snapshot = item["snapshot"]
        path = snapshot["path"]
        require(path in case["base"]["blobs"], "Historical finding source is absent from the frozen base")
        original = source.read_source(root, env, item["original_sha"], path, lambda: False)
        ranges = [snapshot] if case["workload"] == "pr" else snapshot["evidence"]
        for citation in ranges:
            text = original if citation.get("path", path) == path else source.read_source(
                root, env, item["original_sha"], citation["path"], lambda: False)
            require(1 <= citation["start_line"] <= citation["end_line"] <= len(text.splitlines()),
                    "Historical finding range is outside its original source")
            if case["workload"] == "security":
                require(citation["quote"] in "\n".join(text.splitlines()[citation["start_line"] - 1:citation["end_line"]]),
                        "Historical security citation differs from its frozen source")
    if case["workload"] == "pr":
        plan = planning.plan_review(
            root,
            env,
            case["base"]["commit"],
            case["head"]["commit"],
            case["merge_base_sha"],
            options,
            lambda: False,
        )
        require(
            sorted(item.path for item in plan.selected) == sorted(case["selected_paths"]),
            "Production PR selection does not match frozen scope",
        )
        require(
            not plan.limit_reason and all(not item.error for item in plan.selected),
            "Frozen PR source is incomplete",
        )
    else:
        with tempfile.TemporaryDirectory(prefix="eval-scope-") as temporary:
            item = Snapshot(Path(temporary), case["head"]["commit"], env, lambda: False)
            item.git = root
            item.populate()
            require(
                sorted(path for path, entry in item.inventory.items() if entry["code"])
                == sorted(case["selected_paths"]),
                "Production security selection does not match frozen scope",
            )
            require(
                sorted(item.inventory) == sorted(case["scanner_inventory_paths"]),
                "Scanner inventory mismatch",
            )
    return context


class Measurements:
    """Time the first persisted terminal task output, independently of coverage or truth."""

    def __init__(self, started=None):
        self.started = time.monotonic() if started is None else started
        self.phases = {}
        self.internal_errors = []
        self.first_validated = None
        self.lock = Lock()

    def measure(self, name, function):
        def call(*args, **kwargs):
            started = time.monotonic()
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                self.internal_errors.append({"type": type(exc).__name__, "phase": name,
                    "cause_type": type(getattr(exc, "orig", exc.__cause__)).__name__,
                    "frames": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                               for frame in traceback.extract_tb(exc.__traceback__) if "/code_mortis/" in frame.filename][-4:]})
                raise
            finally:
                with self.lock:
                    self.phases[name] = self.phases.get(name, 0) + (time.monotonic() - started) * 1000

        return call

    @contextmanager
    def installed(self):
        from code_mortis.core import analysis
        from code_mortis.reviews import assessment, planning, summary, verification
        from code_mortis.security_scans import service

        finish = analysis.finish_task

        def finished(*args, **kwargs):
            result = finish(*args, **kwargs)
            saved = kwargs.get("result") or {}
            output = saved.get("result") or {}
            if (
                result
                and saved.get("kind") in {"final", "validated"}
                and not any(output.get(field) for field in ("required_paths", "required_sources"))
            ):
                with self.lock:
                    if self.first_validated is None:
                        self.first_validated = (time.monotonic() - self.started) * 1000
            return result

        stage = service.stage
        active = {}

        def scan_stage(scan_id, name, status, **kwargs):
            if status == "running" and name not in active:
                active[name] = time.monotonic()
            elif status != "running" and name in active:
                self.phases[name] = (time.monotonic() - active.pop(name)) * 1000
            return stage(scan_id, name, status, **kwargs)

        with ExitStack() as stack:
            for module, name, phase in (
                (planning, "plan_review", "planning"),
                (assessment, "perform", "assessment"),
                (verification, "perform", "verification"),
                (verification, "mortis_verify", "verification_inference"),
                (summary, "generate", "summary"),
            ):
                stack.enter_context(patch.object(module, name, self.measure(phase, getattr(module, name))))
            stack.enter_context(patch.object(analysis, "finish_task", finished))
            stack.enter_context(patch.object(service, "stage", scan_stage))
            yield


class SyntheticGitHub:
    """An exact synthetic identity, not a general HTTP mock or network fallback."""

    def __init__(self, case, repo_id, full_name, root):
        self.case, self.repo_id, self.full_name, self.root = (
            case,
            repo_id,
            full_name,
            root,
        )
        self.calls = []

    def authorize(self, db, actor, name, **kwargs):
        from code_mortis.models import Installation, Membership, Repository

        repo = db.get(Repository, self.repo_id)
        require(
            name == self.full_name and actor and actor.enabled and db.get(Membership, actor.id),
            "Synthetic authorization identity mismatch",
        )
        require(
            repo
            and repo.full_name == name
            and repo.active
            and db.get(Installation, repo.installation_id).active,
            "Synthetic repository authorization revoked",
        )
        return {
            "id": self.repo_id,
            "default_branch": "head",
            "permissions": {"pull": True, "push": True},
        }

    def token(self, db, installation_id, **kwargs):
        require(installation_id == self.repo_id, "Synthetic installation mismatch")
        return TOKEN

    def threads(self, token, name, number):
        from code_mortis.core.db import transaction
        from code_mortis.models import AppConfig, Finding, PullRequest
        from code_mortis.reviews.service import marker
        from sqlalchemy import select

        require((token, name, number) == (TOKEN, self.full_name, 1), "Synthetic thread identity mismatch")
        with transaction() as db:
            bot = db.get(AppConfig, 1).github_slug + "[bot]"
            rows = list(db.scalars(select(Finding).join(PullRequest).where(PullRequest.repository_id == self.repo_id)))
            return [{
                "id": row.thread_id, "isResolved": False, "isOutdated": True, "resolvedBy": None,
                "comments": {"pageInfo": {"hasNextPage": False}, "nodes": [{
                    "databaseId": row.comment_id, "body": marker("finding", row.id),
                    "author": {"login": bot}, "updatedAt": "2026-11-08T00:00:00Z",
                }]},
            } for row in rows if row.thread_id]

    def request(self, method, path, token, **kwargs):
        from code_mortis.core import source
        from code_mortis.core.process import child_environment

        require(
            method == "GET" and token == TOKEN and not kwargs,
            "GitHub writes and non-synthetic requests are forbidden",
        )
        self.calls.append({"method": method, "path": path})
        base, head = self.case["base"]["commit"], self.case["head"]["commit"]
        prefix = f"/repos/{self.full_name}"
        if path == prefix:
            return {
                "id": self.repo_id,
                "default_branch": "head",
                "permissions": {"pull": True, "push": True},
            }
        if path == prefix + "/pulls/1":
            return {
                "number": 1,
                "state": "open",
                "head": {"sha": head, "ref": "head"},
                "base": {"sha": base, "repo": {"id": self.repo_id}},
            }
        if path == prefix + "/commits/head":
            return {"sha": head}
        if path == prefix + f"/compare/{base}...{head}":
            names = source.git(
                self.root,
                child_environment(),
                "diff",
                "--name-status",
                "--no-renames",
                base,
                head,
            ).splitlines()
            files = []
            for row in names:
                status, filename = row.split("\t")
                patch_text = source.git(
                    self.root,
                    child_environment(),
                    "--literal-pathspecs",
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--unified=3",
                    base,
                    head,
                    "--",
                    filename,
                )
                lines = patch_text.splitlines()
                start = next(
                    (i for i, line in enumerate(lines) if line.startswith("@@")),
                    len(lines),
                )
                patch_lines = lines[start:]
                files.append(
                    {
                        "filename": filename,
                        "status": {"A": "added", "D": "removed", "M": "modified"}[status],
                        "patch": "\n".join(patch_lines),
                        "additions": sum(line.startswith("+") for line in patch_lines),
                        "deletions": sum(line.startswith("-") for line in patch_lines),
                    }
                )
            return {
                "base_commit": {"sha": base},
                "merge_base_commit": {"sha": base},
                "files": files,
            }
        raise ValueError("Synthetic GitHub request is outside the frozen identity")

    @contextmanager
    def review_snapshot(self, name, number, base_sha, head_sha, token, stopped, **kwargs):
        from code_mortis.core import source
        from code_mortis.core.config import settings
        from code_mortis.core.process import child_environment

        require(
            (name, number, base_sha, head_sha, token)
            == (
                self.full_name,
                1,
                self.case["base"]["commit"],
                self.case["head"]["commit"],
                TOKEN,
            ),
            "Snapshot request identity mismatch",
        )
        require(not stopped(), "Evaluation stopped")
        with tempfile.TemporaryDirectory(prefix="eval-review-", dir=settings().work_dir) as temporary:
            repo = Path(temporary) / "repo"
            shutil.copytree(self.root, repo)
            env = child_environment()
            source.git(repo, env, "checkout", "--detach", "--quiet", base_sha, stopped=stopped)
            yield repo, env, env, self.case["merge_base_sha"]

    @contextmanager
    def security_snapshot(self, name, sha, previous_shas, token, stopped):
        from code_mortis.core.config import settings
        from code_mortis.core.process import child_environment
        from code_mortis.security_scans.engine import Snapshot

        require(
            (name, sha, previous_shas, token) == (self.full_name, self.case["head"]["commit"],
                [item["original_sha"] for item in self.case.get("historical_findings", [])], TOKEN),
            "Security snapshot identity mismatch",
        )
        require(not stopped(), "Evaluation stopped")
        with tempfile.TemporaryDirectory(prefix="eval-security-", dir=settings().work_dir) as temporary:
            item = Snapshot(Path(temporary), sha, child_environment(), stopped)
            shutil.copytree(self.root, item.git)
            item.populate()
            yield item

    @contextmanager
    def installed(self):
        from code_mortis.code_graph import store
        from code_mortis.core import source
        from code_mortis.integrations import comparison, github
        from code_mortis.security_scans import engine

        def read_token(db, installation_id, repository_id, **kwargs):
            require(repository_id == self.repo_id, "Graph repository identity mismatch")
            return self.token(db, installation_id, **kwargs)

        def acquire(repository_id, name, sha, snapshot_id, token, stopped):
            require((repository_id, name, token) == (self.repo_id, self.full_name, TOKEN),
                    "Graph source identity mismatch")
            require(sha in {self.case[side]["commit"] for side in ("base", "head")},
                    "Graph requested an unfrozen revision")
            require(not stopped(), "Evaluation graph stopped")
            target = store.directory(repository_id)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                # The fixed neutral export is local; preserve production transport restrictions elsewhere.
                store.git(self.root, "-c", "protocol.file.allow=always", "clone", "--bare", "--no-hardlinks", "--quiet", str(self.root), str(target))
            store.git(target, "update-ref", store.reference(snapshot_id), sha)

        comparison.cached.cache_clear()
        with ExitStack() as stack:
            for target, name, replacement in (
                (github, "request", self.request),
                (github, "authorize_repo", self.authorize),
                (github, "installation_token", self.token),
                (github, "repository_read_token", read_token),
                (store, "acquire", acquire),
                (github, "threads", self.threads),
                (source, "review_snapshot", self.review_snapshot),
                (engine, "snapshot", self.security_snapshot),
            ):
                stack.enter_context(patch.object(target, name, replacement))
            yield
        comparison.cached.cache_clear()


def create_attempt(manifest, case, arm, credentials, options, attempt_id):
    from code_mortis.core.db import Base, now, transaction
    from code_mortis.core.security import seal, unseal
    from code_mortis.models import (
        AppConfig,
        Connection,
        Finding,
        Installation,
        Job,
        Membership,
        Occurrence,
        PullRequest,
        Repository,
        ReviewRun,
        SecurityScan,
        User,
    )
    from code_mortis.reviews import assessment, context, pipeline, service
    from code_mortis.security_scans import engine as security_engine
    from code_mortis.security_scans.service import STAGES
    from sqlalchemy import select

    parallel = execution_profile(manifest) == PARALLEL_PROFILE
    require(case["workload"] != "pr" or not case.get("historical_findings") or options.get("auto_resolve") is True,
            "Historical verification requires frozen auto_resolve settings")

    # A fresh database or our exact sentinel only. No schema reset, truncation or migrations here.
    with transaction() as db:
        marker = db.get(AppConfig, 1)
        if marker:
            require(
                marker.github_slug == "eval-" + manifest["run_id"],
                "Disposable database belongs to another run",
            )
        else:
            for table in Base.metadata.sorted_tables:
                if table.name != "alembic_version":
                    require(
                        db.execute(select(table).limit(1)).first() is None,
                        "Evaluation refuses nonempty unmarked database",
                    )
            db.add(
                AppConfig(
                    id=1,
                    github_app_id="synthetic",
                    github_slug="eval-" + manifest["run_id"],
                    client_id="synthetic",
                    client_secret=seal("synthetic"),
                    private_key=seal("synthetic"),
                    webhook_secret=seal("synthetic"),
                )
            )
        require(
            not db.get(Job, attempt_id),
            "Attempt already exists; failed attempts are never overwritten",
        )
        identity = int(hashlib.sha256(attempt_id.encode()).hexdigest()[:14], 16)
        full_name = "mortis-eval/" + case["case_id"] + "-" + (attempt_id if parallel else attempt_id[:8])
        db.add(User(id=identity, login="eval-" + attempt_id, role="admin"))
        db.add(Membership(github_id=identity, login="eval-" + attempt_id, role="admin"))
        db.add(Installation(id=identity, account="mortis-eval"))
        selected = manifest["connection"]
        connection = db.get(Connection, selected["id"])
        if connection:
            require(
                all(getattr(connection, key) == value for key, value in selected.items()),
                "Frozen shared connection changed",
            )
            require(
                json.loads(unseal(connection.secret)) == credentials, "Frozen provider credential changed"
            )
        else:
            connection = Connection(**selected, secret=seal(json.dumps(credentials)))
            db.add(connection)
        db.flush()
        db.add(
            Repository(
                id=identity,
                installation_id=identity,
                full_name=full_name,
                enabled=True,
                private=False,
                connection_id=connection.id,
                settings=options,
            )
        )
        db.flush()
        config = {
            "analysis_engine": arm,
            "connection": service.connection_snapshot(connection),
            "settings": options,
            "assessment_policy": assessment.POLICY_VERSION,
            "task_contract": context.TASK_CONTRACT,
        }
        if parallel:
            config["pipeline_version"] = 2
        if case["workload"] == "pr":
            db.add(
                PullRequest(
                    id=attempt_id,
                    repository_id=identity,
                    number=1,
                    title="Synthetic proposed change",
                    author="synthetic",
                    url="https://example.invalid/evaluation",
                    base_sha=case["base"]["commit"],
                    head_sha=case["head"]["commit"],
                    head_ref="head",
                )
            )
            db.flush()
            db.add(
                ReviewRun(
                    id=attempt_id,
                    pr_id=attempt_id,
                    actor_id=identity,
                    trigger="manual",
                    engine=arm,
                    connection_id=connection.id,
                    dedup_key=attempt_id,
                    base_sha=case["base"]["commit"],
                    head_sha=case["head"]["commit"],
                    config=config,
                    summary={"status": "pending", "tokens": 0},
                    stages={stage: {"status": "pending", "tokens": 0} for stage in pipeline.STAGES} if parallel else {},
                    check_enabled=False,
                    check_pending=False,
                )
            )
            db.flush()
            if case.get("historical_findings"):
                historical_id = str(uuid4())
                db.add(ReviewRun(
                    id=historical_id, pr_id=attempt_id, actor_id=identity, trigger="manual",
                    dedup_key=historical_id, engine=arm, connection_id=connection.id,
                    base_sha=case["base"]["commit"], head_sha=case["base"]["commit"],
                    config=config, status="completed", publication="published", finished_at=now(),
                    check_enabled=False, check_pending=False,
                ))
                db.flush()
                for index, item in enumerate(case["historical_findings"]):
                    snapshot = item["snapshot"]
                    finding_id = str(uuid4())
                    db.add(Finding(
                        id=finding_id, pr_id=attempt_id, fingerprint=fingerprint(snapshot),
                        path=snapshot["path"], content=snapshot["content"], severity=snapshot["severity"],
                        category=snapshot["category"], start_line=snapshot["start_line"], end_line=snapshot["end_line"],
                        existing_code=snapshot["existing_code"], suggestion=snapshot["suggestion_code"],
                        thread_id="eval-" + finding_id, comment_id=index + 1,
                        last_seen_run_id=historical_id, publication_run_id=historical_id,
                    ))
                    db.flush()
                    db.add(Occurrence(run_id=historical_id, finding_id=finding_id, snapshot=snapshot))
        else:
            config = {
                "analysis_engine": arm,
                "connection": config["connection"],
                "limits": manifest["security_limits"],
                "policy": security_engine.POLICY,
                "task_contract": security_engine.TASK_CONTRACT,
                "rating_policy": "highest-unresolved-severity/v1",
                "trivy_version": "0.76.0",
                "language": options["language"],
            }
            db.add(
                SecurityScan(
                    id=attempt_id,
                    repository_id=identity,
                    actor_id=identity,
                    connection_id=connection.id,
                    request_key=attempt_id,
                    branch="head",
                    head_sha=case["head"]["commit"],
                    config=config,
                    stages={stage: {"status": "pending"} for stage in STAGES},
                    progress={"tasks": {}, "tokens": 0},
                )
            )
        db.flush()
        if case["workload"] == "security" and case.get("historical_findings"):
            from code_mortis.models import SecurityFinding, SecurityOccurrence
            historical_id = str(uuid4())
            db.add(SecurityScan(id=historical_id, repository_id=identity, actor_id=identity,
                connection_id=connection.id, request_key=historical_id, branch="head",
                head_sha=case["base"]["commit"], config=config, status="completed", finished_at=now()))
            db.flush()
            for item in case["historical_findings"]:
                snapshot = item["snapshot"]
                finding_id = str(uuid4())
                evidence = {**snapshot, "kind": "code", "source_sha": item["original_sha"],
                            "sources": [arm], "fingerprint": fingerprint(snapshot)}
                db.add(SecurityFinding(id=finding_id, repository_id=identity,
                    fingerprint=fingerprint(snapshot), state="open", kind="code", severity=snapshot["severity"],
                    title=snapshot["title"], path=snapshot["path"], first_scan_id=historical_id,
                    last_scan_id=historical_id, evidence=evidence))
                db.flush()
                db.add(SecurityOccurrence(scan_id=historical_id, finding_id=finding_id,
                    outcome="observed", snapshot=copy.deepcopy(evidence)))
        db.flush()
        key = "run_id" if case["workload"] == "pr" else "scan_id"
        db.add(
            Job(
                id=attempt_id,
                kind="review" if key == "run_id" else "security_scan",
                payload={key: attempt_id},
                status="queued" if parallel else "running",
                attempts=0 if parallel else 1,
                lease_until=None if parallel else now() + timedelta(seconds=manifest["case_deadline_seconds"] + 300),
            )
        )
    return identity, full_name


def row_data(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def scored_finding(row, occurrence):
    value = {"finding_id": row.id, **row_data(row)}
    snapshot = occurrence.snapshot
    value["body"] = value.get("content") or "\n".join(
        str(snapshot.get(key, "")) for key in ("explanation", "trigger", "impact", "remediation")
    )
    if snapshot.get("evidence"):
        value["evidence"] = snapshot["evidence"]
    if not value.get("start_line"):
        evidence = value.get("evidence", {})
        if isinstance(evidence, dict):
            value["start_line"] = evidence.get("start_line")
            value["end_line"] = evidence.get("end_line", evidence.get("start_line"))
    return value


def retained_result(case, attempt_id):
    from code_mortis.core.db import transaction
    from code_mortis.models import (
        AnalysisAttempt,
        AnalysisBudget,
        AnalysisPlan,
        AnalysisTask,
        Finding,
        FindingVerification,
        Job,
        Occurrence,
        ReviewCandidate,
        ReviewRun,
        SecurityFinding,
        SecurityOccurrence,
        SecurityScan,
    )
    from code_mortis.reviews.analytics import run_tokens
    from sqlalchemy import select

    with transaction() as db:
        run = db.get(ReviewRun if case["workload"] == "pr" else SecurityScan, attempt_id)
        scope = AnalysisPlan.run_id if case["workload"] == "pr" else AnalysisPlan.scan_id
        plans = list(db.scalars(select(AnalysisPlan).where(scope == attempt_id)))
        tasks = list(db.scalars(select(AnalysisTask).where(AnalysisTask.plan_id.in_([p.id for p in plans]))))
        attempts = list(
            db.scalars(select(AnalysisAttempt).where(AnalysisAttempt.task_id.in_([t.id for t in tasks])))
        )
        budgets = list(
            db.scalars(select(AnalysisBudget).where(AnalysisBudget.plan_id.in_([p.id for p in plans])))
        )
        if case["workload"] == "pr":
            verification_targets = [
                row_data(row)
                for row in db.scalars(
                    select(FindingVerification).where(FindingVerification.run_id == attempt_id)
                )
            ]
            occurrences = list(db.scalars(select(Occurrence).where(Occurrence.run_id == attempt_id)))
            findings = [
                scored_finding(db.get(Finding, occurrence.finding_id), occurrence)
                for occurrence in occurrences
            ]
            candidates = [
                row_data(row)
                for row in db.scalars(select(ReviewCandidate).where(ReviewCandidate.run_id == attempt_id))
            ]
            tokens = run_tokens(db, run)
            coverage = (run.report or {}).get("manifest", {}).get("coverage", {})
            validated = len(coverage.get("completed", []))
            if not coverage:
                validated = len((run.report or {}).get("files", [])) if run.status == "completed" else 0
        else:
            occurrences = list(
                db.scalars(select(SecurityOccurrence).where(SecurityOccurrence.scan_id == attempt_id))
            )
            findings = [
                scored_finding(db.get(SecurityFinding, occurrence.finding_id), occurrence)
                for occurrence in occurrences
            ]
            candidates = []
            verification_targets = None
            tokens = run.progress.get("tokens")
            stage = run.stages.get("analysis", {})
            validated = (
                stage.get("files", stage.get("completed", 0))
                if stage.get("status") == "completed"
                else stage.get("completed", 0)
            )
        return {
            "status": run.status,
            "error": run.error,
            "findings": findings,
            "coverage": {
                "assigned_units": case["expected_assigned_units"],
                "validated_units": validated,
            },
            "usage": {
                "requests": len(attempts) if attempts else None,
                "tokens": tokens,
                "input_tokens": None,
                "output_tokens": None,
                "cache_read_tokens": None,
                "cache_write_tokens": None,
                "reasoning_tokens": None,
                "cost_usd": None,
            },
            "report": run.report,
            "progress": run.progress,
            "stages": run.stages,
            "summary": run.summary if case["workload"] == "pr" else None,
            "candidates": candidates,
            "verification_targets": verification_targets,
            "verification_selection": {
                "observed": case["workload"] == "pr",
                "selected": len(verification_targets) if verification_targets is not None else None,
                "source": "FindingVerification.run_id"
                if case["workload"] == "pr"
                else "security_scan_stages",
            },
            "ledger": {
                "plans": [row_data(p) for p in plans],
                "tasks": [row_data(t) for t in tasks],
                "attempts": [row_data(a) for a in attempts],
                "budgets": [row_data(b) for b in budgets],
            },
            "job": row_data(db.get(Job, attempt_id)),
            "workflow_jobs": [row_data(row) for row in db.scalars(select(Job).where(
                (Job.payload["run_id"].as_string() == attempt_id)
                | (Job.payload["scan_id"].as_string() == attempt_id)
                | (Job.id == attempt_id)
                | (Job.payload["verification_id"].as_string().in_([row["id"] for row in verification_targets or []]))
            ))],
            "occurrences": [row_data(row) for row in occurrences],
        }


def queue_worker(bootstrap):
    """Run real prefork Celery deliveries with only acquisition/publication adapted."""
    validate_environment()
    from code_mortis import jobs
    from code_mortis.reviews import pipeline

    adapter = SyntheticGitHub(bootstrap["case"], bootstrap["repo_id"], bootstrap["full_name"], Path(bootstrap["root"]))
    execute_job = jobs.execute
    allowed = {"review", "security_scan", "finalize_review", *pipeline.KINDS}

    def execute(kind, payload):
        # Retain side-effect jobs in PostgreSQL without running publication or synchronization.
        if kind not in allowed:
            raise ValueError("Evaluation publication/synchronization is forbidden")
        require(payload.get("run_id", payload.get("scan_id")) == bootstrap["attempt_id"],
                "Queue delivery belongs to another evaluation attempt")
        measurements = Measurements(bootstrap["started"])
        request_start = len(adapter.calls)
        event = {"job_id": payload.get("_job_id"), "kind": kind,
                 "started_ms": (time.monotonic() - bootstrap["started"]) * 1000}
        scanner_guard = nullcontext(None)
        if kind == "security_scan":
            from scanner_preflight import guard_scanner

            scanner_guard = guard_scanner(bootstrap["scanner_snapshot"], Path(bootstrap["scanner_cache"]))
        scanner_state = None
        try:
            with scanner_guard as scanner_state, measurements.installed():
                return execute_job(kind, payload)
        finally:
            event.update(finished_ms=(time.monotonic() - bootstrap["started"]) * 1000,
                         first_validated_ms=measurements.first_validated, phases=measurements.phases,
                         github_requests=adapter.calls[request_start:], internal_errors=measurements.internal_errors)
            if scanner_state is not None:
                event["scanner_guard"] = scanner_state
            encoded = canonical(event) + b"\n"
            require(len(encoded) <= 4096, "Queue measurement event exceeds bound")
            descriptor = os.open(bootstrap["events"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, encoded)
            finally:
                os.close(descriptor)

    with adapter.installed(), patch.object(jobs, "execute", execute):
        jobs.celery.worker_main([
            "worker", "--pool=prefork", "--concurrency=4", "--loglevel=WARNING",
            "--queues=" + ("security" if bootstrap["case"]["workload"] == "security" else "reviews,verification,summaries,events"),
            "--without-gossip", "--without-mingle",
            "--hostname=eval-" + bootstrap["attempt_id"] + "@%h",
        ])


def dispatch_attempt(attempt_id):
    """Scope the production dispatcher to this arm; retained side effects never reach Redis."""
    from code_mortis import jobs
    from code_mortis.models import Job
    from code_mortis.reviews import pipeline
    from sqlalchemy import event
    from sqlalchemy.orm import Session, with_loader_criteria

    allowed = {"review", "security_scan", "finalize_review", *pipeline.KINDS}
    scope = Job.kind.in_(allowed) & (
        (Job.payload["run_id"].as_string() == attempt_id) | (Job.payload["scan_id"].as_string() == attempt_id)
    )

    def scoped(execution):
        if execution.is_select:
            execution.statement = execution.statement.options(with_loader_criteria(Job, scope, include_aliases=True))

    event.listen(Session, "do_orm_execute", scoped)
    try:
        jobs.dispatch()
    finally:
        event.remove(Session, "do_orm_execute", scoped)


def execute_queued(manifest, case, export, attempt_id, repo_id, full_name, measurements):
    from code_mortis.core.db import transaction
    from code_mortis.models import Job, ReviewRun, SecurityScan
    from code_mortis.reviews import pipeline
    from sqlalchemy import select

    allowed = {"review", "security_scan", "finalize_review", *pipeline.KINDS}
    with tempfile.TemporaryDirectory(prefix="eval-queue-") as temporary:
        folder = Path(temporary)
        bootstrap = {"case": case, "repo_id": repo_id, "full_name": full_name,
                     "root": str((export / "repo").resolve()), "attempt_id": attempt_id,
                     "started": measurements.started, "events": str(folder / "events.jsonl")}
        if case["workload"] == "security":
            from code_mortis.core.config import settings

            require(manifest.get("scanner_snapshot", {}).get("schema") == "mortis-engine-scanner-snapshot/v1",
                    "Queued security workflow requires its frozen scanner snapshot")
            bootstrap.update(scanner_snapshot=manifest["scanner_snapshot"], scanner_cache=str(settings().trivy_cache_dir))
        (folder / "bootstrap.json").write_bytes(canonical(bootstrap))
        with (folder / "worker.log").open("wb") as output:
            worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--queue-worker", str(folder / "bootstrap.json")],
                                      stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                next_dispatch = 0
                while True:
                    require(worker.poll() is None, "Evaluation Celery worker exited before terminal completion")
                    require((folder / "worker.log").stat().st_size <= 4 * 1024 * 1024,
                            "Evaluation Celery worker log exceeds its retained-output bound")
                    require(time.monotonic() - measurements.started < manifest["case_deadline_seconds"],
                            "Evaluation queued workflow exceeded its frozen deadline")
                    if time.monotonic() >= next_dispatch:
                        dispatch_attempt(attempt_id)
                        next_dispatch = time.monotonic() + QUEUE_PROFILE["dispatch_interval_seconds"]
                    with transaction() as db:
                        row = db.get(ReviewRun if case["workload"] == "pr" else SecurityScan, attempt_id)
                        pending = db.scalar(select(Job.id).where(
                            Job.kind.in_(allowed), Job.status.in_(["queued", "running"]),
                            (Job.payload["run_id"].as_string() == attempt_id)
                            | (Job.payload["scan_id"].as_string() == attempt_id),
                        ).limit(1))
                        if row.status not in {"queued", "running", "blocked"} and not pending:
                            terminal_ms = (time.monotonic() - measurements.started) * 1000
                            break
                    time.sleep(0.05)
            finally:
                try:
                    os.killpg(worker.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    worker.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=5)
                # A crashed Celery parent can leave children behind; never return with live inference.
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        events = []
        if (folder / "events.jsonl").exists():
            require((folder / "events.jsonl").stat().st_size <= 4 * 1024 * 1024, "Queue measurement log exceeds bound")
            events = [json.loads(line) for line in (folder / "events.jsonl").read_text().splitlines()]
        for event in events:
            first = event["first_validated_ms"]
            if first is not None and (measurements.first_validated is None or first < measurements.first_validated):
                measurements.first_validated = first
            for phase, duration in event["phases"].items():
                measurements.phases[phase] = measurements.phases.get(phase, 0) + duration
        return {"profile": PARALLEL_PROFILE, "queue": QUEUE_PROFILE, "events": events,
                "queue_to_terminal_ms": terminal_ms, "includes_worker_boot": True,
                "started_monotonic": measurements.started,
                "dispatch_scope": "current_attempt_workflow_jobs_only",
                "publication": "side_effect_jobs_fenced",
                "scanner_guard": next((event["scanner_guard"] for event in reversed(events) if "scanner_guard" in event), None)}


def execute(manifest, case, export, arm, credentials, options, attempt_id):
    from code_mortis.core.config import settings
    from code_mortis.core.db import now, transaction
    from code_mortis.models import Job, ReviewRun, SecurityScan
    from code_mortis.reviews import service
    from code_mortis.security_scans import service as security_service

    measurements = Measurements()
    repo_id, full_name = create_attempt(manifest, case, arm, credentials, options, attempt_id)
    queued = execution_profile(manifest) == PARALLEL_PROFILE
    graph_setup = None
    adapter = SyntheticGitHub(case, repo_id, full_name, export / "repo")
    if manifest.get("graph", "off") != "off":
        from code_mortis import jobs
        from code_mortis.code_graph import service as graphs
        from code_mortis.models import CodeGraphSnapshot, Connection, Repository, User
        from code_mortis.reviews import graph_context
        started = time.monotonic()
        with adapter.installed():
            graphs.configure(repo_id, repo_id, enabled=True)
            sha = case["head" if manifest["graph"] == "on" else "base"]["commit"]
            snapshot_id = graphs.enqueue_snapshot(repo_id, sha)
            with transaction() as db:
                graph_job = db.get(CodeGraphSnapshot, snapshot_id).job_id
            jobs.execute_job(graph_job)
            with transaction() as db:
                snapshot = db.get(CodeGraphSnapshot, snapshot_id)
                require(snapshot.status in graphs.USABLE, "Evaluation graph failed to index")
                if case["workload"] == "pr":
                    run = db.get(ReviewRun, attempt_id)
                    run.config = {**run.config, "code_graph": graph_context.configuration(db,
                        db.get(Repository, repo_id), db.get(Connection, run.connection_id), db.get(User, repo_id),
                        engine={"analysis_engine": arm})}
                graph_setup = {"snapshot_id": snapshot_id, "indexed_commit": snapshot.commit_sha,
                               "status": snapshot.status, "outside_queue_timing": True,
                               "enrichment": "production_pr_adapter" if case["workload"] == "pr" else "not_applicable_security_has_no_graph_enrichment",
                               "elapsed_ms": (time.monotonic() - started) * 1000}
    setup_ms = (time.monotonic() - measurements.started) * 1000
    if queued:
        measurements.started = time.monotonic()
    adapter = SyntheticGitHub(case, repo_id, full_name, export / "repo")
    settings().work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    outcomes = []
    queue_result = None
    with adapter.installed(), measurements.installed():
        try:
            if queued:
                queue_result = execute_queued(manifest, case, export, attempt_id, repo_id, full_name, measurements)
            elif case["workload"] == "pr":
                service.perform_review(attempt_id, attempt_id + ":1")
            else:
                security_service.perform(attempt_id, attempt_id + ":1")
        except Exception as exc:  # noqa: BLE001 - retain every failed evaluation attempt
            # Keep provider/source details in production's sanitized durable records only.
            outcomes.append({"kind": "execution_error", "error_type": type(exc).__name__})
            with transaction() as db:
                row = db.get(ReviewRun if case["workload"] == "pr" else SecurityScan, attempt_id)
                row.status, row.finished_at = "failed", now()
                row.error = (
                    "Evaluation workflow raised "
                    + type(exc).__name__
                    + "; inspect retained task diagnostics."
                )
        with transaction() as db:
            job = db.get(Job, attempt_id)
            row = db.get(ReviewRun if case["workload"] == "pr" else SecurityScan, attempt_id)
            if not queued:
                job.status = "completed" if row.status in {"completed", "partial", "skipped"} else "failed"
            # Evaluation adapters fence publication and resolution; queue profiles retain durable jobs.
        result = retained_result(case, attempt_id)
    elapsed = (time.monotonic() - measurements.started) * 1000
    result.update(
        {
            "timing_ms": {
                "terminal": queue_result["queue_to_terminal_ms"] if queue_result else elapsed,
                "first_validated": measurements.first_validated,
                **measurements.phases,
            },
            "outcomes": outcomes,
            "graph_setup": graph_setup,
            "github_adapter": {"publication": "forbidden", "requests": adapter.calls},
        }
    )
    if queued:
        result["execution_profile"] = PARALLEL_PROFILE
        result["timing_ms"]["fixture_setup"] = setup_ms
        result["queue_measurement"] = queue_result
        if queue_result:
            result["github_adapter"]["requests"] = [row for event in queue_result["events"] for row in event["github_requests"]]
        if queue_result is None:
            result["stop_pilot"] = True
    return result


def cgroup_metrics():
    root = Path("/sys/fs/cgroup")
    result = {}
    for name in ("cpu.stat", "memory.peak", "memory.current", "memory.events", "memory.stat", "memory.pressure", "pids.current", "pids.peak", "pids.events"):
        try:
            raw = (root / name).read_text()[:4096].strip()
            result[name] = raw if name.endswith(".pressure") else (
                int(raw)
                if raw.isdigit()
                else {key: int(value) for key, value in (line.split() for line in raw.splitlines())}
            )
        except (OSError, ValueError):
            result[name] = None
    return result


def captured_execute(manifest, case, export, arm, credentials, options, attempt_id, *, fake_provider=False):
    from capture import capture
    from code_mortis.core.db import now, transaction
    from code_mortis.models import Job, ReviewRun, SecurityScan
    from sqlalchemy import select

    declared = {**manifest["connection"], "options": provider_options(manifest, case)}
    credentials = copy.deepcopy(credentials)
    endpoint = urlsplit(declared["base_url"])
    if endpoint.hostname == "opencode.ai" and endpoint.path.rstrip("/") == "/zen/go/v1":
        credentials["extra_headers"] = {
            key: value
            for key, value in credentials["extra_headers"].items()
            if key.lower() not in {"user-agent", "x-opencode-session"}
        }
        credentials["extra_headers"].update(
            {"User-Agent": "code-mortis/0.1.0", "x-opencode-session": attempt_id}
        )
    with capture(declared, credentials, allow_insecure_loopback=fake_provider) as recorder:

        def retain_event(event):
            with transaction() as db:
                job = db.scalar(select(Job).where(Job.id == attempt_id).with_for_update())
                if execution_profile(manifest) == PARALLEL_PROFILE:
                    row = db.get(ReviewRun if case["workload"] == "pr" else SecurityScan, attempt_id)
                    require(job and row and row.status in {"queued", "running"} and not row.cancel_requested,
                            "Provider capture no longer owns the live queued evaluation workflow")
                else:
                    require(
                        job and job.status == "running" and job.attempts == 1 and job.lease_until > now(),
                        "Provider capture no longer owns the live evaluation job",
                    )
                events = {row["sequence"]: row for row in job.payload.get("provider_events", [])}
                require(
                    event["sequence"] in events or len(events) < MAX_PROVIDER_EVENTS,
                    "Evaluation provider event bound reached; further dispatch is forbidden",
                )
                events[event["sequence"]] = event
                job.payload = {**job.payload, "provider_events": [events[key] for key in sorted(events)]}

        recorder.on_event = retain_event
        effective = copy.deepcopy(manifest)
        # A private per-attempt row prevents credentials/session/history reuse across paired arms.
        effective["connection"] = {**declared, "id": attempt_id, "base_url": recorder.base_url}
        scanner_guard = nullcontext(None)
        if case["workload"] == "security" and execution_profile(manifest) != PARALLEL_PROFILE:
            from scanner_preflight import guard_scanner

            require(
                manifest.get("scanner_snapshot", {}).get("schema") == "mortis-engine-scanner-snapshot/v1",
                "Security evaluation requires its frozen scanner snapshot",
            )
            scanner_guard = guard_scanner(manifest["scanner_snapshot"], Path("/scanner-cache"))
        with scanner_guard as scanner_state:
            result = execute(effective, case, export, arm, credentials, options, attempt_id)
        if case["workload"] == "security" and execution_profile(manifest) == PARALLEL_PROFILE:
            scanner_state = (result.get("queue_measurement") or {}).get("scanner_guard") or {
                "validated": False, "error": "MissingWorkerScannerGuard",
            }
        scanner_failed = scanner_state is not None and (
            not scanner_state["validated"] or scanner_state["error"]
        )
        if scanner_state is not None:
            result["scanner_guard"] = scanner_state
        if scanner_failed:
            result["outcomes"].append(
                {"kind": "scanner_preflight_failure", "error_type": scanner_state["error"]}
            )
        events = list(recorder.events)
        result["provider_events"] = events
        result["transport"] = {
            "provider_mode": "controlled_synthetic_http" if fake_provider else "live",
            "declared_connection": declared,
            "effective_base_url": recorder.base_url,
            "session_scope": "attempt",
            "blocked_reason": recorder.blocked_reason,
            "event_limit": MAX_PROVIDER_EVENTS,
        }
        if execution_profile(manifest) == PARALLEL_PROFILE:
            result["transport"]["physical_concurrency"] = {"limit": 4, "peak": recorder._peak}
        keys = (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "reasoning_tokens",
        )
        result["workflow_reported_tokens"] = result["usage"]["tokens"]
        result["usage"] = {
            "requests": sum(bool(row.get("forwarded")) for row in events),
            "tokens": None,
            "cost_usd": None,
            **{key: None for key in keys},
        }
        for key in (*keys, "total_tokens"):
            values = [row.get(key) for row in events if row.get("forwarded")]
            result["usage"]["tokens" if key == "total_tokens" else key] = (
                sum(values) if all(type(value) is int and value >= 0 for value in values) else None
            )
        if recorder.blocked_reason:
            result["outcomes"].append(
                {"kind": "provider_dispatch_stopped", "reason": recorder.blocked_reason}
            )
            result["stop_pilot"] = True
        else:
            result["stop_pilot"] = result.get("stop_pilot", False) or bool(scanner_failed) or any(
                row.get("consumption_unknown") for row in events
            )
        result["timing_ms"]["provider_sum"] = sum(
            row.get("elapsed_ms", 0) for row in events if row.get("forwarded")
        )
        result["cgroup"] = cgroup_metrics()
        return result


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--queue-worker":
        queue_worker(json.loads(Path(sys.argv[2]).read_text()))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--arm", choices=["ocr", "mortis"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fake-provider", action="store_true")
    args = parser.parse_args()
    require(str(args.output) == "-" or not args.output.exists(), "Refusing to overwrite a retained attempt")
    manifest = json.loads(args.manifest.read_text())
    require(
        hashlib.sha256(args.manifest.read_bytes()).hexdigest() == os.environ.get("CM_EVAL_MANIFEST_SHA256"),
        "Worker manifest hash mismatch",
    )
    require(
        not (args.dry_run and args.fake_provider),
        "Choose either offline validation or fake-provider execution",
    )
    case = validate_manifest(
        manifest, args.case.name, args.arm, live=not (args.dry_run or args.fake_provider)
    )
    if args.fake_provider:
        endpoint = urlsplit(manifest["connection"]["base_url"])
        require(
            endpoint.hostname in {"127.0.0.1", "::1"}
            and manifest.get("authorization") == "synthetic_provider_check",
            "Fake-provider execution requires an explicit loopback-only synthetic manifest",
        )
    validate_environment()
    from code_mortis.schemas.common import RepoSettings

    options = RepoSettings.model_validate({**manifest["settings"], "analysis_engine": args.arm}).model_dump()
    context = checked_case(args.case, case, options)
    provider_options(manifest, case)
    if case["workload"] == "pr":
        options["background"] = context["context"]
    require(
        case["identity"]["settings_sha256"]
        == fingerprint(
            {
                "settings": {key: value for key, value in options.items() if key != "analysis_engine"},
                "security_limits": manifest["security_limits"],
            }
        ),
        "Effective per-case settings identity mismatch",
    )
    result = {
        "schema": "mortis-engine-eval-attempt/v1",
        "attempt_id": str(uuid4()),
        "run_id": manifest["run_id"],
        "corpus_digest": manifest["corpus_digest"],
        "protocol_sha256": manifest["protocol_sha256"],
        "case_id": case["case_id"],
        "workload": case["workload"],
        "arm": args.arm,
        "repetition": manifest["repetition"],
        "graph": manifest["graph"],
        "cache": manifest["cache"],
        "case_digest": case["case_digest"],
        "identity": case["identity"],
        "manifest_sha256": fingerprint(manifest),
    }
    if args.dry_run:
        result.update({"status": "validated_offline", "external_model_requests": 0})
    else:
        result.update(
            captured_execute(
                manifest,
                case,
                args.case,
                args.arm,
                read_credentials(),
                options,
                result["attempt_id"],
                fake_provider=args.fake_provider,
            )
        )
    if str(args.output) == "-":
        print(json.dumps(result, ensure_ascii=False, default=lambda value: value.isoformat()))
        return
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with args.output.open("x") as output:
        json.dump(
            result,
            output,
            ensure_ascii=False,
            indent=2,
            default=lambda value: value.isoformat(),
        )
        output.write("\n")
    print(
        json.dumps(
            {
                "attempt_id": result["attempt_id"],
                "case_id": case["case_id"],
                "arm": args.arm,
                "status": result["status"],
            }
        )
    )


if __name__ == "__main__":
    raise SystemExit("This historical OCR/native evaluation is retired. Saved evidence and offline scoring remain available; new execution is disabled.")
