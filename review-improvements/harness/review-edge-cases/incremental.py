"""Check caller assignments across successive public API review runs."""

import json
import os
import runpy
from pathlib import Path
from unittest.mock import patch

from mortis_engine import gateway
from mortis_engine.review import review_commits
from mortis_engine.schemas import Response, Usage

DEPENDENCY = "billing.py"
CALLER = "checkout.py"
UNRELATED = "inventory.py"

CASES = {
    "incremental-async-to-sync": {
        "before": "async def total(amount):\n    return amount\n",
        "after": "def total(amount):\n    return amount\n",
        "caller": "from billing import total\n\nasync def quote():\n    return await total(10)\n",
    },
    "incremental-async-body-only-control": {
        "before": "async def total(amount):\n    return amount\n",
        "after": "async def total(amount):\n    return round(amount)\n",
        "caller": "from billing import total\n\nasync def quote():\n    return await total(10)\n",
    },
    "incremental-positional-only-reorder": {
        "before": "def total(amount, currency, /):\n    return amount + len(currency)\n",
        "after": "def total(currency, amount, /):\n    return amount + len(currency)\n",
        "caller": "from billing import total\n\nprice = total(10, 'USD')\n",
    },
    "incremental-required-positional-only-guard": {
        "before": "def total(amount, /):\n    return amount\n",
        "after": "def total(amount, currency, /):\n    return amount + len(currency)\n",
        "caller": "from billing import total\n\nprice = total(10)\n",
    },
    "incremental-keyword-captured-from-kwargs": {
        "before": "def total(amount, **metadata):\n    return amount, metadata\n",
        "after": "def total(amount, *, quantity=1, **metadata):\n    return amount, metadata\n",
        "caller": "from billing import total\n\nprice, metadata = total(10, quantity=2)\nunits = metadata['quantity']\n",
    },
    "incremental-optional-keyword-control": {
        "before": "def total(amount):\n    return amount\n",
        "after": "def total(amount, *, quantity=1):\n    return amount * quantity\n",
        "caller": "from billing import total\n\nprice = total(10)\n",
    },
}


def _git_helpers():
    helper = Path(__file__).resolve().parent.parent / "python-callers" / "run.py"
    if not helper.is_file():
        helper = Path(os.environ["MORTIS_BENCHMARKS"]) / "review-improvements/harness/python-callers/run.py"
    return runpy.run_path(str(helper))


_git = _git_helpers()
commit, git, write_files = (_git[name] for name in ("commit", "git", "write_files"))


def _assigned_paths(report, status):
    return sorted(row["path"] for row in report["coverage"].get(status, []))


def observe(case_id, spec, root):
    repo = root / "repo"
    repo.mkdir()
    env = dict(os.environ)
    git(repo, env, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    write_files(repo, {DEPENDENCY: spec["before"], CALLER: "price = 0\n", UNRELATED: "items = 0\n"})
    base_sha = commit(repo, env, "Base")
    git(repo, env, "switch", "-qc", "topic")
    write_files(repo, {CALLER: spec["caller"], UNRELATED: "items = 1\n"})
    previous_sha = commit(repo, env, "Review checkout and inventory")

    assignments = []

    async def scripted_response(connection, credentials, request, **kwargs):
        if credentials != {}:
            raise AssertionError("The offline replay received unexpected credentials.")
        if "narrative" in request.output_schema["properties"]:
            output = {"narrative": "Synthetic summary", "groups": []}
        else:
            content = request.messages[0].content
            payload = json.loads(content.split("\n\n", 2)[1] if content.startswith("# ") else content)
            units = payload["assigned_units"]
            assignments.extend(unit["path"] for unit in units)
            output = {
                "task_key": payload["task_key"],
                "completed_units": [unit["key"] for unit in units],
                "findings": [],
            }
        return Response(output=output, usage=Usage(total_tokens=3))

    options = {
        "base": "main",
        "head": "topic",
        "connection": {"provider": "custom", "protocol": "openai", "model": "fixture", "options": {}},
        "get_credentials": dict,
        "concurrency": 1,
        "overrides": {"incremental": True},
    }
    with patch.object(gateway, "send", scripted_response):
        first = review_commits(repo, **options)
        first_assigned = sorted(assignments)
        assignments.clear()
        write_files(repo, {DEPENDENCY: spec["after"]})
        head_sha = commit(repo, env, "Change billing contract")
        second = review_commits(repo, **options)

    first_comparison = first.get("comparison", {})
    second_comparison = second.get("comparison", {})
    return {
        "revisions": {"base": base_sha, "previous": previous_sha, "head": head_sha},
        "statuses": [first["status"], first["workflow_status"], second["status"], second["workflow_status"]],
        "schema_versions": [first["schema_version"], second["schema_version"]],
        "errors": sum(len(report["errors"]) + len(report.get("stage_errors", [])) for report in (first, second)),
        "pinned_revisions_match": (
            first["base_sha"] == second["base_sha"] == base_sha
            and first["head_sha"] == previous_sha
            and second["head_sha"] == head_sha
        ),
        "baseline_linked": (
            second_comparison.get("baseline_run_id") == first["run_id"]
            and second_comparison.get("baseline_head_sha") == previous_sha
        ),
        "first_comparison_reason": first_comparison.get("reason"),
        "first_assigned_paths": first_assigned,
        "strategy": second_comparison.get("strategy"),
        "reason": second_comparison.get("reason"),
        "assigned_paths": sorted(assignments),
        "completed_paths": _assigned_paths(second, "completed"),
        "reused_paths": _assigned_paths(second, "reused"),
    }
