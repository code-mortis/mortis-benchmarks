"""Exercise affected-caller discovery through the connection-free review preview."""

import subprocess
from pathlib import Path

from mortis_engine.review import preview_local

PYTHON_DEPENDENCY = "def apply(amount):\n    return amount\n"
SHELL_DEPENDENCY = "#!/bin/sh\nexit 0\n"
SHELL_PATH = "scripts/legacy task.sh"


def _python_deletion(target, caller, other_files=None):
    return {
        "target": target,
        "base_files": {
            target: PYTHON_DEPENDENCY,
            "jobs/run.py": caller,
            **(other_files or {}),
        },
    }


def _shell_deletion(caller):
    return {
        "target": SHELL_PATH,
        "base_files": {SHELL_PATH: SHELL_DEPENDENCY, "run.sh": caller},
    }


def _rename_case(aliased, stale):
    previous_name = "quote" if aliased else "apply"
    alias = " as quote" if aliased else ""
    future_call = f"{previous_name}(20)" if stale else "regular_order()"
    separator = "\n" * 8
    return {
        "target": "src/shop/old.py",
        "replacement": "src/shop/new.py",
        "base_files": {
            "src/shop/__init__.py": "",
            "src/shop/old.py": PYTHON_DEPENDENCY,
            "src/shop/orders.py": (
                f"from .old import apply{alias}\n\n"
                f"def regular_order():\n    return {previous_name}(10)\n"
                f"{separator}def back_order():\n    return {previous_name}(20)\n"
            ),
        },
        "updates": {
            "src/shop/orders.py": (
                "def regular_order():\n    from .new import apply as update_total\n"
                "    return update_total(10)\n"
                f"{separator}def back_order():\n    return {future_call}\n"
            ),
        },
    }


CASES = {
    "caller-delete-src-single-module": _python_deletion("src/legacy.py", "from legacy import apply\napply(10)\n"),
    "caller-delete-src-package-module": _python_deletion(
        "src/shop/legacy.py", "from shop.legacy import apply\napply(10)\n", {"src/shop/__init__.py": ""}
    ),
    "caller-delete-unrelated-python-package": _python_deletion(
        "src/shop/legacy.py",
        "from elsewhere.legacy import apply\napply(10)\n",
        {"src/shop/__init__.py": "", "src/elsewhere/__init__.py": "", "src/elsewhere/legacy.py": PYTHON_DEPENDENCY},
    ),
    "caller-delete-unrelated-top-level-module": _python_deletion(
        "src/shop/legacy.py",
        "from legacy import apply\napply(10)\n",
        {"src/shop/__init__.py": "", "src/legacy.py": PYTHON_DEPENDENCY},
    ),
    "caller-delete-distant-symbol-alias": _python_deletion(
        "src/shop/legacy.py", "from shop.legacy import apply as quote\n" + "\n" * 8 + "quote(10)\n",
        {"src/shop/__init__.py": ""},
    ),
    "caller-delete-distant-declared-symbol": _python_deletion(
        "src/shop/legacy.py", "from shop.legacy import apply\n" + "\n" * 8 + "apply(10)\n",
        {"src/shop/__init__.py": ""},
    ),
    "caller-delete-escaped-shell-path": _shell_deletion(r"./scripts/legacy\ task.sh" + "\n"),
    "caller-delete-quoted-shell-path": _shell_deletion("'./scripts/legacy task.sh'\n"),
    "caller-rename-stale-symbol-alias": _rename_case(aliased=True, stale=True),
    "caller-rename-stale-declared-symbol": _rename_case(aliased=False, stale=True),
    "caller-rename-updated-symbol-alias": _rename_case(aliased=True, stale=False),
}


def _git(repo, *arguments):
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()


def _write(repo, files):
    for relative, text in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))


def _commit(repo, message):
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def observe(case_id, spec, root: Path):
    """Create one synthetic history and record preview trigger and site outcomes."""
    _git(root, "init", "--quiet", "--initial-branch=main", "--object-format=sha1", "--template=")
    _write(root, spec["base_files"])
    if spec["target"] == SHELL_PATH:
        (root / SHELL_PATH).chmod(0o755)
    base = _commit(root, "Base")
    original = root / spec["target"]
    if replacement := spec.get("replacement"):
        original.rename(root / replacement)
    else:
        original.unlink()
    _write(root, spec.get("updates", {}))
    head = _commit(root, "Move or remove dependency")

    result = preview_local(root, mode="commits", base=base, head=head)
    scope = result.get("affected_callers", {})
    return {
        "revisions": {"base": base, "head": head},
        "affected_status": scope.get("status"),
        "limits": scope.get("limits_reached"),
        "triggers": [[row["path"], row["new_path"]] for row in scope.get("triggers", ())],
        "sites": [
            [row["path"], row["start_line"], row["end_line"], row["status"], row["triggers"]]
            for row in scope.get("sites", ())
        ],
        "unit_ranges": [[row["path"], row["start_line"], row["end_line"]] for row in result["units"]],
        "scanned_files": scope.get("scanned_files"),
        "scanned_bytes": scope.get("scanned_bytes"),
        "preview_errors": result["errors"],
    }
