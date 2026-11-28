"""Exercise Git index and working-tree edge cases through the public preview API."""

import hashlib
import stat
import subprocess
from itertools import batched
from pathlib import Path

from mortis_engine.review import preview_local

CASES = {
    "snapshot-file-to-directory-worktree": {"fixture": "file-to-directory", "mode": "worktree"},
    "snapshot-file-to-directory-staged": {"fixture": "file-to-directory", "mode": "staged"},
    "snapshot-directory-to-file-worktree": {"fixture": "directory-to-file", "mode": "worktree"},
    "snapshot-directory-to-file-staged": {"fixture": "directory-to-file", "mode": "staged"},
    "snapshot-intent-to-add-staged": {"fixture": "intent-to-add", "mode": "staged"},
    "snapshot-intent-to-add-worktree": {"fixture": "intent-to-add", "mode": "worktree"},
    "snapshot-empty-file-staged": {"fixture": "empty-file", "mode": "staged"},
    "snapshot-crlf-auto-text": {"fixture": "crlf-auto-text", "mode": "worktree"},
    "snapshot-crlf-explicit-text": {"fixture": "crlf-explicit-text", "mode": "worktree"},
    "snapshot-literal-unicode-path": {"fixture": "literal-unicode-path", "mode": "worktree"},
}


def git(repository: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "--no-optional-locks", "--literal-pathspecs", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repository, check=True, capture_output=True, timeout=10,
    ).stdout


def write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def prepare(repository: Path, fixture: str, mode: str) -> None:
    git(repository, "init", "-qb", "main", "--object-format=sha1", "--template=")
    git(repository, "config", "core.autocrlf", "false")
    git(repository, "config", "user.name", "Benchmark fixture")
    git(repository, "config", "user.email", "fixture@example.invalid")
    write(repository / "app.py", b"value = 1\n")
    if fixture == "file-to-directory":
        write(repository / "component.py", b"old = 1\n")
    elif fixture == "directory-to-file":
        write(repository / "component.py" / "value.py", b"old = 1\n")
    elif fixture.startswith("crlf-"):
        text = b"text=auto" if fixture == "crlf-auto-text" else b"text"
        write(repository / ".gitattributes", b"*.py " + text + b" eol=crlf\n")
    elif fixture == "literal-unicode-path":
        write(repository / "café [west].py", b"value = 1\n")
    git(repository, "add", "-A")
    git(repository, "commit", "--no-gpg-sign", "-qm", "base")

    if fixture == "file-to-directory":
        (repository / "component.py").unlink()
        write(repository / "component.py" / "value.py", b"new = 2\n")
        write(repository / "app.py", b"value = 2\n")
    elif fixture == "directory-to-file":
        (repository / "component.py" / "value.py").unlink()
        (repository / "component.py").rmdir()
        write(repository / "component.py", b"new = 2\n")
        write(repository / "app.py", b"value = 2\n")
    elif fixture == "intent-to-add":
        write(repository / "draft.py", b"draft = 2\n")
        git(repository, "add", "-N", "--", "draft.py")
    elif fixture == "empty-file":
        write(repository / "draft.py", b"")
        git(repository, "add", "--", "draft.py")
    elif fixture.startswith("crlf-"):
        app = repository / "app.py"
        app.unlink()
        git(repository, "restore", "--worktree", "--", "app.py")
        if app.read_bytes() != b"value = 1\r\n":
            raise RuntimeError("Fixture requires Git to check out CRLF bytes.")
    elif fixture == "literal-unicode-path":
        write(repository / "café [west].py", b"value = 2\n")

    if fixture in {"file-to-directory", "directory-to-file"} and mode == "staged":
        git(repository, "add", "-A")


def fingerprint(repository: Path) -> dict:
    return {
        path.relative_to(repository).as_posix(): (
            stat.S_IMODE(path.stat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in repository.rglob("*")
        if path.is_file()
    }


def observe(case_id: str, spec: dict, root: Path) -> dict:
    del case_id
    fixture, mode = spec["fixture"], spec["mode"]
    prepare(root, fixture, mode)
    staged = git(root, "diff", "--cached", "--name-status", "--no-renames", "-z").decode("utf-8")
    git_reference = [list(pair) for pair in batched(staged.split("\0")[:-1], 2, strict=True)]
    before = fingerprint(root)
    try:
        report = preview_local(root, mode=mode)
    except ValueError as error:
        result = {"exception": str(error), "selected": [], "deleted": [], "errors": [], "units": 0}
    else:
        result = {
            "exception": None,
            "selected": [
                [row["path"], row["status"], row["source_bytes"]] for row in report["selected_files"]
            ],
            "deleted": sorted(row["path"] for row in report["excluded_files"] if row["reason"] == "deleted"),
            "errors": report["errors"],
            "units": report["totals"]["units"],
        }
    result.update(repository_unchanged=before == fingerprint(root), git_staged=git_reference)
    if fixture.startswith("crlf-"):
        result["git_clean"] = git(root, "status", "--porcelain", "-z") == b""
    return result
