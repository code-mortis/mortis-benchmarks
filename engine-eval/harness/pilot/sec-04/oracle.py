# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Validate destination planning only; no archive is extracted."""

import posixpath


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["restore.py"], "restore.py", "exec"), scope)
    plan = scope["restore_plan"]
    if plan([{"kind": "file", "name": "data/users.json"}]) != [
        "/srv/imports/current/data/users.json"
    ]:
        return False
    for name in (
        "../../service/settings.json",
        "/srv/service/settings.json",
        "data/../../../service/settings.json",
    ):
        try:
            paths = plan([{"kind": "file", "name": name}])
        except ValueError:
            continue
        if any(
            not posixpath.normpath(path).startswith("/srv/imports/current/")
            for path in paths
        ):
            return False
    try:
        plan([{"kind": "symlink", "name": "data/link"}])
    except ValueError:
        return True
    return False
