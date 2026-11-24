# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Check lexical plans without reading or writing any filesystem path."""

import posixpath


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["downloads.py"], "downloads.py", "exec"), scope)
    plan = scope["download_plan"]
    principal = {"authenticated": True, "tenant_id": "tenant-a"}
    root = "/srv/exports/tenant-a/"
    if plan(principal, "reports/annual.csv") != root + "reports/annual.csv":
        return False
    for name in (
        "../tenant-b/report.csv",
        "/srv/private/config.json",
        "reports/../../tenant-b/report.csv",
    ):
        try:
            result = posixpath.normpath(plan(principal, name))
        except ValueError:
            continue
        if not result.startswith(root):
            return False
    return True
