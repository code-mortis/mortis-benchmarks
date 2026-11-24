# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Structural freshness contract, not vulnerability detection or a Trivy run."""

import json


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["coverage.py"], "coverage.py", "exec"), scope)
    lock = json.loads(files["package-lock.json"])
    if lock["lockfileVersion"] != 3 or not isinstance(lock["packages"], dict):
        return False
    raw = files["scanner-report.json"]
    report = json.loads(raw)
    age = report.get("advisory_age_hours")
    complete = (
        type(age) is int
        and 0 <= age <= 24
        and all(
            report["scanners"].get(name) == "completed"
            for name in ("vulnerability", "misconfiguration", "secret")
        )
    )
    result = scope["coverage_outcome"](raw)
    return result == {
        "status": "completed" if complete else "incomplete",
        "clean": complete and not report.get("findings", []),
    }
