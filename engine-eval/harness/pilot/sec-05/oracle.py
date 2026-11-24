# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Inspect rendered policy using JSON only, without deployment APIs."""

import json


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["storage.py"], "storage.py", "exec"), scope)
    render = scope["render_policy"]
    if render(files["bucket.json"])["read_principals"] != ["invoice-service"]:
        return False
    explicit = json.loads(files["bucket.json"])
    explicit["public_read"] = True
    try:
        policy = render(json.dumps(explicit))
    except ValueError:
        policy = {"read_principals": ["invoice-service"]}
    if "*" in policy["read_principals"]:
        return False
    public = {
        "bucket": "fixture-assets",
        "classification": "public",
        "public_read": True,
    }
    return render(json.dumps(public))["read_principals"] == ["*"]
