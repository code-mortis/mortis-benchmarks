# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Exercise literal search against an in-memory SQLite database."""


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["catalog.py"], "catalog.py", "exec"), scope)
    search = scope["search_catalog"]
    return (
        search("public widget") == [(1, "public widget")]
        and search("internal export") == []
        and search("' OR 1=1 --") == []
        and search("widget' UNION SELECT 9, 'injected' --") == []
    )
