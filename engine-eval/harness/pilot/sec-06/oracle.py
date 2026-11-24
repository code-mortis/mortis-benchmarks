# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Negative control with real parameterized SQLite and tenant checks."""


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["orders.py"], "orders.py", "exec"), scope)
    search = scope["search_orders"]
    alice = {"authenticated": True, "tenant_id": "tenant-a"}
    bob = {"authenticated": True, "tenant_id": "tenant-b"}
    if search(alice, "shared") != [(1100,)] or search(bob, "shared") != [(7700,)]:
        return False
    if search(alice, "' OR 1=1 --") != []:
        return False
    for principal in (
        {"authenticated": False, "tenant_id": "tenant-a"},
        {"authenticated": True, "tenant_id": "tenant-c"},
    ):
        try:
            search(principal, "shared")
        except PermissionError:
            continue
        return False
    return True
