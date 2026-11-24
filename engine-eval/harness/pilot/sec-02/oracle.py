# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
"""Verify tenant and authentication boundaries with ordinary mappings."""


def check(files: dict[str, str]) -> bool:
    scope = {}
    exec(compile(files["invoices.py"], "invoices.py", "exec"), scope)
    read = scope["get_invoice"]
    alice = {"authenticated": True, "tenant_id": "tenant-a"}
    bob = {"authenticated": True, "tenant_id": "tenant-b"}
    if (
        read(alice, "inv-a")["total_cents"] != 1700
        or read(bob, "inv-b")["total_cents"] != 9200
    ):
        return False
    if read(alice, "inv-b") is not None or read(bob, "inv-a") is not None:
        return False
    if read(alice, "missing") is not None:
        return False
    try:
        read({"authenticated": False}, "inv-a")
    except PermissionError:
        return True
    return False
