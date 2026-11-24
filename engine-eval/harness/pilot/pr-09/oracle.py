# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["src/auth.py"], "src/auth.py", "exec"), namespace)
    apply = namespace["apply_reset"]

    def setup():
        return (
            {"link-a": {"account": "alice", "expires_at": 200, "used": False}},
            {"alice": {"login_hash": "a" * 20}, "bob": {"login_hash": "b" * 20}},
        )

    resets, users = setup()
    if apply(
        {"token": "link-a", "account": "bob", "new_hash": "x" * 20}, resets, users, 100
    ):
        return False
    if users["bob"]["login_hash"] != "b" * 20 or resets["link-a"]["used"]:
        return False
    resets, users = setup()
    if not apply({"token": "link-a", "new_hash": "x" * 20}, resets, users, 100):
        return False
    if (
        users["alice"]["login_hash"] != "x" * 20
        or users["bob"]["login_hash"] != "b" * 20
    ):
        return False
    if apply({"token": "link-a", "new_hash": "y" * 20}, resets, users, 100):
        return False
    resets, users = setup()
    return (
        not apply({"token": "link-a", "new_hash": "x" * 20}, resets, users, 200)
        and not resets["link-a"]["used"]
    )
