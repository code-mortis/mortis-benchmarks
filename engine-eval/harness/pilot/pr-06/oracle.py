# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["members.py"], "members.py", "exec"), namespace)
    rows = [
        {"name": " bob "},
        {"name": " ALICE "},
        {"name": "alice"},
        {"name": "Hidden", "archived": True},
        {"name": "  "},
        {"name": " Ada  Example "},
    ]
    names = namespace["visible_names"]
    return (
        names(iter(rows)) == ["Ada Example", "ALICE", "alice", "bob"]
        and names(iter([])) == []
        and namespace["member_count"](iter(rows)) == 4
        and rows[0]["name"] == " bob "
    )
