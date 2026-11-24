# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["review_gate.py"], "review_gate.py", "exec"), namespace)
    queue = namespace["queue_review"]
    paths, dispatched = ["one.py", "two.py"], []
    equal = queue(paths, 2, dispatched.append)
    if equal["status"] != "ready" or dispatched != paths:
        return False
    dispatched.clear()
    over = queue(paths, 1, dispatched.append)
    if over != {"status": "skipped", "selected": paths, "assigned": []} or dispatched:
        return False
    unlimited = queue(paths, None, dispatched.append)
    return unlimited["status"] == "ready" and dispatched == paths
