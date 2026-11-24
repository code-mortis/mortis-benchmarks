# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["src/results.py"], "src/results.py", "exec"), namespace)
    aggregate = namespace["aggregate_results"]
    good = {"path": "a.py", "status": "completed", "comments": []}
    if aggregate(["a.py"], [good]) != {
        "state": "clean",
        "completed": 1,
        "findings": [],
    }:
        return False
    for result in (
        {"path": "a.py", "status": "failed", "comments": []},
        {"path": "a.py", "status": "completed", "comments": {}},
        {"path": "a.py", "status": "completed", "comments": None},
    ):
        if aggregate(["a.py"], [result])["state"] != "incomplete":
            return False
    if aggregate(["a.py", "b.py"], [good])["state"] != "incomplete":
        return False
    if aggregate(["a.py"], [good, good])["state"] != "incomplete":
        return False
    comment = {"message": "Check index bounds"}
    observed = aggregate(
        ["a.py"], [{"path": "a.py", "status": "completed", "comments": [comment]}]
    )
    return observed["state"] == "findings" and observed["findings"] == [comment]
