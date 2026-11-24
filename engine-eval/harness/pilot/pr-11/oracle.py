# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["src/report.py"], "src/report.py", "exec"), namespace)
    response = namespace["response"]
    expected = {"version": 2, "counts": {"completed": 5, "failed": 1}, "total": 6}
    if (
        response(
            [
                {"state": "completed", "count": 2},
                {"state": "failed", "count": 1},
                {"state": "completed", "count": 3},
            ]
        )
        != expected
    ):
        return False
    if response([]) != {
        "version": 2,
        "counts": {"completed": 0, "failed": 0},
        "total": 0,
    }:
        return False
    for row in (
        {"state": "unknown", "count": 1},
        {"state": "failed", "count": -1},
        {"state": "completed", "count": True},
        {"state": "completed", "count": 1.5},
    ):
        try:
            response([row])
        except ValueError:
            continue
        return False
    return True
