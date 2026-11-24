# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["src/coordinator.py"], "src/coordinator.py", "exec"), namespace)
    summarize = namespace["summarize"]
    assigned = ["src/coordinator.py", "src/worker.py"]
    outcomes = {"src/coordinator.py": {"status": "completed"}}
    result = summarize(assigned, outcomes, unavailable=["src/worker.py"])
    if result != {
        "status": "incomplete",
        "completed": ["src/coordinator.py"],
        "unavailable": ["src/worker.py"],
    }:
        return False
    if "incomplete" not in namespace["display_status"](result).lower():
        return False
    complete = summarize(assigned, {path: {"status": "completed"} for path in assigned})
    return complete["status"] == "completed" and len(complete["completed"]) == 2
