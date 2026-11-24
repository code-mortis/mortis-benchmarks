# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
import builtins
import types


def check(files):
    modules = {}
    normal_import = builtins.__import__

    def import_memory(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"formatter", "rendering"}:
            path = name + ".py"
            if path not in files:
                raise ModuleNotFoundError(name)
            if name not in modules:
                module = types.ModuleType(name)
                modules[name] = module
                exec(compile(files[path], path, "exec"), module.__dict__)
            return modules[name]
        return normal_import(name, globals, locals, fromlist, level)

    namespace = {"__builtins__": {**vars(builtins), "__import__": import_memory}}
    try:
        exec(compile(files["report.py"], "report.py", "exec"), namespace)
        rendered = namespace["render_invoice"](
            {"id": "I-42", "customer": " Ada  Example ", "total_cents": 1250}
        )
    except (ImportError, AttributeError, KeyError):
        return False
    return rendered == "Invoice I-42\nCustomer: Ada Example\nTotal: USD 12.50\n"
