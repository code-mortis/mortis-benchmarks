# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
def check(files):
    repository_module, api_module = {}, {}
    exec(compile(files["order_store.py"], "order_store.py", "exec"), repository_module)
    exec(compile(files["order_api.py"], "order_api.py", "exec"), api_module)
    repository = repository_module["OrderRepository"]()
    try:
        first = api_module["create_order"](
            repository, {"request_key": "req-17", "amount": 450}
        )
        repeated = api_module["create_order"](
            repository, {"request_key": "req-17", "amount": 450}
        )
    except (TypeError, ValueError, KeyError):
        return False
    return (
        first[0] == 201
        and repeated[0] == 200
        and first[1] == repeated[1]
        and repository.count() == 1
        and api_module["create_order"](repository, {})[0] == 400
    )
