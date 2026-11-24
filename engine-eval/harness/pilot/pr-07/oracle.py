# Execute only trusted original synthetic fixture strings, never arbitrary repository code.
# ruff: noqa: S102
def check(files):
    namespace = {}
    exec(compile(files["src/checkout.py"], "src/checkout.py", "exec"), namespace)
    charge = namespace["charge_order"]
    for timing in ("after_commit", "before_commit", "never"):

        class Gateway:
            def __init__(self, timing):
                self.timing = timing
                self.calls = 0
                self.charges = {}

            def charge(self, amount, *, idempotency_key):
                self.calls += 1
                if self.calls == 1 and self.timing == "before_commit":
                    raise TimeoutError()
                receipt = self.charges.setdefault(
                    idempotency_key, (amount, "receipt-1")
                )
                if self.calls == 1 and self.timing == "after_commit":
                    raise TimeoutError()
                return receipt[1]

        gateway = Gateway(timing)
        order = {"id": "purchase-27", "amount_cents": 1299}
        first = charge(order, gateway)
        second = charge(order, gateway)
        if first != second or first["receipt"] != "receipt-1":
            return False
        if (
            len(gateway.charges) != 1
            or sum(item[0] for item in gateway.charges.values()) != 1299
        ):
            return False
    return True
