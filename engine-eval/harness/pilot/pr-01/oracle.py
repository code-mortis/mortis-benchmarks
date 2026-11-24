# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
from decimal import Decimal


def check(files):
    namespace = {}
    exec(compile(files["billing.py"], "billing.py", "exec"), namespace)
    total = namespace["invoice_totals"]
    return (
        total([Decimal("0.05"), Decimal("0.05")], Decimal("0.10"))["tax"]
        == Decimal("0.01")
        and total(iter([Decimal("10.00")]), Decimal("0.20"))["total"]
        == Decimal("12.00")
        and total([], Decimal("0.20"))["tax"] == Decimal("0.00")
    )
