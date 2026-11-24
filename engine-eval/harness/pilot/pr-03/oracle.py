# Execute only the case's trusted original synthetic fixture strings.
# ruff: noqa: S102
from datetime import datetime, timezone


def check(files):
    namespace = {}
    exec(compile(files["token_expiry.py"], "token_expiry.py", "exec"), namespace)
    expired = namespace["is_expired"]
    now = datetime(2026, 1, 1, 11, tzinfo=timezone.utc)
    if not expired("2026-01-01T12:00:00+02:00", now):
        return False
    if expired("2026-01-01T09:00:00-03:00", now):
        return False
    if not expired("2026-01-01T11:00:00+00:00", now):
        return False
    try:
        expired("2026-01-01T11:00:00", now)
    except ValueError:
        return True
    return False
