"""Read-only timing probe. Run inside the API environment with --login, --pr-id and --path.

See the suite README for the Docker Compose invocation. Output contains durations
and counts only.
"""

import argparse
import functools
import json
import time
from collections import Counter

from sqlalchemy import event, select

from code_mortis.code_graph import explorer, retrieval, store
from code_mortis.core.db import engine, transaction
from code_mortis.integrations import comparison, github
from code_mortis.models import Job, User
from code_mortis.reviews import code
from code_mortis.schemas.pr_code import CodeNavigation

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--login", required=True)
parser.add_argument("--pr-id", required=True)
parser.add_argument("--path", required=True)
parser.add_argument("--samples", type=int, default=20)
args = parser.parse_args()
if not 1 <= args.samples <= 100:
    parser.error("--samples must be between 1 and 100")
stages, samples = [], []
sql = {"count": 0, "ms": 0}


@event.listens_for(engine(), "before_cursor_execute")
def before(conn, cursor, statement, parameters, context, executemany):
    context.perf_started = time.perf_counter()


@event.listens_for(engine(), "after_cursor_execute")
def after(conn, cursor, statement, parameters, context, executemany):
    sql["count"] += 1
    sql["ms"] += (time.perf_counter() - context.perf_started) * 1000


def measure(module, name):
    original = getattr(module, name)

    @functools.wraps(original)
    def timed(*values, **kwargs):
        started = time.perf_counter()
        try:
            return original(*values, **kwargs)
        finally:
            item = {"stage": f"{module.__name__.split('.')[-1]}.{name}", "ms": round((time.perf_counter() - started) * 1000, 2)}
            if name == "authorize_repo":
                item["fresh"] = kwargs.get("fresh", False)
            if name == "request":
                item["kind"] = "compare" if "/compare/" in values[1] else "installation_token" if "/access_tokens" in values[1] else "permission"
            stages.append(item)
    setattr(module, name, timed)


for module, name in [(github, "request"), (github, "authorize_repo"), (explorer, "check_source"),
                     (code, "parse_patch"), (code, "saved_findings"), (code, "saved_groups"),
                     (retrieval, "read_snapshot"), (store, "read_blob")]:
    measure(module, name)
with transaction() as db:
    actor = db.scalar(select(User.id).where(User.login == args.login))
    if actor is None:
        parser.error("User not found")
    jobs_before = Counter(db.scalars(select(Job.kind)))

for iteration in range(args.samples + 1):
    for view in ("diff", "dependencies", "definitions", "source"):
        stages.clear()
        sql.update(count=0, ms=0)
        hits = comparison.cached.cache_info().hits
        started = time.perf_counter()
        with transaction() as db:
            result = code.workspace(db, db.get(User, actor), args.pr_id, CodeNavigation(path=args.path, view=view))
        sample = {"iteration": iteration, "mode": ("cold" if view == "diff" else "initial") if iteration == 0 else "warm", "view": view,
                  "ms": round((time.perf_counter() - started) * 1000, 2), "bytes": len(json.dumps(result).encode()),
                  "sql_count": sql["count"], "sql_ms": round(sql["ms"], 2),
                  "comparison_hits": comparison.cached.cache_info().hits - hits, "stages": stages.copy()}
        samples.append(sample)
        print(json.dumps({key: value for key, value in sample.items() if key != "stages"}), flush=True)
with transaction() as db:
    jobs_after = Counter(db.scalars(select(Job.kind)))
github.close_http_client()
print("RESULT " + json.dumps({"samples": samples, "background_jobs_delta": dict(jobs_after - jobs_before)}))
