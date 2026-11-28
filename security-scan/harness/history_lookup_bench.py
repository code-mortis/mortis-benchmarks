"""Isolated steady-state lookup through list_findings after 250 sequential completed scans."""
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from mortis_engine.findings import list_findings
from mortis_engine.history import History

count = 250
with tempfile.TemporaryDirectory(prefix="scan-history-") as temp:
    root = Path(temp)
    os.environ.update(XDG_STATE_HOME=str(root / "state"), XDG_CONFIG_HOME=str(root / "config"))
    repo = root / "repo"
    subprocess.run(["git", "init", "--template=", "-q", str(repo)], check=True)
    report = {"schema_version": "mortis.security/v1", "status": "completed",
              "coverage": {"inventory": {f"file{i}.py": {"lines": 100} for i in range(30)}},
              "findings": [{"id": "fixture", "kind": "code", "state": "open", "outcome": "present",
                            "fingerprint": "f"*64, "source_sha": "a"*40, "version": 1, "severity": "high"}]}
    with History(repo) as history:
        for i in range(count):
            if hasattr(history, "scan_history_cutoff"):
                fields = {"scan_history_through": history.scan_history_cutoff()}
            else:
                fields = {"previous": history.previous_ids("scan", "same"), "assessment_runs": []}
            run = history.begin("scan", "same", fields)
            history.finish(run, report)
        size = history.db.execute("SELECT SUM(LENGTH(plan)) FROM runs").fetchone()[0]
        latest = len(history.row(run)["plan"].encode())
    samples = []
    for i in range(7):
        started = time.perf_counter()
        rows = list_findings(repo, run_id=run)["findings"]
        elapsed = (time.perf_counter() - started) * 1000
        assert [(r["id"], r["decision"], r["source_sha"]) for r in rows] == [("fixture", "open", "a"*40)]
        if i:
            samples.append(elapsed)
    result = {"scans": count, "files_per_scan": 30, "findings_per_scan": 1, "warmups": 1,
              "history_plan_bytes_total": size, "history_plan_bytes_last": latest,
              "list_findings_samples_ms": samples, "list_findings_median_ms": statistics.median(samples),
              "finding_output_verified": True}
    Path(sys.argv[1]).write_text(json.dumps(result, indent=2)+"\n")
