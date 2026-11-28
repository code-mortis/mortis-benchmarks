from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "osv-scanner_darwin_arm64"
RELEASE_SHA256 = "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3"
RELEASE_URL = "https://github.com/google/osv-scanner/releases/expanded_assets/v2.7.1"
FLAGS = ["scan", "source", "--no-resolve", "--all-packages", "--format=json", "--lockfile=package-lock.json"]
STATE = ROOT / "isolated"
STATE.mkdir(exist_ok=True)
for subdir in ("cache", "config", "data", "state", "tmp"):
    (STATE / subdir).mkdir(exist_ok=True)
environment = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "XDG_CACHE_HOME": str(STATE / "cache"),
    "XDG_CONFIG_HOME": str(STATE / "config"),
    "XDG_DATA_HOME": str(STATE / "data"),
    "XDG_STATE_HOME": str(STATE / "state"),
    "TMPDIR": str(STATE / "tmp"),
}

def digest(path):
    with path.open("rb") as file:
        from hashlib import file_digest
        return file_digest(file, "sha256").hexdigest()

if digest(BINARY) != RELEASE_SHA256:
    raise SystemExit("Release SHA-256 does not match.")
version = subprocess.run([str(BINARY), "--version"], env=environment, text=True, check=True, capture_output=True)
protocol = json.loads((ROOT / "protocol.json").read_text())
results = []
for case in protocol["cases"]:
    fixture = ROOT / case["path"]
    if digest(fixture) != case["sha256"]:
        raise SystemExit(f"Input changed for case {case['case']}.")
    start = time.perf_counter()
    try:
        process = subprocess.run([str(BINARY), *FLAGS], env=environment, cwd=fixture.parent,
                                 text=True, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        results.append({**case, "elapsed_seconds": round(time.perf_counter() - start, 6),
                        "status": "timeout"})
        continue
    elapsed = round(time.perf_counter() - start, 6)
    detail = {**case, "elapsed_seconds": elapsed, "exit_code": process.returncode}
    try:
        data = json.loads(process.stdout)
    except json.JSONDecodeError:
        data = {}
    packages = [
        package for result in data.get("results", []) for package in result.get("packages", [])
        if package.get("package", {}).get("name") == case["package"]
        and package["package"].get("version") == case["version"]
        and package["package"].get("ecosystem") == case["ecosystem"]
    ]
    ids = set()
    record_ids = set()
    for package in packages:
        for advisory in package.get("vulnerabilities", []):
            record_ids.add(advisory["id"])
            ids.add(advisory["id"])
            ids.update(advisory.get("aliases", []))
        for group in package.get("groups", []):
            ids.update(group.get("ids", []))
    found = bool(ids.intersection(protocol["advisory_ids"]))
    stderr = process.stderr.replace(str(ROOT), "<fixture-root>").strip()
    detail.update(package_matches=len(packages), vulnerability_records_count=len(record_ids),
                  advisory_record_ids=sorted(record_ids), advisory_ids_with_aliases=sorted(ids),
                  target_advisory_found=found, status="pass" if packages and process.returncode in (0, 1)
                  and found == case["target_advisory_expected"] else "inconclusive" if not packages
                  or process.returncode not in (0, 1) else "mismatch")
    if detail["status"] == "inconclusive" and stderr:
        detail["diagnostic"] = stderr[-1000:]
    results.append(detail)

report = {
    "method": protocol["method"],
    "utc_time": datetime.now(timezone.utc).isoformat(),
    "release_metadata_url": RELEASE_URL,
    "binary": {"sha256": RELEASE_SHA256, "version_info": version.stdout.strip().splitlines()},
    "input_protocol_sha256": digest(ROOT / "protocol.json"),
    "runner_sha256": digest(Path(__file__)),
    "platform": {"os": platform.system(), "arch": platform.machine(), "release": platform.release()},
    "command": ["osv-scanner_darwin_arm64", *FLAGS],
    "state": "Separate empty temporary config, cache, data, state and temp directories. No inherited environment or credentials.",
    "units": "Elapsed wall seconds include OSV API latency and process startup. One sample per fixture.",
    "cases": results,
}
(ROOT / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
if any(case["status"] != "pass" for case in results):
    raise SystemExit(1)
