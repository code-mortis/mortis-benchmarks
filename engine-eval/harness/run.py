"""Run the frozen synthetic pilot in disposable, bounded Docker containers.

Default mode validates exported inputs without provider requests. --live requires
the separately authorized frozen runtime manifest. No other containers are stopped.
Only created containers/network are removed; every scheduled outcome stays on disk.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import selectors
import shutil
import stat
import subprocess
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from scanner_preflight import CACHE_LIMIT, snapshot_identity

SEED = 20261107
MIB = 1024 * 1024
MAX_RESULT = 32 * MIB
MAX_LOG = 4 * MIB
MAX_WORK = 8 * 1024 * MIB
MAX_EXPORT = 512 * MIB
PG_IMAGE = "sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62"
REDIS_IMAGE = "sha256:ec4f171e9ff071bb2a1c936057d3be00206069b028b6c0d61df2477e1dd02c42"
LIMITS = {
    "pr": {"cpus": 4, "memory": 2048 * MIB, "pids": 256},
    "security": {"cpus": 2, "memory": 1024 * MIB, "pids": 128},
    "postgres": {"cpus": 1, "memory": 512 * MIB, "pids": 128},
    "redis": {"cpus": .5, "memory": 128 * MIB, "pids": 64},
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def command(args, *, check=True, timeout=30):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError("Docker command failed: " + result.stderr.decode(errors="replace")[-2000:])
    return result.stdout.decode()


def tree_bytes(root):
    total = 0
    for path in root.rglob("*"):
        require(not path.is_symlink(), "Evaluation input/output symlinks are forbidden")
        if path.is_file():
            total += path.stat().st_size
    return total


def validate_inputs(manifest, cases, credentials, image, *, live, scanner_cache=None):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "Worker image must be an immutable local image ID")
    workflow = manifest.get("schema") == "mortis-engine-workflow-run/v2"
    require(workflow or manifest.get("schema") == "mortis-engine-live-run/v1", "Unsupported run manifest")
    quality_only = manifest.get("measurement_track") == "live_quality"
    require(manifest.get("measurement_track") in {None, "live_quality"}, "Unknown measurement track")
    require(not quality_only or (workflow and manifest.get("performance_claim_allowed") is False),
            "Only versioned live-quality runs can omit quiescence; their timings cannot support performance")
    if workflow:
        require(manifest.get("execution_profile") == "parallel_queue_v2"
                and manifest.get("queue") == {"pool": "prefork", "concurrency": 4, "dispatch_interval_seconds": 10},
                "Workflow run requires the frozen parallel queue profile")
    else:
        require(manifest.get("execution_profile", "retained_sequential_v1") == "retained_sequential_v1"
                and "queue" not in manifest, "Original pilot cannot change execution profile")
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", manifest.get("run_id", "")), "Invalid run identity")
    require(manifest.get("publication") == "disabled_sandbox_adapter_only", "Publication policy mismatch")
    if workflow:
        require(manifest.get("graph") in {"off", "on", "exact_revision_gap"}, "Unknown graph stratum")
        require(manifest.get("cache") in {"cold", "warm"}, "Unknown source-cache stratum")
        require(type(manifest.get("repetition")) is int and 1 <= manifest["repetition"] <= 100,
                "Invalid paired repetition")
    else:
        require(manifest.get("graph") == "off", "Publication/graph policy mismatch")
        require(manifest.get("cache") == "cold" and manifest.get("repetition") == 1, "Frozen pilot schedule mismatch")
    require(manifest.get("effective_resources_sha256"), "Missing frozen resource identity")
    require(cases.is_dir() and not cases.is_symlink() and tree_bytes(cases) <= MAX_EXPORT, "Export exceeds frozen snapshot ceiling")
    if workflow:
        expected = sorted(row["case_id"] for row in manifest["cases"])
        require(0 < len(expected) <= 1000 and len(set(expected)) == len(expected)
                and all(re.fullmatch(r"(?:pr|sec)-\d{2,4}", value) for value in expected),
                "Workflow cohort requires unique bounded case identities")
    else:
        expected = [f"pr-{i:02}" for i in range(1, 13)] + [f"sec-{i:02}" for i in range(1, 9)]
        require(sorted(row["case_id"] for row in manifest["cases"]) == expected, "Run manifest must retain all 20 frozen cases")
    require(sorted(path.name for path in cases.iterdir()) == expected, "Export contains missing or unexpected case inputs")
    for row in manifest["cases"]:
        folder = cases / row["case_id"]
        require(folder.is_dir() and {path.name for path in folder.iterdir()} == {"repo", "context.json", "change.diff"}, "Export must contain only source Git, context and diff; scorer truth is forbidden")
        require(row.get("evaluation_track") in {"quality_microcase", "reliability_fixture"}, "Unknown evaluation track")
        if workflow:
            require(row.get("evaluation_track") == "quality_microcase", "Workflow fault injection uses the separate adapter")
            require(row.get("identity", {}).get("history_sha256") == fingerprint(row.get("historical_findings", [])),
                    "Workflow history differs from frozen pair identity")
    def reject_private(value):
        if isinstance(value, dict):
            require(not {"truth", "oracle", "defects", "control", "api_key", "extra_headers"} & value.keys(), "Private scorer/credential content in worker manifest")
            for item in value.values():
                reject_private(item)
        elif isinstance(value, list):
            for item in value:
                reject_private(item)
    reject_private(manifest)
    require(credentials.is_file() and not credentials.is_symlink(), "Provider credential must be a regular private file")
    require(stat.S_IMODE(credentials.stat().st_mode) & 0o077 == 0, "Provider credential permissions must be private")
    require(credentials.stat().st_uid == os.getuid() and not credentials.is_relative_to(cases), "Credential must belong to the worker UID and remain outside source exports")
    require(all("," not in str(path) and not any(ord(char) < 32 for char in str(path)) for path in (cases, credentials)), "Bind paths cannot contain Docker mount-option delimiters")
    require(os.getuid() != 0, "Evaluation workers must run as the host nonroot UID")
    if scanner_cache is not None:
        require("," not in str(scanner_cache) and not any(ord(char) < 32 for char in str(scanner_cache)), "Scanner cache bind path contains Docker mount-option delimiters")
        require(not scanner_cache.is_relative_to(cases), "Scanner cache must remain outside source exports")
        check_scanner_cache(manifest, scanner_cache)
    if live:
        require(scanner_cache is not None, "Live security arms require the frozen read-only scanner snapshot")
        require(manifest.get("live_enabled") is True and manifest.get("authorization") == "owner_selected_pilot" and manifest.get("isolation_checks_passed") is True, "Live run needs explicit authorization and passed isolation checks")
        require(manifest.get("worker_image_id") == image, "Live worker image differs from frozen manifest")
        quiescence = manifest.get("host_quiescence", {})
        if quality_only:
            require(quiescence.get("verified") is False and quiescence.get("reason")
                    and isinstance(quiescence.get("observed_at"), str)
                    and isinstance(quiescence.get("active_container_ids"), list),
                    "Live-quality execution must disclose unverified quiescence and observed host workloads")
            stamp = quiescence["observed_at"]
        else:
            require(quiescence.get("verified") is True and isinstance(quiescence.get("verified_at"), str), "Live measurement requires dated host-quiescence verification")
            stamp = quiescence["verified_at"]
        require(datetime.fromisoformat(stamp.replace("Z", "+00:00")).utcoffset() is not None, "Host observation timestamp requires a timezone")


def schedule(manifest):
    rng = random.Random(SEED)
    planned = []
    for case in sorted(manifest["cases"], key=lambda row: row["case_id"]):
        arms = ["ocr", "mortis"]
        rng.shuffle(arms)
        planned.extend({"case_id": case["case_id"], "arm": arm, "repetition": manifest["repetition"], "graph": manifest["graph"], "cache": manifest["cache"]} for arm in arms)
    return planned


def limits_args(kind):
    limits = LIMITS[kind]
    return ["--cpus", str(limits["cpus"]), "--memory", str(limits["memory"]), "--memory-swap", str(limits["memory"]), "--pids-limit", str(limits["pids"]), "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--log-driver", "none"]


def worker_command(name, network, image, environment, manifest_path, cases, credentials, *, workload, live, migration=False, case=None, arm=None, scanner_cache=None):
    uid, gid = os.getuid(), os.getgid()
    require("," not in str(manifest_path) and not any(ord(char) < 32 for char in str(manifest_path)), "Manifest bind path contains Docker mount-option delimiters")
    args = ["create", "--pull", "never", "--name", name, "--network", network, "--user", f"{uid}:{gid}", "--workdir", "/app/backend", *limits_args(workload), "--tmpfs", f"/tmp:rw,nosuid,nodev,size={512 * MIB},mode=1777", "--tmpfs", f"/home/mortis/.opencodereview:rw,nosuid,nodev,size={64 * MIB},uid={uid},gid={gid},mode=0700"]
    for field, value in sorted(environment.items()):
        args.extend(["--env", f"{field}={value}"])
    if not migration:
        args.extend(["--mount", f"type=bind,src={manifest_path},dst=/input/manifest.json,readonly", "--mount", f"type=bind,src={cases},dst=/cases,readonly"])
        if live:
            args.extend(["--mount", f"type=bind,src={credentials},dst=/secrets/provider.json,readonly"])
        if workload == "security" and scanner_cache is not None:
            args.extend(["--mount", f"type=bind,src={scanner_cache},dst=/scanner-cache,readonly", "--env", "CM_TRIVY_CACHE_DIR=/scanner-cache"])
    args.append(image)
    if migration:
        args.extend(["alembic", "upgrade", "head"])
    else:
        args.extend(["python", "/app/evaluation/runtime.py", "--manifest", "/input/manifest.json", "--case", f"/cases/{case}", "--arm", arm, "--output", "-"])
        if not live:
            args.append("--dry-run")
    return args


def inspect_constraints(name, kind, *, worker=False):
    inspection = json.loads(command(["inspect", name]))[0]
    host = inspection["HostConfig"]
    limits = LIMITS[kind]
    require(host["NanoCpus"] == int(limits["cpus"] * 1_000_000_000) and host["Memory"] == limits["memory"] and host["MemorySwap"] == limits["memory"] and host["PidsLimit"] == limits["pids"], "Docker did not enforce frozen resource ceilings")
    require(host["ReadonlyRootfs"] and "ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"] and not host["Privileged"] and not host.get("PortBindings"), "Docker isolation constraints differ from frozen policy")
    if worker:
        require(inspection["Config"]["User"] == f"{os.getuid()}:{os.getgid()}", "Worker UID differs from host nonroot user")
        require(all(mount["Type"] != "bind" or not mount["RW"] for mount in inspection["Mounts"]), "Worker has writable host mounts")
        require(not any(mount["Destination"] in {"/var/run/docker.sock", "/run/docker.sock"} for mount in inspection["Mounts"]), "Docker socket is forbidden")
        require(host["Tmpfs"].get("/tmp", "").find(f"size={512 * MIB}") >= 0 and host["Tmpfs"].get("/home/mortis/.opencodereview", "").find(f"size={64 * MIB}") >= 0, "Worker tmpfs ceilings differ from frozen policy")
    return {"image_id": inspection["Image"], "limits": limits, "readonly": host["ReadonlyRootfs"], "cap_drop": host["CapDrop"], "security_opt": host["SecurityOpt"], "tmpfs": host["Tmpfs"], "mounts": [{key: row[key] for key in ("Type", "Destination", "RW")} for row in inspection["Mounts"]]}


def bounded_capture(args, stdout_path, stderr_path, *, timeout, container=None, stats_path=None, result_bound=None):
    """Drain both pipes while bounding retained bytes; caller removes its container."""
    process = subprocess.Popen(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    counts = {"stdout": 0, "stderr": 0}
    sampled_at = 0
    stats = stats_path.open("xb") if stats_path else None
    stats_bytes = 0
    try:
        with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
            for pipe, stream, label, bound in ((process.stdout, out, "stdout", MAX_RESULT if result_bound is None else result_bound), (process.stderr, err, "stderr", MAX_LOG)):
                selector.register(pipe, selectors.EVENT_READ, (stream, label, bound))
            while selector.get_map():
                if time.monotonic() - started > timeout:
                    raise TimeoutError("Evaluation container exceeded frozen deadline")
                if stats and time.monotonic() - sampled_at >= 10:
                    sample = command(["stats", "--no-stream", "--format", "{{json .}}", container], check=False, timeout=5)
                    encoded = canonical({"elapsed_ms": (time.monotonic() - started) * 1000, "docker_stats": sample[:16384]}) + b"\n"
                    require(stats_bytes + len(encoded) <= MAX_LOG, "Docker stats exceed retained-output bound")
                    stats.write(encoded)
                    stats_bytes += len(encoded)
                    sampled_at = time.monotonic()
                for item, _ in selector.select(timeout=1):
                    data = os.read(item.fd, 65536)
                    if not data:
                        selector.unregister(item.fileobj)
                        continue
                    stream, label, bound = item.data
                    remaining = bound - counts[label]
                    stream.write(data[:remaining])
                    counts[label] += len(data)
                    if counts[label] > bound:
                        raise ValueError("Evaluation " + label + " exceeds retained-output bound")
            code = process.wait(timeout=5)
            return code, (time.monotonic() - started) * 1000
    finally:
        selector.close()
        if stats:
            stats.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def placeholder(item, case, reason="planned_not_started", status="not_started"):
    return {**item, "schema": "mortis-engine-eval-attempt/v1", "attempt_id": f"{item['case_id']}-{item['arm']}-1", "case_digest": case["case_digest"], "identity": case["identity"], "status": status, "findings": [], "coverage": {"assigned_units": case["expected_assigned_units"], "validated_units": 0}, "timing_ms": {}, "usage": {}, "outcomes": [{"kind": reason}]}


def must_stop(attempt):
    if attempt.get("stop_pilot") is True:
        return True
    events = attempt.get("provider_events", [])
    if any(row.get("consumption_unknown") or row.get("error_code") in {"authentication", "quota"} for row in events):
        return True
    return attempt.get("status") not in {"validated_offline", "unsupported_fixture"} and attempt.get("usage", {}).get("tokens") is None


def wait_ready(name, args):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = subprocess.run(["docker", "exec", name, *args], capture_output=True, timeout=5, check=False)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise TimeoutError("Disposable service did not become ready")


def verify_quiescence(created):
    running = set(command(["ps", "--filter", "status=running", "--format", "{{.Names}}"]).splitlines())
    require(running <= set(created), "External Docker workloads are active; measurement stopped without changing them")


def check_scanner_cache(manifest, scanner_cache):
    require(tree_bytes(scanner_cache) <= CACHE_LIMIT, "Scanner cache exceeds the frozen 3GiB disk ceiling")
    observed = snapshot_identity(scanner_cache)
    require(observed == manifest.get("scanner_snapshot"), "Scanner cache identity differs from the frozen run manifest")
    return observed


def recovery_query():
    # Project inside PostgreSQL so even the raw retained stdout cannot contain source or secrets.
    fields = "'sequence','status','elapsed_ms','forwarded','consumption_unknown','input_tokens','output_tokens','total_tokens','cache_read_tokens','cache_write_tokens','reasoning_tokens','state','error_code'"
    errors = "'authentication','quota','rate_limit','provider_error','redirect','unknown_consumption','connection','transport','capture_persistence','capture_credentials'"
    events = f"""(SELECT coalesce(jsonb_agg(projected), '[]'::jsonb) FROM (
        SELECT (SELECT jsonb_object_agg(key, CASE
            WHEN jsonb_typeof(value) IN ('number','boolean') THEN value
            WHEN key='state' AND value #>> '{{}}' IN ('started','finished') THEN value
            WHEN key='error_code' AND value #>> '{{}}' IN ({errors}) THEN value
            ELSE 'null'::jsonb END)
            FROM jsonb_each(event) WHERE key IN ({fields})) AS projected
        FROM jsonb_array_elements(CASE WHEN jsonb_typeof(payload::jsonb->'provider_events')='array'
             THEN payload::jsonb->'provider_events' ELSE '[]'::jsonb END) event LIMIT 256
    ) projected_events)"""
    selections = {
        "jobs": (1024, f"id,kind,status,attempts,CASE WHEN jsonb_typeof(payload::jsonb->'provider_events')='array' THEN jsonb_array_length(payload::jsonb->'provider_events') ELSE 0 END AS provider_event_count,{events} AS provider_events"),
        "analysis_plans": (256, "id,job_id,run_id,scan_id"),
        "analysis_tasks": (4096, "id,plan_id,stage,status,attempts,input_hash"),
        "analysis_attempts": (8192, "id,task_id,number,job_attempt,status,reserved_tokens,usage_tokens,usage_state,started_at,finished_at,error_code"),
        "analysis_budgets": (512, "plan_id,stage,token_limit,charged_tokens,deadline_at"),
    }
    sections = []
    counts = []
    for table, (limit, columns) in selections.items():
        sections.extend([f"'{table}'", f"(SELECT coalesce(jsonb_agg(record_data), '[]'::jsonb) FROM (SELECT {columns} FROM {table} ORDER BY 1 LIMIT {limit}) record_data)"])
        counts.extend([f"'{table}'", f"(SELECT count(*) FROM {table})"])
    return "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; SELECT jsonb_build_object('schema','mortis-engine-recovered-ledger/v1'," + ",".join(sections) + ",'row_counts',jsonb_build_object(" + ",".join(counts) + ")); COMMIT;"


def recovery_summary(document):
    require(document.get("schema") == "mortis-engine-recovered-ledger/v1", "Unexpected recovered-ledger schema")
    bounds = {"jobs": 1024, "analysis_plans": 256, "analysis_tasks": 4096, "analysis_attempts": 8192, "analysis_budgets": 512}
    truncated = any(document["row_counts"][table] > bound for table, bound in bounds.items()) or any(job["provider_event_count"] > len(job["provider_events"]) for job in document["jobs"])
    events = [event for job in document["jobs"] for event in job["provider_events"] if event.get("forwarded") is True]
    known_events = [event for event in events if event.get("state") == "finished" and event.get("consumption_unknown") is False and type(event.get("total_tokens")) is int and event["total_tokens"] >= 0]
    ledger = document["analysis_attempts"]
    unknown = [row for row in ledger if row["usage_state"] != "known" or type(row["usage_tokens"]) is not int or row["usage_tokens"] < 0]
    return {
        "exported": True, "artifact": "recovered-ledger.json", "truncated": truncated,
        "provider_forwarded_events": len(events), "provider_known_token_subtotal": sum(event["total_tokens"] for event in known_events),
        "provider_unknown_events": len(events) - len(known_events),
        "ledger_known_token_subtotal": sum(row["usage_tokens"] for row in ledger if row not in unknown),
        "ledger_unknown_attempts": len(unknown), "ledger_unknown_reserved_tokens": sum(row["reserved_tokens"] for row in unknown),
        "consumption_complete": not truncated and len(events) == len(known_events) and not unknown,
        "accounting_note": "Provider and engine subtotals overlap; never add them. Started-only events and unobserved consumption remain unknown; never redispatch automatically.",
    }


def recover_ledger(postgres, output):
    args = ["exec", "--user", "postgres", postgres, "psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1", "--username", "mortis", "--dbname", "mortis_eval", "--command", recovery_query()]
    code, _ = bounded_capture(args, output / "recovered-ledger.json", output / "recovered-ledger.stderr.log", timeout=30, result_bound=MAX_LOG)
    require(code == 0, "Sanitized ledger export failed")
    return recovery_summary(json.loads((output / "recovered-ledger.json").read_text()))


def run(manifest_path, cases, credentials, image, output, *, live=False, scanner_cache=None):
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    validate_inputs(manifest, cases, credentials, image, live=live, scanner_cache=scanner_cache)
    quiet = manifest.get("measurement_track") != "live_quality"
    require(not output.exists(), "Output directory must be new; retained attempts cannot be overwritten")
    require(not output.is_relative_to(cases), "Output directory must remain outside source exports")
    require(shutil.disk_usage(output.parent).free >= 10 * 1024 * MIB, "Insufficient frozen working-disk headroom")
    output.mkdir(mode=0o700)
    (output / "manifest.json").write_bytes(manifest_bytes)
    planned = schedule(manifest)
    write_new(output / "schedule.json", planned)
    indexed = {case["case_id"]: case for case in manifest["cases"]}
    attempts = [placeholder(item, indexed[item["case_id"]]) for item in planned]
    resources, created = {}, []
    network = "mortis-eval-" + uuid4().hex[:12]
    postgres, redis = network + "-pg", network + "-redis"
    password = uuid4().hex
    environment = {
        "CM_DATABASE_URL": f"postgresql+psycopg://mortis:{password}@{postgres}:5432/mortis_eval",
        "CM_REDIS_URL": f"redis://{redis}:6379/0", "CM_EVAL_RUN_ID": manifest["run_id"],
        "CM_EVAL_SOURCE_REVISION": manifest["source_revision"], "CM_EVAL_MANIFEST_SHA256": hashlib.sha256(manifest_bytes).hexdigest(),
        "CM_EVAL_DISPOSABLE_DATABASE": "true", "CM_EVAL_CREDENTIALS_FILE": "/secrets/provider.json",
        "CM_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(), "CM_BOOTSTRAP_TOKEN": uuid4().hex,
        "CM_OWNER_GITHUB_LOGIN": "mortis-eval", "CM_OCR_ISOLATED_RUNTIME": "true", "CM_ALLOW_PRIVATE_ENDPOINTS": "true",
        "CM_TRUSTED_ENDPOINT_HOSTS": "127.0.0.1",
        "PYTHONPATH": "/app/backend", "HOME": "/home/mortis", "PYTHONDONTWRITEBYTECODE": "1",
    }
    network_created, migrated, stopped = False, False, None
    recovery = {"exported": False, "reason": "no_live_worker_database"}
    try:
        for pinned in (image, PG_IMAGE, REDIS_IMAGE):
            require(json.loads(command(["image", "inspect", pinned]))[0]["Id"] == pinned, "Pinned local image identity mismatch")
        if live and quiet:
            verify_quiescence(created)
        command(["network", "create", *([] if live else ["--internal"]), network])
        network_created = True
        pg_args = ["create", "--pull", "never", "--name", postgres, "--network", network, "--user", "postgres", *limits_args("postgres"), "--tmpfs", f"/var/lib/postgresql/data:rw,nosuid,nodev,size={384 * MIB},mode=1777", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16777216,mode=1777", "--env", "POSTGRES_USER=mortis", "--env", "POSTGRES_DB=mortis_eval", "--env", f"POSTGRES_PASSWORD={password}", "--env", "PGDATA=/var/lib/postgresql/data/pgdata", PG_IMAGE]
        redis_args = ["create", "--pull", "never", "--name", redis, "--network", network, "--user", "redis", *limits_args("redis"), "--tmpfs", "/data:rw,nosuid,nodev,size=16777216,mode=1777", REDIS_IMAGE, "redis-server", "--save", "", "--appendonly", "no", "--maxmemory", "96mb", "--maxmemory-policy", "noeviction"]
        for name, args, kind in ((postgres, pg_args, "postgres"), (redis, redis_args, "redis")):
            command(args)
            created.append(name)
            resources[kind] = inspect_constraints(name, kind)
            command(["start", name])
        wait_ready(postgres, ["pg_isready", "-U", "mortis", "-d", "mortis_eval"])
        wait_ready(redis, ["redis-cli", "ping"])
        migration = network + "-migrate"
        command(worker_command(migration, network, image, environment, manifest_path, cases, credentials, workload="pr", live=False, migration=True))
        created.append(migration)
        resources["migration"] = inspect_constraints(migration, "pr", worker=True)
        code, _ = bounded_capture(["start", "-a", migration], output / "migration.stdout", output / "migration.stderr", timeout=180)
        require(code == 0, "Disposable database migration failed")
        migrated = True
        write_new(output / "preflight.json", {"effective_constraints": resources, "host_quiescence": manifest.get("host_quiescence", "not_verified"), "performance_claim_allowed": False, "live": live})
        for index, item in enumerate(planned):
            case = indexed[item["case_id"]]
            if case["evaluation_track"] == "reliability_fixture":
                attempts[index] = placeholder(item, case, "requires_separate_failure_injection_harness", "unsupported_fixture")
                continue
            if stopped:
                attempts[index] = placeholder(item, case, stopped)
                continue
            require(tree_bytes(output) + tree_bytes(cases) + (tree_bytes(scanner_cache) if scanner_cache is not None else 0) <= MAX_WORK, "Evaluation working data including the shared scanner cache exceeded frozen 8GiB ceiling")
            if live and quiet:
                verify_quiescence(created)
            name = network + f"-arm-{index:02}"
            stem = output / f"{index:02}-{item['case_id']}-{item['arm']}"
            if case["workload"] == "security" and scanner_cache is not None:
                write_new(stem.with_suffix(".scanner-before.json"), check_scanner_cache(manifest, scanner_cache))
            command(worker_command(name, network, image, environment, manifest_path, cases, credentials, workload=case["workload"], live=live, case=item["case_id"], arm=item["arm"], scanner_cache=scanner_cache))
            created.append(name)
            effective = inspect_constraints(name, case["workload"], worker=True)
            write_new(stem.with_suffix(".constraints.json"), effective)
            try:
                code, elapsed = bounded_capture(["start", "-a", name], stem.with_suffix(".stdout.json"), stem.with_suffix(".stderr.log"), timeout=1800, container=name, stats_path=stem.with_suffix(".stats.jsonl"))
                require(code == 0, "Evaluation worker failed")
                result = json.loads(stem.with_suffix(".stdout.json").read_text())
                require(result.get("schema") == "mortis-engine-eval-attempt/v1" and result.get("identity") == case["identity"], "Worker artifact schema/settings/source identity mismatch")
                require(all(result.get(field) == value for field, value in item.items()) and result.get("case_digest") == case["case_digest"], "Worker returned a different arm/case identity")
                if not live:
                    result = {**placeholder(item, case, "offline_input_validation", "validated_offline"), **result}
                result["orchestration_ms"] = elapsed
                attempts[index] = result
                if live and must_stop(result):
                    stopped = "stopped_after_auth_quota_or_unknown_consumption"
            except (ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
                attempts[index] = placeholder(item, case, "worker_error_" + type(exc).__name__, "failed")
                stopped = "stopped_after_unobserved_worker_consumption"
            finally:
                state = json.loads(command(["inspect", name]))[0]["State"]
                write_new(stem.with_suffix(".state.json"), state)
                command(["rm", "-f", name], check=False)
                created.remove(name)
                if case["workload"] == "security" and scanner_cache is not None:
                    try:
                        write_new(stem.with_suffix(".scanner-after.json"), check_scanner_cache(manifest, scanner_cache))
                    except (OSError, ValueError) as exc:
                        attempts[index]["status"], attempts[index]["stop_pilot"] = "failed", True
                        attempts[index]["outcomes"].append({"kind": "scanner_snapshot_changed_or_unavailable", "error_type": type(exc).__name__})
                        stopped = "stopped_after_scanner_snapshot_change"
            write_new(stem.with_suffix(".attempt.json"), attempts[index])
    except BaseException as exc:
        stopped = "orchestration_error_" + type(exc).__name__
        raise
    finally:
        preserve_database = False
        try:
            if live and migrated:
                try:
                    # Stop any interrupted arm before the read-only snapshot; it must not keep spending.
                    for name in created:
                        if "-arm-" in name:
                            command(["kill", name], check=False)
                    recovery = recover_ledger(postgres, output)
                    if recovery["truncated"]:
                        preserve_database = True
                        recovery.update(database_container_preserved=postgres, network_preserved=network, reason="Bounded export is incomplete; recover remaining evidence before cleanup")
                except (OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
                    preserve_database = True
                    recovery = {"exported": False, "error_type": type(exc).__name__, "consumption_complete": False, "database_container_preserved": postgres, "network_preserved": network, "reason": "Manual evidence recovery required before removing the disposable database"}
            result_schema = "mortis-engine-workflow-results/v2" if manifest["schema"] == "mortis-engine-workflow-run/v2" else "mortis-engine-eval-results/v1"
            write_new(output / "results.json", {"schema": result_schema, "corpus_digest": manifest["corpus_digest"], "protocol_sha256": manifest["protocol_sha256"], "run_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "scanner_snapshot": manifest.get("scanner_snapshot"), "planned_attempts": planned, "attempts": attempts, "stopped_reason": stopped, "live": live, "recovered_ledger": recovery})
        finally:
            for name in reversed(created):
                if preserve_database and name == postgres:
                    continue
                try:
                    command(["rm", "-f", name], check=False)
                except (OSError, subprocess.SubprocessError):
                    pass
            if network_created and not preserve_database:
                command(["network", "rm", network], check=False)
        if preserve_database:
            raise RuntimeError("Incomplete evidence export; recover the preserved disposable database before cleanup")
    return output / "results.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "cases", "credentials-file", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--scanner-cache", type=Path)
    args = parser.parse_args()
    result = run(args.manifest.resolve(), args.cases.resolve(), args.credentials_file.resolve(), args.image, args.output.resolve(), live=args.live, scanner_cache=args.scanner_cache.resolve() if args.scanner_cache else None)
    print("Retained evaluation results: " + str(result))


if __name__ == "__main__":
    raise SystemExit("This historical OCR/native evaluation is retired. Saved evidence and offline scoring remain available; new execution is disabled.")
