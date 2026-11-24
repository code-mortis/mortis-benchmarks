"""Prepare and guard one immutable, disk-backed Trivy snapshot for both pilot arms.

Only Trivy's official advisory/check repositories are contacted during preparation.
The real production scanner then runs without networking and with a read-only cache
under the frozen 2 CPU/1 GiB worker ceiling. Advisory data is preloaded, not cold.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

GIB = 1024**3
CACHE_LIMIT = 3 * GIB
WORK_LIMIT = 8 * GIB
DB_REPOSITORY = "ghcr.io/aquasecurity/trivy-db:2"
CHECK_REPOSITORY = "mirror.gcr.io/aquasec/trivy-checks:2"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tree_bytes(root):
    files = list(root.rglob("*"))
    require(not any(path.is_symlink() for path in files), "Scanner snapshot symlinks are forbidden")
    return sum(path.stat().st_size for path in files if path.is_file())


def snapshot_identity(root, *, timestamp=None):
    """Hash every advisory/check byte and metadata; refuse missing/stale snapshots."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "Scanner cache must be a regular directory")
    require(tree_bytes(root) <= CACHE_LIMIT, "Scanner cache exceeds the frozen 3 GiB disk bound")
    metadata = json.loads((root / "db" / "metadata.json").read_text())
    updated = datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
    timestamp = timestamp or datetime.now(UTC)
    require(
        updated.utcoffset() is not None and 0 <= (timestamp - updated).total_seconds() <= 86400,
        "Frozen scanner advisory database is missing, future-dated or older than 24 hours",
    )
    require(metadata.get("Version") == 2, "Unsupported Trivy advisory schema")
    require((root / "db" / "trivy.db").is_file(), "Missing Trivy advisory database")
    require(
        (root / "policy" / "content").is_dir() and (root / "policy" / "metadata.json").is_file(),
        "Fresh downloaded checks and metadata are required; embedded checks cannot replace them",
    )
    checks = json.loads((root / "policy" / "metadata.json").read_text())
    downloaded = datetime.fromisoformat(checks["DownloadedAt"].replace("Z", "+00:00"))
    require(
        checks.get("MajorVersion") == 2
        and downloaded.utcoffset() is not None
        and 0 <= (timestamp - downloaded).total_seconds() <= 86400
        and any(path.is_file() for path in (root / "policy" / "content").rglob("*")),
        "Frozen scanner checks are missing or were not downloaded within 24 hours",
    )
    files = {}
    for folder in (root / "db", root / "policy"):
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                files[path.relative_to(root).as_posix()] = {"bytes": path.stat().st_size, "sha256": digest}
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "mortis-engine-scanner-snapshot/v1",
        "trivy_version": "0.76.0",
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "files": files,
        "bytes": sum(value["bytes"] for value in files.values()),
        "database": metadata,
        "cache_policy": "read_only_preloaded_advisories_and_checks; cold_source_workspace",
    }


@contextmanager
def guard_scanner(expected, cache_root):
    """Keep production scanning intact; reject changed/fallback data before any AI."""
    from code_mortis.core.config import settings
    from code_mortis.security_scans import engine

    original = engine.trivy
    state = {"validated": False, "error": None}

    def scan(*args, **kwargs):
        before = snapshot_identity(cache_root)
        require(before == expected, "Scanner advisory/check snapshot differs from the frozen identity")
        result = original(*args, **kwargs)
        after = snapshot_identity(cache_root)
        require(
            after == before, "Scanner advisory/check snapshot changed during execution; inference forbidden"
        )
        metadata = result["metadata"]
        require(
            metadata["database_fresh"]
            and metadata["checks_present"]
            and set(metadata["scanners"]) == {"vuln", "misconfig", "secret"},
            "The pinned scanner could not establish fresh complete advisory/check coverage",
        )
        metadata["evaluation_snapshot"] = {
            "before": before["sha256"],
            "after": after["sha256"],
            "bytes": before["bytes"],
            "cache_policy": before["cache_policy"],
        }
        state["validated"] = True
        return result

    def guarded(*args, **kwargs):
        try:
            return scan(*args, **kwargs)
        except Exception as exc:
            state["error"] = type(exc).__name__
            raise

    with (
        patch.object(settings(), "trivy_cache_dir", Path(cache_root)),
        patch.object(engine, "trivy", guarded),
    ):
        yield state


def scan_check(cache, identity):
    """Run the real production scanner over an original synthetic source, no database/model."""
    from code_mortis.core import source
    from code_mortis.core.process import child_environment
    from code_mortis.security_scans import engine

    with tempfile.TemporaryDirectory(prefix="scanner-preflight-") as temporary:
        root, env = Path(temporary), child_environment()
        repo = root / "git"
        repo.mkdir()
        source.git(repo, env, "init", "--quiet")
        (repo / "requirements.txt").write_text("requests==2.19.0\n")
        (repo / "main.py").write_text("def status():\n    return 200\n")
        source.git(repo, env, "add", ".")
        source.git(
            repo,
            env,
            "-c",
            "user.name=Scanner preflight",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "synthetic scanner evidence",
        )
        sha = source.git(repo, env, "rev-parse", "HEAD").strip()
        item = engine.Snapshot(root, sha, env, lambda: False)
        item.populate()
        with guard_scanner(identity, cache):
            result = engine.trivy(item, 300, lambda: False)
        require(
            not result["problems"],
            "Actual bounded scanner preflight is incomplete: " + "; ".join(result["problems"]),
        )
        metrics = {}
        for name in ("memory.peak", "memory.events", "cpu.stat", "pids.current"):
            try:
                metrics[name] = (Path("/sys/fs/cgroup") / name).read_text()[:4096].strip()
            except (OSError, ValueError):
                metrics[name] = None
        return {"status": "passed", "provider_requests": 0, "trivy": result["metadata"], "cgroup": metrics}


def _docker(arguments, *, timeout=30):
    result = subprocess.run(["docker", *arguments], capture_output=True, timeout=timeout, check=False)
    require(
        result.returncode == 0,
        "Scanner Docker operation failed: " + result.stderr.decode(errors="replace")[-2000:],
    )
    return result.stdout


def _container(image, root, label, arguments, *, readonly_cache=False, offline=False):
    name = "mortis-scanner-preflight-" + uuid4().hex[:12]
    args = [
        "create",
        "--pull",
        "never",
        "--name",
        name,
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--network",
        "none" if offline else "bridge",
        "--cpus",
        "2",
        "--memory",
        str(GIB),
        "--memory-swap",
        str(GIB),
        "--pids-limit",
        "128",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=536870912,mode=1777",
        "--mount",
        f"type=bind,src={root / 'cache'},dst=/cache" + (",readonly" if readonly_cache else ""),
        "--mount",
        f"type=bind,src={root / 'source'},dst=/source,readonly",
        "--mount",
        f"type=bind,src={Path(__file__).resolve()},dst=/scanner_preflight.py,readonly",
        "--mount",
        f"type=bind,src={root / 'identity.json'},dst=/snapshot.json,readonly",
    ]
    for key, value in {
        "CM_ENCRYPTION_KEY": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        "CM_BOOTSTRAP_TOKEN": "synthetic-scanner-preflight",
        "CM_OWNER_GITHUB_LOGIN": "synthetic",
        "PYTHONPATH": "/app/backend",
        "PYTHONDONTWRITEBYTECODE": "1",
    }.items():
        args.extend(["--env", key + "=" + value])
    args.extend(["--entrypoint", arguments[0], image, *arguments[1:]])
    log = root / (label + ".log")
    _docker(args)
    try:
        with log.open("xb") as output:
            child = subprocess.Popen(["docker", "start", "-a", name], stdout=output, stderr=subprocess.STDOUT)
            started = time.monotonic()
            try:
                while child.poll() is None:
                    require(time.monotonic() - started <= 600, "Scanner preparation exceeded ten minutes")
                    require(tree_bytes(root / "cache") <= CACHE_LIMIT, "Scanner cache exceeded 3 GiB")
                    require(
                        tree_bytes(root) <= WORK_LIMIT and log.stat().st_size <= 4 * 1024**2,
                        "Scanner preparation exceeded working disk/log bounds",
                    )
                    time.sleep(0.5)
                require(child.returncode == 0, "Scanner preflight failed; retained log: " + str(log))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        inspection = json.loads(_docker(["inspect", name]))[0]
        require(not inspection["State"]["OOMKilled"], "Scanner exceeded its frozen 1 GiB memory ceiling")
        return {
            "image": inspection["Image"],
            "state": inspection["State"],
            "cpu_nanos": inspection["HostConfig"]["NanoCpus"],
            "memory": inspection["HostConfig"]["Memory"],
        }
    finally:
        _docker(["rm", "-f", name])


def prepare(root, image):
    root = Path(root).resolve()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "Preparation image must be an immutable local ID")
    require(
        root.is_dir() and not root.is_symlink() and not any((root / "cache").iterdir()),
        "Preparation requires a new empty cache in a private work directory",
    )
    require("," not in str(root), "Scanner bind path cannot contain mount delimiters")
    # The identity bind exists during preparation; replace only our own empty marker later.
    (root / "identity.json").write_text("{}")
    common = [
        "trivy",
        "fs",
        "--cache-dir",
        "/cache",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
    ]
    resources = {
        "database": _container(
            image, root, "download-db", [*common, "--db-repository", DB_REPOSITORY, "--download-db-only"]
        )
    }
    resources["checks"] = _container(
        image,
        root,
        "download-checks",
        [
            *common,
            "--scanners",
            "misconfig",
            "--skip-db-update",
            "--skip-java-db-update",
            "--checks-bundle-repository",
            CHECK_REPOSITORY,
            "--offline-scan",
            "--format",
            "json",
            "/source",
        ],
    )
    identity = snapshot_identity(root / "cache")
    (root / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    resources["actual_scanner"] = _container(
        image,
        root,
        "actual-scanner",
        ["python", "/scanner_preflight.py", "--scan-cache", "/cache", "--identity", "/snapshot.json"],
        readonly_cache=True,
        offline=True,
    )
    report = {
        "identity": identity,
        "resources": resources,
        "repositories": {"database": DB_REPOSITORY, "checks": CHECK_REPOSITORY},
    }
    (root / "preflight.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--scan-cache", type=Path)
    parser.add_argument("--identity", type=Path)
    args = parser.parse_args()
    if args.prepare:
        result = prepare(args.prepare, args.image)
    else:
        result = scan_check(args.scan_cache, json.loads(args.identity.read_text()))
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
