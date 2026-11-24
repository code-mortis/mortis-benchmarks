"""Measure Phase 0 source corpora in a disposable schema on the isolated test DB.

Run with the Code Mortis backend environment against the isolated test database.
--repo NAME LOCAL_PATH COMMIT [--repo ...] --output REPORT.json.
No network, source execution, checkout, application activation or model calls.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, insert, text

from code_mortis.code_graph import client, store
from code_mortis.code_graph.extract import extract
from code_mortis.core.config import settings
from code_mortis.core.db import Base
from code_mortis.models import (
    CodeGraphFile,
    CodeGraphImport,
    CodeGraphSnapshot,
    CodeGraphSymbol,
    Installation,
    Repository,
)
from code_mortis.schemas.code_graph import EXTRACTOR_VERSION, CodeGraphRequest, CodeGraphSource

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".cpp", ".rb", ".cs", ".php", ".sh"}


def git(root, *args):
    return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                                    "-c", "maintenance.auto=false", "-C", str(root), *args],
                                   env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}, stderr=subprocess.DEVNULL)


def sizes(db, schema):
    return {name: {"table_bytes": table, "index_bytes": indexes, "total_bytes": total}
            for name, table, indexes, total in db.execute(text(
                "SELECT relname, pg_table_size(oid), pg_indexes_size(oid), pg_total_relation_size(oid) "
                "FROM pg_class WHERE relnamespace = CAST(:schema AS regnamespace) AND relkind = 'r' "
                "AND relname LIKE 'code_graph_%' ORDER BY relname"), {"schema": schema})}


def measure(name, source, commit, engine, temporary):
    schema = "graph_measure_" + uuid4().hex
    scoped = engine.execution_options(schema_translate_map={None: schema})
    with engine.begin() as db:
        db.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        Base.metadata.create_all(scoped)
        with scoped.begin() as db:
            db.execute(insert(Installation), [{"id": 10, "account": "fixture"}])
            db.execute(insert(Repository), [{"id": 22, "installation_id": 10, "full_name": "fixture/corpus"}])
        root = temporary / name / "22"
        root.mkdir(parents=True)
        git(root, "init", "--bare", "--template=", ".")
        git(root, "-c", "protocol.file.allow=always", "fetch", "--depth=1", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules", str(source.resolve()), commit)
        sha = git(root, "rev-parse", commit + "^{commit}").decode().strip()
        identity = str(uuid4())
        git(root, "update-ref", store.reference(identity), sha)
        rules = {"version": 1, "exclusions": []}
        row = CodeGraphSnapshot(id=identity, repository_id=22, commit_sha=sha, extractor_version=EXTRACTOR_VERSION,
                                policy_digest=store.policy_digest(rules), policy=rules)
        settings().code_graph_store_dir = root.parent
        try:
            full = store.request(row, lambda: False)
            admission = {"state": "admitted", "files": len(full.files)}
        except ValueError as exc:
            admission = {"state": "rejected", "reason": str(exc)}
        files, manifest = [], []
        entries = git(root, "ls-tree", "-rlz", sha).split(b"\0")
        for entry in filter(None, entries):
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, blob, raw_size = metadata.decode().split()
            path = raw_path.decode()
            if kind != "blob" or mode not in {"100644", "100755"} or Path(path).suffix not in EXTENSIONS or int(raw_size) > 1024**2:
                continue
            size = int(raw_size)
            manifest.append({"path": path, "blob": blob, "bytes": size})
            excluded = store.excluded(path, rules)
            files.append(CodeGraphSource(path=path, blob_sha=blob, size_bytes=size,
                         content_base64=None if excluded else base64.b64encode(git(root, "cat-file", "blob", blob)).decode(),
                         exclusion="excluded" if excluded else None))
        request = CodeGraphRequest(repository_id=22, commit_sha=sha, policy_digest=row.policy_digest, files=files)
        result = extract(request)
        client.validate_result(request, result)
        with engine.connect() as db:
            before, start = sizes(db, schema), db.scalar(text("SELECT pg_current_wal_insert_lsn()"))
        with scoped.begin() as db:
            db.execute(insert(CodeGraphSnapshot), [{"id": identity, "repository_id": 22, "commit_sha": sha,
                       "extractor_version": EXTRACTOR_VERSION, "policy_digest": row.policy_digest, "policy": rules, "status": "partial"}])
            for model, values in (
                (CodeGraphFile, [dict(snapshot_id=identity, **f.model_dump()) for f in result.files]),
                (CodeGraphSymbol, [dict(snapshot_id=identity, key=s.key, **s.model_dump()) for s in result.symbols]),
                (CodeGraphImport, [dict(snapshot_id=identity, **i.model_dump()) for i in result.imports]),
            ):
                if values:
                    db.execute(insert(model), values)
        with engine.connect() as db:
            after = sizes(db, schema)
            wal = int(db.scalar(text("SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), CAST(:start AS pg_lsn))"), {"start": start}))
        git(root, "gc", "--prune=now")
        stats = [p.stat() for p in root.rglob("*") if p.is_file()]
        return {"name": name, "commit": sha, "full_tree_files": len(entries) - 1, "full_tree_admission": admission,
                "source_files": len(manifest), "source_bytes": sum(f["bytes"] for f in manifest),
                "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
                "rows": {"files": len(result.files), "symbols": len(result.symbols), "imports": len(result.imports)},
                "empty_relations": before, "stored_relations": after, "insert_wal_bytes": wal,
                "retained_git_logical_bytes": sum(s.st_size for s in stats),
                "retained_git_allocated_bytes": sum(s.st_blocks * 512 for s in stats)}
    finally:
        with engine.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


if __name__ == "__main__":
    os.environ.update(CM_ENCRYPTION_KEY=base64.urlsafe_b64encode(bytes(32)).decode(),
                      CM_BOOTSTRAP_TOKEN="disposable-storage-measurement", CM_OWNER_GITHUB_LOGIN="fixture")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", nargs=3, action="append", required=True, metavar=("NAME", "PATH", "COMMIT"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine("postgresql+psycopg://mortis:mortis-test-only@127.0.0.1:55439/mortis_test")
    report = {"checked_at": datetime.now(UTC).isoformat(), "extractor_version": EXTRACTOR_VERSION,
              "scope": "DB rows use the exact Phase 0 extension-filtered source corpus. Git storage retains the full shallow commit. Full-tree admission is reported separately.",
              "limits": "One snapshot per corpus; WAL is cluster LSN delta and may include background writes. No peak memory, deployment or GitHub integration claim.", "corpora": []}
    with tempfile.TemporaryDirectory(prefix="cm-graph-storage-") as directory:
        for name, path, commit in args.repo:
            assert name.isidentifier() or name.replace("-", "_").isidentifier()
            report["corpora"].append(measure(name, Path(path), commit, engine, Path(directory)))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Saved {args.output}")
