"""Export inert Git blobs and benchmark both candidates in fresh bounded containers."""

import argparse
import hashlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".cpp", ".rb", ".cs", ".php", ".sh"}
IMAGE = "code-mortis-code-graph-eval:phase0"


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def export(repo, destination):
    commit = command(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    tree = command(["git", "-C", str(repo), "ls-tree", "-rlz", commit])
    manifest, excluded = [], []
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, blob, size = metadata.decode().split()
        name = raw_name.decode()
        path = Path(name)
        if kind != "blob" or mode not in ("100644", "100755") or path.suffix not in EXTENSIONS:
            continue
        assert not path.is_absolute() and ".." not in path.parts
        if int(size) > 1024 * 1024:
            excluded.append({"path": name, "reason": "file_over_1_MiB"})
            continue
        manifest.append({"path": name, "blob": blob, "bytes": int(size)})
    assert len(manifest) <= 2000, "evaluation corpus exceeds 2,000 files"
    assert sum(item["bytes"] for item in manifest) <= 32 * 1024 * 1024, "evaluation corpus exceeds 32 MiB"
    # cat-file reads Git objects; it does not check out files or run filters/hooks.
    batch = command(["git", "-C", str(repo), "cat-file", "--batch"],
                    input="".join(item["blob"] + "\n" for item in manifest).encode())
    offset = 0
    for item in manifest:
        end = batch.index(b"\n", offset)
        header = batch[offset:end].decode().split()
        assert header == [item["blob"], "blob", str(item["bytes"])]
        data = batch[end + 1:end + 1 + item["bytes"]]
        output = destination / item["path"]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        offset = end + 2 + item["bytes"]
    return {"name": repo.name, "commit": commit, "files": len(manifest),
            "bytes": sum(item["bytes"] for item in manifest), "excluded": excluded,
            "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()}


def run_container(corpus, engine, mode):
    name = "cm-graph-phase0-" + uuid.uuid4().hex[:12]
    memory = 256 if engine == "direct" else 512
    arguments = ["docker", "run", "--rm", "--name", name, "--network", "none",
                 "--memory", f"{memory}m", "--memory-swap", f"{memory}m", "--cpus", "1", "--pids-limit", "32",
                 "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m,mode=1777",
                 "--mount", f"type=bind,src={corpus},dst=/corpus,readonly",
                 "--mount", f"type=bind,src={HERE},dst=/evaluation,readonly", IMAGE, engine, mode]
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"{engine}/{mode} exit={result.returncode}: {result.stderr[-6000:]}")
        output = json.loads(result.stdout)
        output["diagnostics"] = result.stderr.strip().splitlines()
        return output
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"format": 1, "limits": {"memory_MiB": {"direct": 256, "graphify": 512}, "tmpfs_MiB": 128, "cpus": 1, "pids": 32, "timeout_seconds": 120},
              "image": command(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], text=True).strip(),
              "docker": command(["docker", "info", "--format", "{{.OSType}} {{.Architecture}} CPUs={{.NCPU}} Memory={{.MemTotal}}"], text=True).strip(),
              "harness_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.iterdir()) if p.is_file()},
              "corpora": [], "probes": {}}
    with tempfile.TemporaryDirectory(prefix="cm-graph-eval-") as temporary:
        root = Path(temporary)
        fixtures = root / "fixtures"
        for name, source in json.loads((HERE / "fixtures.json").read_text()).items():
            path = fixtures / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        for engine in ("direct", "graphify"):
            print(f"Checking fixtures: {engine}", flush=True)
            result["probes"][engine] = run_container(fixtures, engine, "probe")
        for index, repo in enumerate(args.repo):
            corpus = root / f"repo-{index}"
            corpus.mkdir()
            metadata = export(repo.resolve(), corpus)
            runs = []
            for engine in ("direct", "graphify"):
                for repetition in range(3):
                    print(f"Benchmarking {metadata['name']}: {engine} {repetition + 1}/3", flush=True)
                    runs.append(run_container(corpus, engine, "benchmark"))
            result["corpora"].append({**metadata, "runs": runs})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Saved {args.output}")
