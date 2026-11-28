"""Measure security prompt source amplification without provider dispatch."""

import argparse
import asyncio
import hashlib
import json
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from mortis_engine.review import file_policy
from mortis_engine.security_scans.inference import ask
from mortis_engine.workflow import Session


COUNTS = (1, 8, 16, 17)
SOURCE_BYTES = 1024


def make_source(index):
    function = f"def sample_{index:02d}(value):\n    return value.strip()\n"
    source = function + "# benign synthetic input for prompt packing measurement\n"
    padding = "#" + (" x" * 64) + "\n"
    while len(source.encode()) + len(padding.encode()) <= SOURCE_BYTES:
        source += padding
    source += "#" + "x" * (SOURCE_BYTES - len(source.encode()) - 2) + "\n"
    encoded = source.encode()
    if len(encoded) != SOURCE_BYTES:
        raise RuntimeError(f"Expected {SOURCE_BYTES} source bytes, got {len(encoded)}")
    return source


class SyntheticSnapshot:
    def __init__(self, root, count):
        self.sha = "a" * 40
        self.policy = file_policy.policy({})
        self.files = root / "files"
        self.files.mkdir()
        self.inventory = {}
        self.sources = {}
        self.source_reads = 0
        for index in range(count):
            path = f"src/module_{index:02d}.py"
            text = make_source(index)
            target = self.files / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            self.inventory[path] = {"code": True}
            self.sources[path] = text

    def source(self, path, sha=None):
        self.source_reads += 1
        return self.sources[path]

    @staticmethod
    def redact(value):
        return value

    @staticmethod
    def stopped():
        return False


class CaptureSession(Session):
    def __init__(self):
        super().__init__({}, {})
        self.dispatches = []

    async def ask(self, stage, key, **kwargs):
        request = self.request(
            stage,
            key,
            instructions=kwargs["instructions"],
            context=kwargs["context"],
            schema=kwargs["schema"],
            effort=kwargs["effort"],
            max_output_tokens=kwargs["max_output_tokens"],
        )
        context = kwargs["context"]
        sources = context.get("sources", {}).get("current", {})
        packed = request.messages[0].content.encode("utf-8")
        self.dispatches.append({
            "stage": stage,
            "key": key,
            "raw_source_bytes": sum(len(source.encode("utf-8")) for source in sources.values()),
            "source_paths": sorted(sources),
            "packed_context_bytes": len(packed),
            "packed_context_sha256": hashlib.sha256(packed).hexdigest(),
        })
        return kwargs["validate"]({"findings": [], "required_paths": []})


async def measure(count):
    with tempfile.TemporaryDirectory(prefix="mortis-prompt-bench-") as temporary:
        item = SyntheticSnapshot(Path(temporary), count)
        session = CaptureSession()
        options = {
            "language": "English",
            "effort": "low",
            "max_output_tokens": 512,
            "token_budget": None,
            "assessment_token_budget": None,
            "verification_token_budget": None,
            "timeout_seconds": None,
        }
        paths = sorted(item.inventory)
        for path in paths:
            context = {
                "assigned_path": path,
                "head_sha": item.sha,
                "diff": "",
                "sources": {"current": {path: item.source(path)}},
            }
            await ask(item, session, "analysis", context, "analysis:" + path, options)
        unique_corpus_source_bytes = sum(len(source.encode("utf-8")) for source in item.sources.values())
        source_bytes_across_requests = sum(row["raw_source_bytes"] for row in session.dispatches)
        packed_context_bytes_across_requests = sum(row["packed_context_bytes"] for row in session.dispatches)
        return {
            "source_files": count,
            "source_bytes_each": SOURCE_BYTES,
            "dispatch_count": len(session.dispatches),
            "unique_corpus_source_bytes_by_path": unique_corpus_source_bytes,
            "distinct_file_content_bytes": len({source.encode("utf-8") for source in item.sources.values()}),
            "source_bytes_across_requests": source_bytes_across_requests,
            "source_replication_factor": source_bytes_across_requests / unique_corpus_source_bytes,
            "packed_context_bytes_across_requests": packed_context_bytes_across_requests,
            "packed_context_bytes_per_request": [row["packed_context_bytes"] for row in session.dispatches],
            "raw_source_bytes_per_request": [row["raw_source_bytes"] for row in session.dispatches],
            "source_paths_per_request": [len(row["source_paths"]) for row in session.dispatches],
            "source_read_count": item.source_reads,
            "dispatches": session.dispatches,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path.cwd() / "prompt-results.json",
                        help="Write JSON results here (default: ./prompt-results.json)")
    args = parser.parse_args()
    results = [asyncio.run(measure(count)) for count in COUNTS]
    source_hashes = {
        relative: hashlib.sha256((Path.cwd() / relative).read_bytes()).hexdigest()
        for relative in (
            "src/mortis_engine/security_scans/inference.py",
            "src/mortis_engine/security_scans/payload.py",
            "src/mortis_engine/security_scans/context.py",
            "src/mortis_engine/workflow.py",
        )
    }
    engine_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    data = {
        "schema_version": "mortis.security.prompt-amplification-benchmark/v1",
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "offline deterministic prompt construction with actual security inference and payload packing",
        "protocol": {
            "source_file_counts": list(COUNTS),
            "source_bytes_each": SOURCE_BYTES,
            "source_language": "Python",
            "source_content": "Benign equivalent synthetic functions with per-file names and padding comments",
            "task": "One actual inference.ask analysis invocation per assigned source file",
            "provider_calls": 0,
            "saved_state_or_history": False,
            "capture_point": "Session.request after inference.ask compacts evidence and before provider transport",
            "byte_metrics": {
                "unique_corpus_source_bytes_by_path": "Each distinct repository path counted once",
                "source_bytes_across_requests": "UTF-8 bytes in current source maps passed to each request",
                "packed_context_bytes_across_requests": "UTF-8 bytes in the actual packed user message built by Session.request",
            },
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cwd": str(Path.cwd()),
            "engine_revision": engine_revision,
            "engine_source_sha256": source_hashes,
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "runs": results,
        "conclusion": {
            "replication_at_or_below_16": "confirmed" if all(
                row["source_replication_factor"] == row["source_files"] for row in results if row["source_files"] <= 16
            ) else "not_confirmed",
            "reason": "For 1, 8, and 16 Python files, the actual analysis context prefills all source when aggregate source is at most 32 KiB. The harness sends one analysis request per assigned file, so each corpus source is repeated across that many requests.",
            "17_file_behavior": "The prefill branch stops applying above 16 files. The 17-file corpus therefore sends one assigned file per request, although Python source navigation still reads the corpus for local hints.",
        },
        "limitations": [
            "Measures source bytes and packed user-message bytes, not provider tokenizer token counts or billing.",
            "Uses benign synthetic files and a capture session that returns a validated empty analysis result.",
            "No Trivy, provider, HTTP, database, or saved history access occurs.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "conclusion": data["conclusion"]["replication_at_or_below_16"],
        "runs": [{key: row[key] for key in (
            "source_files", "dispatch_count", "unique_corpus_source_bytes_by_path",
            "source_bytes_across_requests", "source_replication_factor",
            "packed_context_bytes_across_requests", "source_read_count")}
            for row in results],
    }, indent=2))


if __name__ == "__main__":
    main()
