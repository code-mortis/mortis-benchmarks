import os
import subprocess
import sys
from pathlib import Path

import pytest

SUITE = Path(__file__).resolve().parents[1]
HARNESS = SUITE / "harness"
PROBE_ARGS = ["--login", "missing", "--pr-id", "pr", "--path", "main.py"]


def test_direct_snapshot_isolates_unreadable_files(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(HARNESS))
    from evaluate import direct

    (tmp_path / "legacy.py").write_bytes(b'# coding: latin-1\nlog("caf\xe9")\n')
    (tmp_path / "python2.py").write_text("print 1\n")
    (tmp_path / "valid.py").write_text("from .target import f\n")
    (tmp_path / "target.py").write_text("def f(): pass\n")
    result = direct(tmp_path)
    assert result["statuses"] == {
        "legacy.py": "partial", "python2.py": "partial", "valid.py": "parsed", "target.py": "parsed",
    }
    assert [site["target"] for site in result["imports"]] == ["target.py"]


@pytest.mark.parametrize(("v2", "v1", "expected"), [
    ("4096\n", "8192\n", 4096),
    (FileNotFoundError(), "8192\n", 8192),
    (PermissionError(), "8192\n", 8192),
    ("invalid", "8192\n", 8192),
    (FileNotFoundError(), FileNotFoundError(), None),
    (PermissionError(), PermissionError(), None),
    ("invalid", "", None),
])
def test_cgroup_peak_handles_unavailable_counters(monkeypatch, v2, v1, expected):
    monkeypatch.syspath_prepend(str(HARNESS))
    from evaluate import cgroup_peak_bytes

    counters = {
        Path("/sys/fs/cgroup/memory.peak"): v2,
        Path("/sys/fs/cgroup/memory/memory.max_usage_in_bytes"): v1,
    }

    def read_text(path):
        value = counters[path]
        if isinstance(value, OSError):
            raise value
        return value

    monkeypatch.setattr(Path, "read_text", read_text)
    assert cgroup_peak_bytes() == expected


@pytest.mark.parametrize(("script", "args", "error"), [
    (SUITE.parent / "pr-code-performance/harness/probe.py", [*PROBE_ARGS, "--samples", "0"], "--samples must be between 1 and 100"),
    (SUITE.parent / "pr-code-performance/harness/probe.py", [*PROBE_ARGS, "--samples", "101"], "--samples must be between 1 and 100"),
    (SUITE.parent / "pr-code-performance/harness/probe.py", PROBE_ARGS, "User not found"),
    (HARNESS / "quality_run.py", ["--authorized", "--requests", "requests.json", "--output", "out.json",
                                        "--connection-id", "unused"], "historical OCR/native evaluation is retired"),
    (HARNESS / "overlap_workload.py", ["database"], "historical OCR/native overlap evaluation is retired"),
])
def test_script_guards_survive_optimized_python(tmp_path, script, args, error):
    env = os.environ.copy()
    if script.name == "overlap_workload.py":
        env["CM_DATABASE_URL"] = "sqlite:///:memory:"
    result = subprocess.run([sys.executable, "-O", str(script), *args],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert error in result.stderr
    assert not (tmp_path / "out.json").exists()
