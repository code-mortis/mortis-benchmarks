"""Historical launchers cannot start retired engines or create new evidence."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class RetirementTests(unittest.TestCase):
    def test_execution_entrypoints_fail_before_creating_output(self):
        for relative in (
            "engine-eval/harness/run.py", "engine-eval/harness/runtime.py",
            "engine-eval/harness/workloads.py", "engine-eval/harness/faults.py",
            "code-graph/harness/quality_run.py", "code-graph/harness/overlap.py",
            "code-graph/harness/overlap_workload.py",
        ):
            with self.subTest(script=relative), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "new-evidence"
                result = subprocess.run(
                    [sys.executable, str(ROOT / relative), "--output", str(output)],
                    cwd=directory, capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("retired", result.stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
