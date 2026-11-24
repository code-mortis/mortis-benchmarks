"""Corpus binding checks without a database or providers."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import faults
import prepare


class FaultTests(unittest.TestCase):
    def test_host_cli_refuses_ocr_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "results"
            with patch.dict("os.environ", {"CM_OCR_ISOLATED_RUNTIME": "false"}), patch("sys.argv", ["faults.py", "--output", str(output)]), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                faults.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertFalse(output.exists())

    def test_all_original_reliability_exports_are_bound_and_mutations_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case_id in faults.CASES:
                with self.subTest(case_id=case_id):
                    case = prepare.prepare_case(prepare.PILOT / case_id, root)
                    export = root / case_id
                    original = faults.verify_fixture(case, export)
                    self.assertEqual(original["case_id"], case_id)
                    changed = copy.deepcopy(case)
                    changed["selected_paths"] = ["different.py"]
                    with self.assertRaisesRegex(ValueError, "identity changed"):
                        faults.verify_fixture(changed, export)
                    context = json.loads((export / "context.json").read_text())
                    context["selection"]["unavailable"] = [{"path": "different.py"}]
                    (export / "context.json").write_text(json.dumps(context))
                    with self.assertRaisesRegex(ValueError, "availability changed"):
                        faults.verify_fixture(case, export)


if __name__ == "__main__":
    unittest.main()
