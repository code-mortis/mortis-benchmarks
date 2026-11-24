# Code Mortis Engine Comparison

This suite archives the comparison between Mortis and the former OCR review engine. The synthetic pilot has 12 PR review cases and 8 security cases, including clean controls and reliability fixtures. The scorer reports finding precision and recall, execution outcomes, request and token counts, and latency. A separate acceptance protocol covers frozen workloads and controlled performance.

## Offline checks

From the repository root, with Python 3.13+ and Git:

```sh
python3 -B engine-eval/harness/prepare.py
(
  cd engine-eval/harness
  python3 -B -m unittest test_pilot test_score test_acceptance test_retirement
)
```

The preparation check rebuilds and verifies the frozen pilot manifest. The retirement test checks that the archived OCR/native entry points refuse execution. The tests that import Code Mortis internals also need a Code Mortis checkout with its backend dependencies installed. To run the complete suite, set `CODE_MORTIS` to that checkout's absolute path and run:

```sh
PYTHONPATH="$CODE_MORTIS/backend" "$CODE_MORTIS/backend/.venv/bin/python" -B \
  -m unittest discover -s engine-eval/harness
```

## Scoring retained runs

`score.py score` replays the synthetic pilot scorer with its original run results and adjudications. `acceptance.py score` evaluates sealed acceptance records with the matching scorer revision, seal, run results, evidence, judgments, and any controlled-performance results. Use each command's `--help` for the inputs and pass a fresh output path.

The [results directory](results/README.md) contains selected metrics and provenance from the retained reports. A scoring replay requires the original artifacts. The archived live execution code and Docker recipe are retained for reference.

## App-backed regression tests

These checks exercise the archived harness against a local Code Mortis checkout. Start the app's isolated PostgreSQL and Redis test services as documented in that checkout. Run one app-backed test process at a time because the shared fixtures reset test data. Cases that start production-style prefork workers require Linux.

Set `CODE_MORTIS` to the absolute path of the app checkout. From the benchmarks root:

```sh
BENCHMARKS="$PWD"
(
  cd "$CODE_MORTIS/backend"
  unset CM_DATABASE_URL CM_REDIS_URL
  PYTHONPATH="$PWD:$PWD/tests" .venv/bin/python -B -m pytest -p conftest -q \
    "$BENCHMARKS/engine-eval/tests" "$BENCHMARKS/code-graph/tests"
)
```

This also checks the Code Graph harness and PR navigation probe guards.
