# Mortis Engine Review Improvements

This offline evaluation replays scripted responses through the standalone Mortis Engine planner, discovery, assessment, source expansion, evidence validation, summary, and usage accounting. It covers five synthetic Git changes and the optional second discovery pass.

| Case | Change | Expected outcome |
| --- | --- | --- |
| c01 | Change a divisor to zero | Introduced defect |
| c02 | Change a label alongside existing unsafe division | No introduced defect |
| c03 | Pass zero through a caller into unchanged code | Introduced defect |
| c04 | Document a guarded division and add a regression test | Allegation refuted by the guard and test |
| c05 | Capitalize a greeting | Clean change |

The [baseline manifest](harness/baseline.json) freezes the Git object IDs and hashes of the inputs. Each replay uses temporary Git repositories and isolated local state. The transport is mocked, fixture source is read as data, and the grader reads the expected labels after the requests finish.

## Replay and compare

Use a local Mortis Engine Git checkout with its dev environment installed. Set `MORTIS_ENGINE` to its absolute path. From the benchmarks root:

```sh
mkdir -p .local
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B \
  review-improvements/harness/run.py replay \
  --second-pass --recording review-improvements/harness/fixtures/second-pass.json \
  --output .local/second-pass-result.json
python3 -B review-improvements/harness/run.py compare \
  --baseline review-improvements/results/baseline-result.json \
  --experiment .local/second-pass-result.json
```

Replay requires a fresh output path and records the selected engine revision. Omit `--second-pass` to run one discovery pass. The [results README](results/README.md) identifies the historical revisions and explains what the saved runs establish.

Discovery recall counts unique expected defects with validated candidates. Confirmed precision uses unique confirmed findings. Candidate and confirmation duplicates, incomplete cases, and unknown consumption are recorded independently. The `c05` recording exercises unknown usage, so total tokens remain unavailable.

Use `compare --acceptance review-improvements/harness/acceptance.json` to apply the saved acceptance criteria. An offline replay intentionally fails this gate. Acceptance requires real quality evidence on the same frozen cases, additional confirmed defects, full precision and coverage, zero duplicate confirmations, and observed tokens and billed cost within the configured limits.

## Regression tests

```sh
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B \
  -m pytest -q review-improvements/tests
```

## Standalone Engine caller coverage and preview latency

The [caller coverage protocol](harness/python-callers/protocol.md) checks five deletion previews and five incremental coverage decisions against frozen expectations. Use its JSON outcomes to find the exact call site or reuse decision that differed. The [preview benchmark protocol](harness/preview-git/protocol.md) compares the public Python preview with a prototype that reuses the immediately preceding Git tree lookup. Its output includes the complete set of timings and separate Git process counts.

Run these commands from the benchmarks root with `MORTIS_ENGINE` pointing at an Engine development checkout. Choose a fresh output filename for each run.

```sh
mkdir -p .local
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B \
  review-improvements/harness/python-callers/run.py --output .local/python-callers.json
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B \
  review-improvements/harness/preview-git/run.py --output .local/preview-git.json
```

To reproduce the November 26 review replay comparison, use `harness/fixtures/second-pass.json` as the recording for **both** arms. Run the existing replay command once with second discovery disabled and once with `--second-pass`. Compare those two output files using the existing acceptance criteria. The recorded result includes per-case status, request counts and whether the historical integrated metrics matched.

The public API check repeats four of the incremental cases against two successive calls to `review_commits`. It verifies the saved baseline ID and captures the actual paths sent to a scripted provider. Run this check separately from other state-backed Engine tests.

```sh
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B \
  review-improvements/harness/python-callers/review_commits_probe.py \
  --output .local/python-caller-assignments.json
```
