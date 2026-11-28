# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Purpose

Evaluation harnesses and recorded results for the Code Mortis app and the standalone Mortis Engine (sibling `../mortis-engine`). Nothing here is a package. There is no pyproject, Makefile or CI. Each suite is a set of standalone Python 3.13+ scripts (stdlib-first) that run against a separate checkout of the code under test, plus JSON results committed as historical evidence.

## Layout

Each suite has `README.md`, `harness/` (scripts, fixtures, protocols) and `results/` (recorded JSON plus a results README). Some suites also have `tests/`.
- `review-improvements/`: offline replay of the Mortis Engine review pipeline (planner, discovery, assessment, usage accounting) using scripted provider responses and a mocked transport. Also covers caller coverage (`harness/python-callers/`), preview latency (`harness/preview-git/`) and review edge cases (`harness/review-edge-cases/`).
- `engine-eval/`: archived comparison of Mortis with the former OCR engine. `prepare.py` rebuilds and verifies the frozen pilot manifest. `score.py` and `acceptance.py` re-score retained runs. The live execution path is retired, and `test_retirement` asserts that it refuses to run.
- `code-graph/`: Tree-sitter vs Graphify extraction in Docker (`run.py`), storage probe, and Engine graph-enrichment timing (`graph_enrichment.py`, `graph_enrichment_compare.py`). Context-quality and overlap launchers are retired.
- `pr-code-performance/`: `probe.py` is piped into a running Code Mortis dev stack's `api` container.

## Commands (from the repo root)

Offline, with no external checkout needed:
```sh
python3 -B engine-eval/harness/prepare.py
(cd engine-eval/harness && python3 -B -m unittest test_pilot test_score test_acceptance test_retirement)
python3 -B -m unittest discover -s code-graph/harness
python3 -B review-improvements/harness/run.py compare --baseline <a.json> --experiment <b.json> [--acceptance review-improvements/harness/acceptance.json]
```

Engine-backed: set `MORTIS_ENGINE` to the absolute path of an Engine dev checkout with `.venv` installed.
```sh
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B -m pytest -q review-improvements/tests
PYTHONPATH="$MORTIS_ENGINE/src" "$MORTIS_ENGINE/.venv/bin/python" -B review-improvements/harness/run.py replay \
  [--second-pass] --recording review-improvements/harness/fixtures/second-pass.json --output .local/<new>.json
```

App-backed: set `CODE_MORTIS` to a Code Mortis checkout. Use `PYTHONPATH="$CODE_MORTIS/backend" "$CODE_MORTIS/backend/.venv/bin/python"` for the full `engine-eval/harness` unittest discover and for `code-graph/harness/storage.py`. The `engine-eval/tests` and `code-graph/tests` pytest suites run from inside `$CODE_MORTIS/backend` with `-p conftest`. See `engine-eval/README.md` for the exact invocation. They need the app's PostgreSQL and Redis test services. Run only one app-backed test process at a time, because the shared fixtures reset data. Prefork-worker cases need Linux.

## Conventions and gotchas

- Always run Python with `-B`, from the repo root. Scripts resolve paths relative to their own file, but the documented commands assume the root.
- Write all local output under `.local/`, which is gitignored. Harnesses require a fresh output path and refuse to overwrite one.
- `results/` files are historical records. Don't regenerate or edit existing ones. Add new dated files (`<name>-YYYY-MM-DD.json`) and document each in that suite's `results/README.md` (harness and input revisions, environment, sample size, metrics, incomplete work).
- Frozen inputs are pinned by hashes and Git object IDs (`review-improvements/harness/baseline.json`, `engine-eval/harness/pilot_manifest.json`, `BASELINE_REVISION` in `review-improvements/harness/run.py`). Changing a fixture breaks verification on purpose.
- Fixture source is treated as data and never executed. Graders read expected labels only after requests finish. Keep truth and oracle files out of anything sent to the engine.
- Harness Git calls strip `GIT_*` env vars, disable global/system config and hooks, and pin author and date so results stay deterministic. Keep these settings in any new Git helper.
- An offline replay intentionally fails the acceptance gate. It never counts as evidence of live model quality.
- `code-graph/harness/requirements.txt` is a uv-generated, hash-locked file for the Docker image. Regenerate it with uv rather than editing it by hand.
- The `review_commits_probe.py` public-API check is state-backed. Run it separately from other Engine tests.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
