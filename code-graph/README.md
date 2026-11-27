# Code Graph Benchmarks

The extraction benchmark compares direct Tree-sitter parsing with Graphify 0.9.37. It reads committed source blobs from Git, runs each extractor in fresh bounded Docker containers, and records extraction time and peak memory. The suite also preserves storage, model context-quality, and resource-overlap experiments.

## Run the extraction benchmark

Requires Git, Python 3.13+, and Docker. Set `CODE_MORTIS` to the absolute path of a local Code Mortis checkout. Run these commands from the repository root:

```sh
mkdir -p .local
docker build -t code-mortis-code-graph-eval:phase0 code-graph/harness
python3 -B code-graph/harness/run.py \
  --repo "$CODE_MORTIS" \
  --output .local/code-graph-extraction.json
```

Add another `--repo` for a second local corpus. The harness reads each checkout's HEAD. The [recorded measurements](results/README.md) list the exact input commits. Each candidate gets three timed runs per repository. Image construction fetches the pinned dependencies. Extraction runs with networking disabled and read-only input.

## Storage and archived experiments

The storage probe uses the Code Mortis backend environment and its isolated PostgreSQL test service on port 55439. With that service ready, run:

```sh
mkdir -p .local
PYTHONPATH="$CODE_MORTIS/backend" "$CODE_MORTIS/backend/.venv/bin/python" -B \
  code-graph/harness/storage.py \
  --repo code-mortis "$CODE_MORTIS" d8a09f12956bf074cdc9f5db868ecf04895eb812 \
  --output .local/code-graph-storage.json
```

The context-quality and resource-overlap launchers are retired. Their source preserves the original experiment, and their [result reports](results/README.md) record the outcomes. The checkpoint tests run offline with `python3 -B -m unittest discover -s code-graph/harness`.

## Standalone Engine graph enrichment

The [enrichment benchmark](harness/graph_enrichment_protocol.md) measures how the standalone Engine selects supporting source from an already validated parser result. It times the current enrichment function and a prototype that indexes imports once. Synthetic graphs cover one to 1,000 assigned paths, including a separate check for source order, byte limits and partial coverage.

Run this command from the benchmark checkout using an Engine development environment and a fresh output path.

```sh
mkdir -p .local
PYTHONPATH="../mortis-engine/src" PYTHONHASHSEED=0 ../mortis-engine/.venv/bin/python -B \
  code-graph/harness/graph_enrichment.py --engine-checkout ../mortis-engine \
  --output .local/graph-enrichment.json
```

## Compare two Engine checkouts

Run the graph enrichment component with the same validated synthetic data and runtime dependencies in both checkouts. This measures how the standalone Engine selects supporting source after the parser returns. Git source collection, Docker, native parsing, provider calls and worker startup are outside the timed region.

Run this command from the benchmarks repository with `BASE` and `CANDIDATE` pointing to local Engine checkouts.

```sh
mkdir -p .local
"$BASE/.venv/bin/python" -B code-graph/harness/graph_enrichment_compare.py \
  --baseline-checkout "$BASE" --candidate-checkout "$CANDIDATE" \
  --output .local/graph-enrichment-checkouts.json
```

The runner defaults to each checkout's `.venv/bin/python`. Worktrees with identical locked dependencies can share a development environment by specifying that interpreter for both `--baseline-python` and `--candidate-python`. Use `--check-fixtures-only` for an untimed preflight.

The comparison uses the workloads, timing and thresholds from the [graph enrichment protocol](harness/graph_enrichment_protocol.md). Each checkout runs in a persistent Python worker with two warm-up and nine measured calls per workload. Calls alternate across workers, and each measured response must match the baseline byte for byte. The JSON records both source revisions, hashes of tracked and untracked changes under `src/mortis_engine`, `pyproject.toml` and `uv.lock`, individual timings, failures and separate Python allocation measurements.
