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
