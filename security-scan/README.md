# Security scan

This suite measures the standalone Mortis Engine security scan. It covers grading, saved finding history, local Git preparation, provider inputs and live CLI performance. The dependency comparison runs Mortis and OSV-Scanner on the same two npm lockfiles.

## Score saved results offline

From the benchmark repository root, run this command. It uses only the Python standard library.

```sh
python3 -B security-scan/harness/score.py security-scan/results/2026-11-28-baseline
```

Exit 0 means all scored checks passed. Exit 1 identifies failed product or performance checks. Exit 2 identifies invalid or missing evidence. Prompt volume is descriptive. The snapshot timing compares a prototype with the original implementation.

## Run the offline checks

Start in the Engine checkout with its development environment installed. Copy the harness to a temporary directory. The snapshot benchmark writes results next to its script.

```sh
ENGINE="$PWD"
RUN=$(mktemp -d)
cp -R ../mortis-benchmarks/security-scan/harness "$RUN/harness"
"$ENGINE/.venv/bin/python" -B "$RUN/harness/coverage_probes.py"
"$ENGINE/.venv/bin/python" -B "$RUN/harness/snapshot_bench.py"
"$ENGINE/.venv/bin/python" -B "$RUN/harness/prompt_bench.py" --output "$RUN/prompt-results.json"
```

The coverage probes print their expected and actual results. Exit code 1 means that at least one expected contract failed. Each probe uses temporary state. The snapshot prototype runs solely inside the benchmark process.

## Run the live measurements

Put the verified Trivy 0.76.2 binary on PATH. Use the Engine Python environment and a saved connection. The CLI sends the generated fixture to that provider. The first scan populates a private Trivy cache. The later scans reuse the cache. Each sample creates a new fixture repository at the same revision, so previous findings cannot affect the measurement. Use fresh output directories for a new experiment.

```sh
"$ENGINE/.venv/bin/python" -B "$RUN/harness/live_bench.py" "$RUN/live" opencode-go
"$ENGINE/.venv/bin/python" -B "$RUN/harness/live_bench.py" "$RUN/live" opencode-go --higher-cap
"$ENGINE/.venv/bin/python" -B "$RUN/harness/dependency_bench.py" "$RUN/live" "$RUN/harness/osv" opencode-go
```

The live benchmark measures `mortis scan` from entry into the CLI's Python function until it returns. It records Trivy command durations, phase start times, coverage, findings and provider-reported tokens. Python process startup is outside the timer. The first live experiment uses a 2,048-token output cap. The warm follow-up uses 8,192. Each scan has a 64,000-token budget and a 180-second deadline. These are experiment settings.

For the native OSV comparison on macOS arm64, put the official 2.7.1 binary at `$RUN/harness/osv/osv-scanner_darwin_arm64`. The runner checks its SHA-256 against the release digest before execution. OSV-Scanner uses its public API and calls no model.

```sh
"$ENGINE/.venv/bin/python" -B "$RUN/harness/osv/run_osv.py"
```

See the [recorded results](results/README.md) for scope, findings and sample sizes.
