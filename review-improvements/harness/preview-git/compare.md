# Review preview benchmark across Engine checkouts

Compare the public Python preview between the baseline and the actual Engine implementation. Use the [prototype benchmark](protocol.md) fixtures and thresholds. Each arm imports source from its own checkout in a persistent isolated worker running the same Python interpreter. Timing covers the public API call, including its fresh repository snapshot and plan assembly. Worker startup, fixture setup, JSON transport and Git process counting are outside the timing.

The checks compare complete preview dictionaries for each workload, warm-up and timed sample. The untimed edge fixture checks successful reads of unusual filenames and an executable, explicit symlink and UTF-8 errors, exclusions for binary and deleted paths, and discovery of a surviving caller. The timed workloads use one warm-up and five alternating pairs each. Both 80-file workloads must reduce median wall time by at least 15%. A separate invocation counts Git subprocesses and checks that the only reduction in total count comes from the expected 4, 80, 80 and 5 `ls-tree` calls across the three workloads and the edge fixture.

## Reproduce

Use Python 3.13–3.15 from an Engine development environment with its dependencies installed. Set `MORTIS_ENGINE` to that checkout. Set `BASELINE` and `CANDIDATE` to the checkouts to compare. Run from the benchmark repository and choose a fresh output filename.

```sh
mkdir -p .local
"$MORTIS_ENGINE/.venv/bin/python" -I -B \
  review-improvements/harness/preview-git/compare.py \
  --baseline "$BASELINE" --candidate "$CANDIDATE" \
  --output .local/preview-git-implementation.json
```

Add `--verify-only` to run parity, fixture and process-count checks without collecting timing samples.

The implementation comparison starts at Engine v0.1.7 checkout `b02e6f7b4ec67b8d25b8e2de05502ee8835b133c`. To reproduce the performance-only candidate, start a separate checkout at that revision and apply only the changes to the three paths below from the checkout containing the combined implementation. Set `COMBINED_CHECKOUT` to the latter and `CANDIDATE` to the separate checkout.

```sh
git -C "$COMBINED_CHECKOUT" diff b02e6f7b4ec67b8d25b8e2de05502ee8835b133c -- \
  src/mortis_engine/code_graph/__init__.py \
  src/mortis_engine/review/planning.py \
  src/mortis_engine/review/source.py |
  git -C "$CANDIDATE" apply
```

The result records the revision and dirty status for each checkout, a digest of its tracked diff, a digest of tracked and untracked source contents, and both harness digests. Use those fields to confirm the compared revisions and patch. The case records include input commits, output digests, individual timings and the number of actual Git child launches.
