# Mortis Engine Review Improvements Results

These files are the original scripted replay artifacts moved from the Mortis Engine repository.

| Run | Engine revision | Discovered | Confirmed true | Confirmed precision | Duplicate candidates / confirmations | Incomplete cases |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [Frozen baseline](baseline-result.json) | `35fbc999dd7fd4bf42251b22c04059dfdbc51c22` | 1/2 | 1 | 100% | 0 / 0 | 1 |
| [Integrated, single pass](integrated-results.json) | `b86c2ac377e6bb5392d7bbd3cd366aebc941e8bf` | 1/2 | 1 | 100% | 0 / 0 | 0 |
| [Integrated, second pass](integrated-results.json) | `b86c2ac377e6bb5392d7bbd3cd366aebc941e8bf` | 2/2 | 2 | 100% | 0 / 0 | 1 |

The second-pass recording exercised discovery of the caller defect in c03. Normal assessment confirmed it using evidence from the caller and its unchanged dependency. The repeated c01 allegation added no duplicate candidate or confirmation.

All three runs retained unknown usage. The integrated second-pass comparison did not meet the live-quality acceptance gate. These results establish behavior for the five scripted cases. Live-provider quality, billing, and latency remain unmeasured.

## Standalone Engine checks · November 26, 2026

Engine `b02e6f7b4ec67b8d25b8e2de05502ee8835b133c` and the existing replay harness at benchmark revision `edc74c27e2259e7967a57bb1cc2ccc630b8895a0` were clean at measurement time. The new standalone harnesses are identified by their recorded SHA-256 digests. All cases used synthetic data on Python 3.15.2.

| Check | Result |
| --- | --- |
| [Python caller selection](python-callers-2026-11-26.json) | 7 of 10 matched their frozen expectations. After deleting a module, a multiline relative import of that module produced no caller site and no discovery-limit warning. Two incremental cases reused a caller with a broken binding. |
| [Public incremental review](python-caller-assignments-2026-11-26.json) | Real Git, SQLite history and scripted transport corroborated the two incremental misses. After deleting the imported function or renaming the optional keyword passed by the caller, the second review sent only the dependency for analysis. Both control cases passed. |
| [Single and second discovery passes](replay-2026-11-26.json) | Across the same five cases and identical recording, one pass confirmed 1 of 2 expected defects in 14 requests. Two passes confirmed 2 of 2 in 20. Both matched the historical integrated outcomes, with zero false or duplicate confirmations. The second-pass run marked c05 partial due to unknown usage. The live-quality and billing criteria remain unevaluated. |

The public deletion preview accepted the equivalent one-line relative import and the multiline absolute import. The incremental policy currently documents required and variadic parameter changes. Removal of an exported function and renaming an optional keyword are candidates for broader invalidation. The body-only control still reused the caller.

The offline Engine suite passed 1,446 tests. Three optional native parser cases were skipped because `tree_sitter` was unavailable. All 19 review replay harness tests passed. To reproduce the individual experiments, see the [suite commands](../README.md). The [graph enrichment results](../../code-graph/results/README.md) cover a separate Engine component.

### Public preview latency

Reusing one validated tree lookup per admitted file removed 80 Git subprocesses from each 80-file preview. All 30 timed previews matched their reference output, and a separate parity check covered unusual filenames, unreadable source, exclusions and a deleted module with a surviving caller. Each arm used one warm-up and five timed calls per workload.

| Synthetic workload | Current median | Prototype median | Median reduction | Current → prototype Git calls |
| --- | ---: | ---: | ---: | ---: |
| Branch, 4 modified files | 215 ms | 188 ms | 12.4% | 24 → 20 |
| Branch, 80 modified files | 3,125 ms | 2,360 ms | 24.5% | 328 → 248 |
| Full tree, 80 files | 2,093 ms | 1,437 ms | 31.3% | 251 → 171 |

Both 80-file comparisons passed the predeclared 15% latency threshold. The small control had overlapping timing ranges. Timings cover the public Python preview on local, warm filesystem caches. The implementation opportunity is to pass the already validated blob ID and size into the reader and retain the existing decoding, cancellation and size checks. See the [individual samples, process counts, exclusions and input hashes](preview-git-2026-11-26.json).
