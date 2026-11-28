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

### Implemented preview, two-checkout comparison · November 26, 2026

Each checkout ran its public preview in a separate worker. The candidate contained only the two performance changes over v0.1.7 (`b02e6f7`). Both complete previews matched on the edge fixture and all 30 timed calls. The only difference in Git subprocess counts was one fewer `ls-tree` lookup per admitted blob.

| Workload | v0.1.7 median | Implemented median | Git subprocesses |
| --- | ---: | ---: | ---: |
| Branch, 4 files | 199.48 ms | 173.47 ms | 24 → 20 |
| Branch, 80 files | 2,914.34 ms | 2,263.16 ms | 328 → 248 |
| Full tree, 80 files | 2,216.56 ms | 1,588.42 ms | 251 → 171 |

The 80-file median fell by 22.3% for branch previews and 28.3% for full-tree previews, passing the predeclared 15% gate. The four-file control had overlapping sample ranges. See the [individual timings and Git process counts](preview-git-implemented-2026-11-26.json) and [reproduction commands](../harness/preview-git/compare.md).

### Implemented Python caller coverage · November 26, 2026

The candidate used v0.1.7 (`b02e6f7`) with working-tree changes. The frozen fixtures and their scoring expectations came from benchmark commit `37acf18`. The retained reports include the Engine source diff digest, harness hashes, Git revisions and per-case outcomes.

| Check | v0.1.7 | Implemented |
| --- | ---: | ---: |
| [Deletion preview and incremental selection](python-callers-implemented-2026-11-26.json) | 7/10 | 10/10 |
| [Assignments through public review_commits and SQLite history](python-caller-assignments-implemented-2026-11-26.json) | 2/4 | 4/4 |

The multiline relative import now produces a caller site. After removal of an imported function or renaming an optional keyword, the incremental review assigned both the dependency and its caller to the scripted provider. The body-only control still reused the caller. The malformed-source control fell back to full review and the large-file deletion fixture retained explicit partial coverage.

The final Engine checkout passed all 1,468 tests, including the native parser cases. All 19 companion replay tests passed. Ruff, distribution validation and the installed-wheel smoke test also passed. These checks ran offline.

### Caller coverage fixes · November 26, 2026

The [offline rerun](python-caller-fixes-2026-11-26.json) compares the repaired working tree at `277ae12` with v0.1.7. Caller selection passed 10/10 cases (baseline 7/10) and public review assignment passed 4/4 (baseline 2/4). Both scripted replay arms matched the historical case outcomes, including partial coverage for c05 on the second pass.

On the original performance-only comparison, 80-file branch and full-tree previews were 21.3% and 30.8% faster. The full repaired checkout was 25.7% and 31.2% faster against a baseline with matching caller policies. Each pair produced identical previews and saved 80 Git subprocesses on both large workloads.

### Review scope edge cases · November 27, 2026

GitHub main and the clean local Engine checkout both pointed to `2e81e2309970919cf8cb1529b94363ed57829c2c`. The offline runner loaded the source of that commit and v0.1.7 directly from local Git objects. Each of the 27 cases had one warm-up and three timed observations per revision. Outcomes repeated on every sample. These deliberately selected cases measure specific behaviors. [Reproduce the experiment](../harness/review-edge-cases/protocol.md).

| Offline check | v0.1.7 | Main | Current behavior |
| --- | ---: | ---: | --- |
| Git snapshots | 6/10 | 6/10 | Both directions of an unstaged file/directory replacement abort the whole preview. Intent-to-add appears as a staged empty file. A clean Git checkout using `text=auto eol=crlf` appears modified. |
| Caller discovery | 6/11 | 7/11 | Main finds the stale unaliased symbol after a rename. Four cases still disagree with the expected caller ranges. |
| Incremental Python reviews | 3/6 | 3/6 | All three broken callers were marked reused, even with completed initial and subsequent reviews. The required-argument guard and two compatible controls passed. |

The [offline samples](review-edge-cases-2026-11-27.json) record every expected field, actual assignment, API latency and failure. All 11 failing main cases also failed on v0.1.7. Selected examples show where tool users would see the difference.

- **Working-tree snapshots.** An unrelated modification to `app.py` disappears from the output when the preview aborts on either direction of the file/directory replacement. Staging the identical replacement produces the expected plan. All ten fixture fingerprint checks found the original Git and working-tree files intact. [Snapshot file reads](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/snapshots.py#L98-L131)
- **Index and line endings.** Native Git reports an empty staged diff for `git add -N draft.py`. Mortis assigns one zero-byte unit. A genuinely staged empty file is handled correctly. Native Git reports a clean CRLF checkout in both text modes, but Mortis assigns a modified file only for `text=auto`. [Index entries](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/snapshots.py#L66-L77) · [EOL attributes](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/snapshots.py#L154-L160)
- **Shell paths.** A backslash-escaped space in a literal command path produces zero caller sites after its target is deleted. Quoting the same path produces the expected site. [Reference tokenization](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/affected_callers.py#L187-L197)
- **Python aliases and basename collisions.** After a deletion, the planner includes the import but omits the call through its alias on line 10. The unaliased control includes both ranges. In the rename case, the affected-caller range is missing while the primary diff unit still covers the call. Deleting `src/shop/legacy.py` also flags an unrelated import of the surviving `src/legacy.py`. All four caller mismatches report zero discovery limits. [Symbol matching](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/affected_callers.py#L413-L429) · [Basename matching](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/affected_callers.py#L207-L216)
- **Incremental coverage.** With a real saved baseline and a scripted transport, the second review assigns only `billing.py` after each breaking change. Changing an async function to sync breaks the caller's `await`. Reordering two positional-only parameters passes an integer to `len()`. Adding an optional keyword-only parameter previously captured by `**metadata` leaves the caller with a missing dict key. The unrelated control file is correctly reused in each case. These fixtures expose limitations of the current signature comparison. [Signature comparison](https://github.com/code-mortis/mortis-engine/blob/2e81e2309970919cf8cb1529b94363ed57829c2c/src/mortis_engine/review/python_signatures.py#L17-L55)

#### Live shell caller reviews

The [live results](live-shell-callers-2026-11-27.json) cover one review per fixture using the clean main checkout and `muse-spark-1.3-contributor` on OpenCode Go. Both broken forms resolve to the same deleted script. The clean invocation resolves to a surviving sibling. Each fixture includes a version bump to give the reviewer a primary work item.

| Shell operand | Outcome at head | Caller line examined | Confirmed findings | Requests | Reported tokens | Wall seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `"./scripts/rebuild cache.sh"` | Target deleted | Yes | 1, correct at `run.sh:3` | 6 | 31,186 | 100.36 |
| `./scripts/rebuild\ cache.sh` | Target deleted | No | 0 | 3 | 7,436 | 12.65 |
| `./scripts/refresh\ cache.sh` | Target exists | No | 0 | 3 | 7,935 | 19.03 |

All three reviews exited 0, reported completed workflows and had zero errors or discovery limits. The escaped caller had no assigned site and no finding. The quality gate passed on 2/3 cases. Across these three observations, the reviewer confirmed 1/2 seeded defects and reported zero false findings. Total reported usage was 46,557 tokens over 12 request records. Billed cost is unknown.

### Review scope fixes · November 27, 2026

The [offline comparison](review-edge-cases-fixed-2026-11-27.json) measures committed main `2e81e23` against the uncommitted Engine fixes on that same checkout. The candidate workers loaded a snapshot of 76 source files identified by SHA-256 `c060e7976d5f992e79b9b1dab5d3625f7349645bf2725a30ef7a06b28c22d927`. Both arms used the original inputs, expected fields, one warm-up and three timed repetitions per case. See the [working-tree reproduction command](../harness/review-edge-cases/protocol.md#comparing-local-fixes-with-main).

| Offline check | Committed main | Patched working tree |
| --- | ---: | ---: |
| Git snapshots | 6/10 | 10/10 |
| Deleted and renamed callers | 7/11 | 11/11 |
| Incremental Python reviews | 3/6 | 6/6 |

All 11 original failures reproduced on the baseline and passed after the fixes. All 16 prior passing cases continued to pass. The result includes every observation and timing. The full Engine pytest suite with the pinned native parser reported `1514 passed in 236.05s (0:03:56)`. Engine Ruff and Git whitespace checks passed.

The first candidate already passed [all 27 offline cases](review-edge-cases-scope-fixes-2026-11-27.json). In its [initial live checks](live-shell-callers-scope-fixes-2026-11-27.json), both broken invocations received completed caller ranges at `run.sh:3`, but assessment returned uncertain. The assessor saw only `version.py` in the changed-path index and an empty caller diff. The escaped case also had a summary validation error. These three initial reviews consumed 76,008 reported tokens over 17 requests. The final candidate supplies the Git-verified dependency change separately from the model's proposed finding when assessing caller reachability.

The [final live CLI checks](live-shell-callers-fixed-2026-11-27.json) used the same three synthetic commit pairs, single-pass settings, and OpenCode Go model as the [original live run](live-shell-callers-2026-11-27.json). The patched CLI loaded the same Engine source digest as the offline candidate.

| Live case | Earlier findings | Patched findings | Caller line examined | Requests | Reported tokens | Wall seconds |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| Quoted deleted path | 1 | 1 | Yes | 4 | 18,219 | 57.08 |
| Escaped deleted path | 0 | 1 | Yes | 4 | 17,265 | 47.10 |
| Escaped surviving path | 0 | 0 | No | 3 | 8,261 | 21.00 |

The live grader matched 3/3 cases, with 2/2 seeded defects confirmed at the invocation and 0 extra findings. 3/3 workflows completed with full reported coverage. There was one live observation per fixture. The provider reported 43,745 tokens across 11 request records. Billed cost is unknown.
