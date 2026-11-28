# Security scan results

## 2026-11-28 scan regression fixes

All eight security-scan checks passed. The pre-fix branch and fixed working tree produced identical coverage probe results, prompt measurements and snapshot contents. Snapshot Git process counts also matched. [Score](2026-11-28-scan-regressions/score.json) · [Measurements and revisions](2026-11-28-scan-regressions/comparison.json)

All seven live `opencode-go` timing scans covered both files and found the Dockerfile root-user setting. The warm median was 10.48 seconds with a 2,048-token output cap and 10.24 seconds with an 8,192-token cap. The first timing samples overlapped the local test suite. Mortis and OSV-Scanner agreed on both dependency controls. The mixed-manifest scan identified the missing npm inventory and withheld its grade. Total provider-reported usage was 33,800 tokens. [Live samples](2026-11-28-scan-regressions/live-cap-2048.json) · [Higher-cap samples](2026-11-28-scan-regressions/higher-cap-results.json) · [Mixed manifest](2026-11-28-scan-regressions/mixed-results.json)

For 250 sequential scans, the history fields in the last saved plan fell from 8,750 bytes to 28 bytes. Median `list_findings` time fell from 5.90 ms to 0.64 ms. Each lookup returned the same open finding and revision. To repeat this component measurement, run the Engine Python interpreter with `security-scan/harness/history_lookup_bench.py OUTPUT.json`. [History benchmark](../harness/history_lookup_bench.py)

## 2026-11-28 scan fixes

All eight checks passed on the Engine working tree based on `b358049a61fa`. The [score](2026-11-28-scan-fixes/score.json) and [file hashes](2026-11-28-scan-fixes/provenance.json) identify this run. To replay it from the benchmark repository, run `python3 -B security-scan/harness/score.py security-scan/results/2026-11-28-scan-fixes`.

| Check | Result |
| --- | --- |
| [Evidence, dependency coverage and overlapping scans](2026-11-28-scan-fixes/probe-results.jsonl) | All three contract checks passed. |
| [OpenCode with a 2,048-token output cap](2026-11-28-scan-fixes/live-cap-2048.json) | All four scans completed, including the cold scan. Each covered both files and found the root-user Dockerfile setting. |
| [OpenCode with an 8,192-token output cap](2026-11-28-scan-fixes/higher-cap-results.json) | All three warm scans completed. The median elapsed time was 11.2 seconds. |
| [Mixed manifest](2026-11-28-scan-fixes/mixed-results.json) | The report named the missing npm inventory, retained partial status and withheld the grade. |
| [Mortis](2026-11-28-scan-fixes/dependency-results.json) and [OSV-Scanner](2026-11-28-scan-fixes/osv-result.json) | Both found the advisory for minimist 1.2.5 and cleared the 1.2.8 control. |
| [Snapshot prototype](2026-11-28-scan-fixes/snapshot-results.json) | The prototype met both timing and Git process thresholds on 20 and 100 files. The output digests matched. |

The [prompt measurements](2026-11-28-scan-fixes/prompt-results.json) show one copy of each assigned source file across the initial requests for 1, 8, 16 and 17 files. The harness also includes the original hypothesis in its explanation. The seven live timing samples used 25,374 provider-reported tokens. The mixed-manifest scan used 8,617 more. The earlier [2,048-token series](2026-11-28-scan-fixes/attempts/01-live-cap-2048.json) completed two of four samples. It exhausted the output limit twice on each partial sample. All recorded candidate runs used 69,653 tokens in total. Invoice cost was unavailable.

The final Engine test suite passed 1,586 tests. Three optional code graph tests were skipped because Tree-sitter was unavailable. Ruff passed. Both the wheel and source distribution built successfully.

## 2026-11-28 baseline

The standalone Engine working tree was based on `a4a52ea591591b32e0ff9c64579d24de6aeb61dd`. The live records include the working diff digest. The historical results include partial runs. Replay the [offline scorer](../harness/score.py) to see each verdict.

| Check | Recorded result |
| --- | --- |
| [Coverage and saved history](2026-11-28-baseline/probe-results.jsonl) | Three of three synthetic contract checks failed. |
| [Mixed manifest](2026-11-28-baseline/mixed-results.json) | Trivy marked its stage complete without reporting the npm coverage gap. An uncertain AI assessment made the overall scan partial. |
| [2,048 output tokens](2026-11-28-baseline/live-cap-2048.json) | One of four scans completed. Three retained Trivy findings after the Dockerfile analysis exhausted its output cap. |
| [8,192 output tokens](2026-11-28-baseline/higher-cap-results.json) | Three of three warm scans completed. Median time was 30.0 seconds. |
| [Mortis](2026-11-28-baseline/dependency-results.json) and [OSV-Scanner](2026-11-28-baseline/osv-result.json) | Both detected the affected version and cleared the updated control. The [initial OSV attempt](2026-11-28-baseline/osv-sandbox-attempt.json) failed before advisory lookup. |
| [Snapshot prototype](2026-11-28-baseline/snapshot-results.json) | For 100 files, median time fell from 1.77 s to 0.93 s and Git processes fell from 203 to 102. The compared outputs matched. |
| [Prompt input](2026-11-28-baseline/prompt-results.json) | Source was included 16 times across 16 requests for 16 files and once across 17 requests for 17 files. |

The seven OpenCode timing samples reported 58,815 tokens. The mixed-manifest scan reported 8,714 more. Invoice cost was unavailable. The OSV and Mortis dependency comparison used one sample per lockfile. The prompt record omits the machine-specific working directory.
