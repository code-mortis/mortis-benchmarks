# Security scan results

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
