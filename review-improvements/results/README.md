# Mortis Engine Review Improvements Results

These files are the original scripted replay artifacts moved from the Mortis Engine repository.

| Run | Engine revision | Discovered | Confirmed true | Confirmed precision | Duplicate candidates / confirmations | Incomplete cases |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| [Frozen baseline](baseline-result.json) | `35fbc999dd7fd4bf42251b22c04059dfdbc51c22` | 1/2 | 1 | 100% | 0 / 0 | 1 |
| [Integrated, single pass](integrated-results.json) | `b86c2ac377e6bb5392d7bbd3cd366aebc941e8bf` | 1/2 | 1 | 100% | 0 / 0 | 0 |
| [Integrated, second pass](integrated-results.json) | `b86c2ac377e6bb5392d7bbd3cd366aebc941e8bf` | 2/2 | 2 | 100% | 0 / 0 | 1 |

The second-pass recording exercised discovery of the caller defect in c03. Normal assessment confirmed it using evidence from the caller and its unchanged dependency. The repeated c01 allegation added no duplicate candidate or confirmation.

All three runs retained unknown usage. The integrated second-pass comparison did not meet the live-quality acceptance gate. These results establish behavior for the five scripted cases. Live-provider quality, billing, and latency remain unmeasured.
