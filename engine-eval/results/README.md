# Mortis Engine Results

The three November 7–8, 2026 pilots used the same implementer-visible synthetic corpus with OpenCode Go and `muse-spark-1.3-contributor`. Each scheduled 40 outcomes, including six unsupported reliability slots.

| Run | Completed | Other outcomes | Mortis PR recall | Mortis security recall |
| --- | ---: | --- | ---: | ---: |
| [Pilot 01](pilot-01.json) | 33 | 1 failed, 6 unsupported | 7/8 | 5/5 |
| [Pilot 02](pilot-02.json) | 33 | 1 partial, 6 unsupported | 8/8 | 5/5 |
| [Pilot 03](pilot-03.json) | 34 | 6 unsupported | 8/8 | 5/5 |

## M5 corrective run · November 8, 2026

The [frozen M5 score](m5-corrective-2026-11-08.json) recorded **`not_established`**. Both engines detected all 19 PR defects with zero false positives. Each detected 12 of 19 security defects. Security precision remained unresolved, and Mortis missed three high or critical defects.

- The live quality run retained 152 executions. It recorded 138 completed outcomes and 14 fully executed but uncertain security assessments. All 21 scoped reliability checks passed.
- Mortis recorded 170 requests and 682,966 reported tokens. OCR recorded 264 requests and 1,517,154 reported tokens. Six paired cases regressed on token use. Invoice cost was unavailable.
- The controlled latency run used fixed local responses and stopped after 96 of 960 planned executions. Pooled PR p50 was 10.61 seconds for Mortis and 20.41 seconds for OCR, while PR p95 was about 40.5 seconds for both. Performance bounds remained inconclusive.

M5 reused a finite corpus and independent agent judgments. These JSON exports preserve the original score, sample limits, and separate live and synthetic usage totals. They contain selected fields from reports whose SHA-256 hashes appear in `source`.
