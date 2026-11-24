# PR Code Navigation Results

Recorded October 29, 2026, with a production frontend build and an authenticated local Code Mortis backend.

| Browser interaction | Samples | Median | p95 |
| --- | ---: | ---: | ---: |
| Reopen Code with Dependencies | 20 | 967 ms | 1,188 ms |
| Switch to a view with a still-valid cached response | 72 | 25 ms | 28 ms |
| Switch to a file with a still-valid cached response | 35 | 29 ms | 31 ms |
| Switch views, including revalidation | 80 | 26 ms | 913 ms |
| Switch files, including initial and expired responses | 40 | 29 ms | 930 ms |

Warm backend medians ranged from 894 to 917 ms across the four views, with 20 samples per view. Idle terminal-PR traffic went from 41 to 5 API requests in the recorded 60-second windows. The baseline reopen consisted of a single 3,899 ms trace with three sequential requests. Sample sizes and network conditions limit comparisons to this local run.

| File | Contents |
| --- | --- |
| [Baseline](baseline-2026-10-29.json) | Original entry trace, warm comparison summaries, and idle counts. |
| [Backend samples](backend-samples-2026-10-29.json) | 84 observations with response sizes, SQL timings, and stage breakdowns. |
| [Browser samples](browser-samples-2026-10-29.json) | 144 observations with click duration and request count. |
| [Summary](summary-2026-10-29.json) | Aggregate browser and backend timings, idle request totals, and limits. |
