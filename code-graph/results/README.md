# Code Graph Results

## Extraction · October 26, 2026

[Recorded extraction runs](extraction-2026-10-26.json) used three fresh one-CPU containers per candidate and corpus on Linux arm64. Time is the median across three runs. Peak memory is the maximum cgroup measurement.

| Corpus | Direct time | Graphify time | Direct peak | Graphify peak |
| --- | ---: | ---: | ---: | ---: |
| Code Mortis · 244 files | 1.2145 s | 4.5081 s | 81.9 MiB | 226.3 MiB |
| Noodle · 653 files | 1.2271 s | 6.1757 s | 77.0 MiB | 487.7 MiB |

- Code Mortis revision: `d8a09f12956bf074cdc9f5db868ecf04895eb812`
- Noodle revision: `2153c7745e66b72f48dee76b992e91b3be7c653f`

Time includes extraction and JSON sizing. The timer excludes Git export, Docker startup, and database persistence. The result JSON keeps the individual timings and the separate process RSS measurements.

## Other experiments

| Result | Scope and outcome |
| --- | --- |
| [Storage](storage.json) | One snapshot per corpus. Records relation sizes, WAL growth, and retained Git bytes. |
| [Context quality](context-quality.json) | 18 completed answers across six matched cases and three context strategies. None of the strategies confirmed a target defect. The graph arm correctly classified two fixed controls and the rollout gate remained unmet. |
| [Resource overlap](overlap.json) | Concurrent graph, review, security, and database workloads. Over 360 seconds, simultaneous container memory peaked at 2.49 GiB. Model and GitHub responses were stubbed. The security workload remained partial because vulnerability advisory data was stale. |
