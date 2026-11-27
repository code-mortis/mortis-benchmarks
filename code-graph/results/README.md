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

## Standalone Engine enrichment · November 26, 2026

Indexing neighboring files in one pass reduced the time spent selecting graph context. In the current implementation, each assigned path scans every import in the parser result. Both arms received the same validated, synthetic result and produced byte-identical context and coverage status on every comparison. The timings cover host-side enrichment after source collection and parsing.

| Assigned paths | Import records | Current median | Prototype median |
| ---: | ---: | ---: | ---: |
| 1 | 18,000 | 1.750 ms | 1.562 ms |
| 25 | 600 | 1.344 ms | 0.186 ms |
| 100 | 18,000 | 152.200 ms | 2.440 ms |
| 1,000 | 18,000 | 1,511.075 ms | 6.449 ms |

All 72 timed calls completed after two warm-ups per arm and workload. With 1,000 assigned paths, peak traced Python allocations rose from 164,319 to 2,452,591 bytes (+2.18 MiB) in separate memory measurements. For one assigned path, both arms peaked at 64,928 bytes. Each memory measurement used one sample per arm, excluding the prepared fixtures. The run met the predeclared timing and correctness thresholds.

Engine `b02e6f7b4ec67b8d25b8e2de05502ee8835b133c`, Python 3.15.2, Pydantic 2.14.4, macOS arm64, 12 logical CPUs. See [individual samples, range, fixture hashes and controls](graph-enrichment-2026-11-26.json) and the [reproduction protocol](../harness/graph_enrichment_protocol.md).

### Implemented enrichment, two-checkout comparison · November 26, 2026

The working-tree implementation was compared with v0.1.7 (`b02e6f7`) using the real enrichment function from each checkout. The synthetic parser result and assigned files were identical per pair. All 72 timed calls passed output parity and the four predeclared latency criteria.

| Assigned paths | Import records | v0.1.7 median | Implemented median |
| ---: | ---: | ---: | ---: |
| 1 | 18,000 | 1.741 ms | 1.654 ms |
| 25 | 600 | 1.342 ms | 0.191 ms |
| 100 | 18,000 | 152.312 ms | 2.480 ms |
| 1,000 | 18,000 | 1,498.154 ms | 6.699 ms |

Peak traced Python allocations were 64,928 bytes for both single-path arms. With 1,000 assigned paths they rose from 163,951 to 2,443,735 bytes (+2.17 MiB). These isolated component timings exclude Git and parser execution. The [individual results](graph-enrichment-checkouts-2026-11-26.json) include source and fixture digests. The [reconstruction instructions](../../review-improvements/harness/preview-git/compare.md) describe the performance-only checkout shared by both benchmarks.

### Graph enrichment after caller coverage fixes · November 26, 2026

The [offline component rerun](graph-enrichment-caller-fixes-2026-11-26.json) measured the repaired working tree at `277ae12` against v0.1.7 using nine samples per arm and workload. All 72 timed calls passed output parity and all four workload thresholds passed. With 1,000 assigned paths the median fell from 1491.69 ms to 6.64 ms.
