# Standalone Engine graph enrichment benchmark

Does indexing eligible imports once reduce the time spent selecting supporting source in `mortis_engine.code_graph.enrich`? The baseline calls the current Engine function. The candidate replaces its nested edge scan with a single pass that indexes neighbors of assigned paths. Both arms use the same validated synthetic request and parser result. This setup bypasses source collection, Docker, native extraction and provider calls. The measurement includes the Engine's context selection, byte limits, source rendering and result assembly.

| Workload | Indexed JS files | Assigned paths | Parser imports per file |
| --- | ---: | ---: | ---: |
| Single assignment | 1,000 | 1 | 18 |
| Small | 100 | 25 | 6 |
| Medium | 1,000 | 100 | 18 |
| Many assignments | 1,000 | 1,000 | 18 |

The generated import graph includes outgoing, incoming, self, duplicate and unresolved imports. Assigned paths are evenly spaced through the ordered file names. A separate untimed fixture checks source order, incoming and duplicated imports, self and unresolved exclusion, unsupported targets, partial coverage, file and byte limits, and exact output parity.

Use a fresh process and fixed hash seed with two warm-up calls and nine measured calls per arm and workload. Alternate arm order between measurement pairs and run single-threaded. Report median, minimum and maximum wall time per arm in milliseconds, individual samples, output hashes and errors. Time each complete enrichment call with `perf_counter_ns`. Serialize and hash its return outside the measured region, and require each sample to match its baseline reference byte for byte. The candidate passes if the output checks pass with zero errors, the median falls by at least 25% on medium and many-assignment workloads, and the single and small medians rise by at most 10%.

After all timings, record peak traced Python allocation in one separate call per arm for the single-assignment and many-assignment workloads. `tracemalloc` excludes native memory and the prepared fixtures. Record those observations without any allocation gate.

From the benchmark checkout using the Engine development environment:

```sh
PYTHONHASHSEED=0 ../mortis-engine/.venv/bin/python -B code-graph/harness/graph_enrichment.py \
  --engine-checkout ../mortis-engine --output .local/graph-enrichment.json
```

The test is offline and deterministic. It uses synthetic parser facts validated against their source bytes, a simulated parser transport, and no user configuration or history. Provider usage and billing are outside its scope.
