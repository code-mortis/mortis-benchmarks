# Review preview duplicate Git lookup benchmark

Does reusing a validated pinned tree lookup save meaningful wall time in the public Python review preview?

The baseline uses the current Engine source. The in-process candidate reuses the raw result of the immediately preceding, identical literal-path tree lookup. All decoding, regular-file and size checks, blob reads, review plan logic, and contract assembly still execute. A production implementation could pass the prior validated blob identity and size explicitly. This prototype measures one Git child process eliminated per admitted file without changing the read path.

Use fixed synthetic SHA-1 commits with 4 and 80 modified Python files (branch mode) and the 80-file head (full-tree mode). Each file has 30 small assignment lines. Verify a separate unmeasured branch fixture with a regular executable file, Unicode paths and source, a path with spaces, a symlink, invalid UTF-8, a NUL-containing blob, a deleted module and a surviving caller. Git metadata, commit time, and input are the same for both arms. Each call gets a fresh private Engine snapshot. Fixture preparation and JSON digest generation stay outside wall time. The host filesystem cache is naturally warm after one measured-path warm-up per arm and workload. No shared state, external services, Docker, provider requests, or inference.

Collect five `perf_counter_ns` elapsed samples per arm and workload in serial. Alternate first arm each pair, report milliseconds, median, range and failed or incomplete samples. Measure process counts independently with a single instrumented invocation per arm and workload. No percentile is estimated from five samples.

The candidate passes if every compared preview dictionary matches exactly, all regular timed workloads have the expected selected file count and no plan gaps, and both 80-file cases reduce median elapsed by at least 15% and spawn exactly 80 fewer Git processes. The 4-file control is descriptive. The edge-case fixture must exercise both exclusions and explicit selected-file errors. Report results as a synthetic offline comparison of public Python preview latency on this host.
