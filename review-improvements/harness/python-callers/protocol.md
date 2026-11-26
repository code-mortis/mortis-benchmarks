# Python callers and incremental coverage

Evaluate the current Engine at `b02e6f7b4ec67b8d25b8e2de05502ee8835b133c` on ten deterministic synthetic cases. This is an initial baseline. Inputs and scorer expectations are frozen before execution and kept in separate JSON files.

Five cases call the public `preview_local` against a branch that deletes a dependency. Record matched caller paths, coverage status and limits. Positive fixtures have a surviving static import of the deleted module. Clean fixtures import a sibling module with the same basename in a different package. A source blob larger than the discovery limit must produce explicitly partial coverage.

Five cases call `comparison.decide` against real pinned Git revisions and a synthetic compatible completed baseline supplied in memory. Record strategy, reason and whether it reuses the previously covered caller. Require a caller recheck when a direct binding breaks, preserve reuse for a body-only edit, and require a full comparison if Python source needed for caller inspection fails parsing. Function removal and optional keyword renaming test safe reuse beyond the documented required-parameter policy.

Run each case once. Cases pass only on an exact match against the scorer expectations. Report individual outcomes, exact pass count and limits. Acceptance requires 10/10 cases. There is no provider workload, database, timing or cost measurement.
