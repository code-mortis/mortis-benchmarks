# PR Code Navigation Benchmark

The backend probe times the saved PR workspace in Diff, Dependencies, Definitions, and Source views. Each invocation samples one initial pass and 20 warm passes by default. It records response size, SQL count and time, comparison cache hits, and timing by GitHub and backend stage. The historical benchmark also recorded browser interaction and idle request counts.

## Run the backend probe

Use a running local Code Mortis development stack, an authorized Code Mortis login, and a saved PR and source file visible to that account. Set `CODE_MORTIS` to the absolute checkout path. From this repository's root, substitute the login, saved PR ID, and repository-relative file path:

```sh
mkdir -p .local
docker compose --project-directory "$CODE_MORTIS" \
  --env-file "$CODE_MORTIS/.env.dev" -f "$CODE_MORTIS/compose.dev.yaml" \
  exec -T api python - --login '<login>' --pr-id '<saved-pr-id>' \
  --path '<path/in/repo>' --samples 20 \
  < pr-code-performance/harness/probe.py > .local/pr-code-performance.jsonl
```

The probe uses the application's normal GitHub authorization and can make read requests to GitHub. Per-sample lines report timings and counts. The final `RESULT` line includes stage details and background job count deltas. Browser measurements in [results](results/README.md) are from the original local benchmark and are collected separately from this probe.
