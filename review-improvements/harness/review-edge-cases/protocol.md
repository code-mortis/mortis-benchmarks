# Review scope edge cases

Compare the public review planner and incremental workflow against frozen outcomes on v0.1.7 and the first main revision after PR 27. The unit of correctness is one case on one Git fixture. A pass requires exact equality for all graded fields on every measured repetition. Exceptions, incomplete reports, missed sites and incorrect reuse count as failures when the case expects success. Observe an initial baseline for any newly exposed limitation. Count improvements and regressions relative to the release separately.

Run one warm-up and three timed repetitions per case and revision. Start a fresh synthetic Git repo and private home/config/state for each case each time, with fixed Git identity and date and a warm host filesystem cache. Run serially, alternating revision order by repetition. Measure wall-clock milliseconds for fixture construction plus the public API call(s). Also time each public call separately in milliseconds. For incremental cases the first and subsequent review have separate samples. The outer timings describe the cost to reproduce each case, including failures. Never compare a quick failure with a successful result as a speedup. Retain individual samples, median, minimum, maximum and semantic outcomes. There is no speed acceptance threshold. Cases and expectations are in the corresponding Python and JSON files; inputs and grader are hashed in the report.

## Live shell-path check

Use three synthetic branch reviews on current main, with the same selected saved connection, ordinary default single-pass review, one request slot and a 240-second workflow timeout. One review per case, in the order quoted, escaped, clean. Both positive callers invoke the same removed script that has a space in its name. The clean caller invokes a surviving sibling script. The three cases each include an unrelated version bump so there is a primary diff to analyze. Determine the shell operand independently with POSIX shell tokenization and check the head tree for existence. An affected caller must cover run.sh line 3 in both positive cases. Require one confirmed finding pointing to the broken invocation in each positive case, no extra confirmed findings, zero confirmed findings on clean, and complete coverage/workflow in all three. Inspect finding text as well as its location. Keep provider token totals and request counts when available, and leave billing unknown. This is a three-case observation on a single connection and model.

## Reproduce

From the benchmark repository root, set MORTIS_ENGINE to the Engine checkout with its development environment installed. Both Engine revisions must exist locally. The offline command reads the commits directly; the live command uses the installed development CLI. The working-tree snapshot fixtures require Git and POSIX no-follow file access.

```sh
mkdir -p .local
"$MORTIS_ENGINE/.venv/bin/python" -B review-improvements/harness/review-edge-cases/run.py \
  --engine "$MORTIS_ENGINE" --baseline v0.1.7 --candidate 2e81e23 \
  --output .local/review-edge-cases.json
```

For a live replay, choose a fresh private directory and an explicitly selected saved connection. The generator creates three synthetic repositories and verifies their literal shell operands. The review command saves raw reports, stderr and private state inside that directory. A fresh output path protects a dispatched request from accidental replay. Inspect the report and status of each run before interpreting findings. Confirm the finding describes the deleted script at the invocation on line 3. The opt-in command incurs actual provider usage.

```sh
"$MORTIS_ENGINE/.venv/bin/python" -B review-improvements/harness/review-edge-cases/live.py prepare .local/live-shell-run
"$MORTIS_ENGINE/.venv/bin/python" -B review-improvements/harness/review-edge-cases/live.py review .local/live-shell-run \
  --cli "$MORTIS_ENGINE/.venv/bin/mortis" --connection "$MORTIS_CONNECTION"
```

### Comparing local fixes with main

Use the same cases, grading and sampling schedule to measure an uncommitted correction. The candidate worker imports a temporary copy of the Engine working tree's tracked and non-ignored source files. The report records its base commit, digest of the added, modified and deleted source paths and Git blob identities and an inventory digest for the bytes and modes actually supplied. Run the live checks above using the CLI from that same Engine working tree.

```sh
"$MORTIS_ENGINE/.venv/bin/python" -B review-improvements/harness/review-edge-cases/run.py \
  --engine "$MORTIS_ENGINE" --baseline 2e81e23 --candidate-working-tree \
  --output .local/review-edge-cases-fixed.json
```
