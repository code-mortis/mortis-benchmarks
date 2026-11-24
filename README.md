# Mortis Benchmarks

Evaluation harnesses and recorded results for [Code Mortis](https://github.com/code-mortis/code-mortis), covering review quality, repository code graphs, and pull request navigation.

| Suite | What it measures | How to run | Recorded results |
| --- | --- | --- | --- |
| [Mortis Engine](engine-eval/README.md) | PR review and security finding quality, reliability, provider usage, and controlled latency | Offline fixture validation and scoring. The original live comparison is retired. | [Results](engine-eval/results/README.md) |
| [Code Graph](code-graph/README.md) | Extraction time and memory, storage, context quality, and concurrent workload resource use | Docker for extraction. Historical results cover the context-quality and overlap experiments. | [Results](code-graph/results/README.md) |
| [PR Code Navigation](pr-code-performance/README.md) | Backend latency, SQL and GitHub calls, browser interaction timing, and idle requests | Backend probe against a running local Code Mortis instance. Browser measurements are archived. | [Results](pr-code-performance/results/README.md) |

Each suite keeps its scripts and fixtures in `harness/` and its recorded measurements in `results/`. Start with the suite README for prerequisites and commands.

## Quick offline check

Requires Python 3.13+ and Git.

```sh
python3 -B engine-eval/harness/prepare.py
python3 -B -m unittest discover -s code-graph/harness
```

## Reading and adding results

The initial harnesses come from [Code Mortis at `6c2e98f`](https://github.com/code-mortis/code-mortis/tree/6c2e98fdb44a1abdb4cc0b5c45a4f3b2f1031e9f). Each result file identifies the retained source report by filename and SHA-256. These exports contain selected measurements and omit private run material such as credentials, source snapshots, provider payloads, and instance identifiers.

Keep local output under `.local/` or in a temporary directory. For a new result, record the harness and input revisions, environment, sample size, metrics, and any incomplete work. Add it alongside earlier results so each run keeps its original scope.

The code is licensed under [Apache 2.0](LICENSE).
