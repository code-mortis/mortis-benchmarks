"""Compare two Engine revisions or a revision and a snapshot of local source."""

import argparse
import hashlib
import importlib
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from functools import partial
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
GROUPS = ('snapshots', 'callers', 'incremental')
ARM_ORDER = ('baseline', 'candidate')
REPETITIONS = 3


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def digest(data):
    return hashlib.sha256(data).hexdigest()


def content_id(value):
    return digest(json.dumps(value, ensure_ascii=False, sort_keys=True).encode())


def hashes(benchmark_repo):
    inputs = [HERE / name for name in ('run.py', 'protocol.md')]
    inputs += [HERE / f'{group}{suffix}' for group in GROUPS for suffix in ('.py', '-expected.json')]
    helper = benchmark_repo / 'review-improvements/harness/python-callers/run.py'
    return {**{path.name: digest(path.read_bytes()) for path in inputs}, 'python-callers/run.py': digest(helper.read_bytes())}


def timed_call(api, measurements, *args, **kwargs):
    start = time.perf_counter_ns()
    try:
        return api(*args, **kwargs)
    finally:
        measurements.append(round((time.perf_counter_ns() - start) / 1e6, 3))


def worker():
    import mortis_engine

    if Path(mortis_engine.__file__).resolve().parents[1] != Path(os.environ['PYTHONPATH']).resolve():
        raise RuntimeError('Engine did not load from the selected revision')
    results = {}
    for group in GROUPS:
        suite = importlib.import_module(group)
        group_results = {}
        api_name = 'review_commits' if group == 'incremental' else 'preview_local'
        api = getattr(suite, api_name)
        for case, spec in suite.CASES.items():
            api_ms = []

            with tempfile.TemporaryDirectory(prefix='mortis-bench-case-') as scratch:
                root = Path(scratch)
                repo = root / 'fixture'
                repo.mkdir()
                environment = {'HOME': str(root / 'home'), 'XDG_CONFIG_HOME': str(root / 'config'),
                               'XDG_STATE_HOME': str(root / 'state'), 'XDG_CACHE_HOME': str(root / 'cache')}
                with patch.dict(os.environ, environment), patch.object(suite, api_name, partial(timed_call, api, api_ms)):
                    start = time.perf_counter_ns()
                    try:
                        actual = suite.observe(case, spec, repo)
                    except Exception as exc:  # noqa: BLE001 - Keep the failed case in the measured sample.
                        actual = {'unexpected_exception': type(exc).__name__,
                                  'message': str(exc).replace(str(root), '<fixture>')[:400]}
                    elapsed = (time.perf_counter_ns() - start) / 1e6
                group_results[case] = {'input_sha256': content_id(spec), 'observed': actual, 'elapsed_ms': round(elapsed, 3), 'api_ms': api_ms}
        results[group] = group_results
    print(json.dumps(results))


def working_source(engine, destination=None):
    """Hash the same files and modes that are supplied to the candidate worker."""
    inventory = []
    changed = []
    base = git(engine, 'rev-parse', 'HEAD').decode().strip()
    algorithm = git(engine, 'rev-parse', '--show-object-format').decode().strip()
    entries = {}
    for record in git(engine, 'ls-tree', '-rz', base, '--', 'src').split(b'\0'):
        if record:
            metadata, path = record.split(b'\t', 1)
            mode, _, blob = metadata.decode().split()
            entries[os.fsdecode(path)] = (mode, blob)
    names = git(engine, '-c', 'core.fsmonitor=false', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', 'src')
    for name in sorted(set(names.split(b'\0')) - {b''}):
        relative = Path(os.fsdecode(name))
        path = engine / relative
        if path != path.resolve():
            raise ValueError(f'Unsupported link in the benchmark source: {relative}')
        if not path.exists():
            continue  # A local deletion is absent from the candidate.
        contents = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        name = relative.as_posix()
        fingerprint = digest(contents)
        inventory.append((name, mode, fingerprint))
        previous = entries.pop(name, None)
        # Hash admitted bytes directly. Reproduction must never invoke a Git clean filter.
        blob = hashlib.new(algorithm)
        blob.update(f'blob {len(contents)}\0'.encode())
        blob.update(contents)
        current = ('100755' if mode & 0o100 else '100644', blob.hexdigest())
        if current != previous:
            changed.append((name, previous, current))
        if destination is not None:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
            target.chmod(mode)
    changed.extend((path, previous, None) for path, previous in entries.items())
    return {
        'base_revision': base,
        'source_changes_sha256': content_id(sorted(changed)),
        'changed_source_files': len(changed),
        'source_inventory_sha256': content_id(inventory),
        'source_files': len(inventory),
    }


def compare(args):
    benchmark_repo = args.benchmarks.resolve()
    engine = args.engine.resolve()
    expected = {g: json.loads((HERE / f'{g}-expected.json').read_bytes()) for g in GROUPS}
    identity = hashes(benchmark_repo)
    refs = (args.baseline, args.candidate or 'HEAD')
    shas = {arm: git(engine, 'rev-parse', '--verify', f'{ref}^{{commit}}').decode().strip()
            for arm, ref in zip(ARM_ORDER, refs, strict=True)}
    report = {
        'protocol': 'mortis-review-edge-cases/v1', 'evidence': {
            'snapshots': 'offline public preview, native Git and file fingerprints',
            'callers': 'offline public Git commit preview',
            'incremental': 'public review_commits, real isolated SQLite and scripted provider',
        },
        'engine_commits': shas, 'source': 'git archive src/ of each pinned commit using the same interpreter',
        'benchmarks_base': git(benchmark_repo, 'rev-parse', 'HEAD').decode().strip(),
        'harness_sha256': identity,
        'environment': {'python': platform.python_version(), 'git': git(engine, '--version').decode().strip(),
                        'system': platform.system(), 'os_version': platform.mac_ver()[0] or platform.release(),
                        'machine': platform.machine(), 'logical_cpus': os.cpu_count()},
        'warmups_per_arm_case': 1, 'timed_repetitions_per_arm_case': REPETITIONS,
        'metric': 'ms is fixture construction and observation wall time, excluding worker startup. '
                  'api_ms times only the public calls in order; incremental uses initial and subsequent review.',
        'cases': {}, 'summary': {}, 'test_order': [], 'expected': expected,
    }
    with tempfile.TemporaryDirectory(prefix='mortis-bench-arms-') as scratch:
        root = Path(scratch)
        env = {
            'PATH': os.environ['PATH'], 'MORTIS_BENCHMARKS': str(benchmark_repo), 'PYTHONNOUSERSITE': '1',
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_AUTHOR_NAME': 'Benchmark', 'GIT_AUTHOR_EMAIL': 'bench@example.invalid',
            'GIT_COMMITTER_NAME': 'Benchmark', 'GIT_COMMITTER_EMAIL': 'bench@example.invalid',
            'GIT_AUTHOR_DATE': '2026-01-01T00:00:00Z', 'GIT_COMMITTER_DATE': '2026-01-01T00:00:00Z',
            'HOME': str(root / 'home'), 'XDG_CONFIG_HOME': str(root / 'config'),
            'XDG_STATE_HOME': str(root / 'state'), 'XDG_CACHE_HOME': str(root / 'cache'),
        }
        for arm, sha in shas.items():
            if arm == 'candidate' and args.candidate_working_tree:
                report['candidate_working_tree'] = working_source(engine, root / arm)
                report['engine_commits'] = {**shas, 'candidate': None}
                report['source'] = 'baseline Git archive; candidate working-tree source copied and hashed before measurement'
                continue
            archive = git(engine, 'archive', sha, 'src')
            with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
                bundle.extractall(root / arm, filter='data')
        for repetition in range(REPETITIONS + 1):
            order = ARM_ORDER if repetition % 2 == 0 else ARM_ORDER[::-1]
            for arm in order:
                run = subprocess.run(
                    [sys.executable, '-B', str(HERE / 'run.py'), '--worker'], check=False, capture_output=True,
                    env={**env, 'PYTHONPATH': str(root / arm / 'src')}, text=True,
                )
                if run.returncode:
                    raise RuntimeError(f'{arm} worker failed: {run.stderr}')
                results = json.loads(run.stdout)
                report['test_order'].append([repetition, arm])
                passed = 0
                for group, cases in results.items():
                    if cases.keys() != expected[group].keys():
                        raise ValueError(f'Fixture and grader IDs differ for {group}')
                    for case, observation in cases.items():
                        actual = observation['observed']
                        grading = expected[group][case]
                        matches = all(key in actual and actual[key] == value for key, value in grading.items())
                        passed += matches
                        case_row = report['cases'].setdefault(case, {
                            'group': group, 'input_sha256': observation['input_sha256'], 'observations': {},
                        })
                        if case_row['input_sha256'] != observation['input_sha256']:
                            raise ValueError(f'Case {case} changed during the run')
                        index = content_id(actual)
                        case_row['observations'][index] = actual
                        case_row.setdefault(arm, []).append({
                            'warmup': repetition == 0, 'ms': observation['elapsed_ms'], 'api_ms': observation['api_ms'], 'observed': index, 'pass': matches,
                        })
                print(f'{arm} round {repetition}: {passed}/{len(report["cases"])} matched', flush=True)
    if args.candidate_working_tree and working_source(engine) != report['candidate_working_tree']:
        raise ValueError('Candidate source changed during measurement')
    if hashes(benchmark_repo) != identity:
        raise ValueError('Harness or grader changed during measurement')
    for case in report['cases'].values():
        case['timing_ms'] = {}
        for arm in ARM_ORDER:
            values = [r['ms'] for r in case[arm] if not r['warmup']]
            case['timing_ms'][arm] = {'min': min(values), 'median': statistics.median(values), 'max': max(values)}
            api_values = [r['api_ms'] for r in case[arm] if not r['warmup']]
            if len({len(row) for row in api_values}) == 1:
                case['timing_ms'][arm]['public_calls'] = [
                    {'min': min(v), 'median': statistics.median(v), 'max': max(v)}
                    for v in zip(*api_values, strict=True)
                ]
    for arm in ARM_ORDER:
        summary = {}
        for group in GROUPS:
            rows = [row for row in report['cases'].values() if row['group'] == group]
            samples = [s for row in rows for s in row[arm] if not s['warmup']]
            summary[group] = {'cases': len(rows), 'passed_all_repetitions': sum(
                all(s['pass'] for s in row[arm] if not s['warmup']) for row in rows),
                'failed_timed_samples': sum(not s['pass'] for s in samples), 'timed_samples': len(samples)}
        report['summary'][arm] = summary
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write('\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        worker()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--engine', required=True, type=Path)
        parser.add_argument('--benchmarks', type=Path, default=HERE.parents[2])
        parser.add_argument('--baseline', default='v0.1.7')
        candidate = parser.add_mutually_exclusive_group()
        candidate.add_argument('--candidate', help='local commit or ref, default HEAD')
        candidate.add_argument('--candidate-working-tree', action='store_true',
                               help='snapshot local src/ including uncommitted changes')
        parser.add_argument('--output', required=True, type=Path)
        compare(parser.parse_args())
