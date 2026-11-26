"""Replay synthetic Python callers against stateless Engine entry points."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

import mortis_engine
from mortis_engine.review import comparison, preview_local, settings, snapshots

DIRECTORY = Path(__file__).resolve().parent
ENGINE = Path(mortis_engine.__file__).resolve().parents[2]


def git(repo, env, *args):
    return subprocess.run(
        ['git', '-c', 'core.hooksPath=/dev/null', *args],
        cwd=repo, env=env, capture_output=True, text=True, check=True, timeout=10,
    ).stdout.strip()


def commit(repo, env, message):
    git(repo, env, 'add', '-A')
    git(repo, env, 'commit', '--quiet', '-m', message)
    return git(repo, env, 'rev-parse', 'HEAD')


def write_files(repo, files):
    for name, contents in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding='utf-8')


def deletion(repo, env, fixture, suite):
    caller = fixture['caller']
    if padding := fixture.get('caller_padding_bytes'):
        caller += '#' * padding + '\n'
    write_files(repo, suite['base_files'] | {'src/shop/checkout.py': caller})
    base = commit(repo, env, 'Base')
    (repo / suite['deleted_file']).unlink()
    head = commit(repo, env, 'Delete dependency')
    result = preview_local(repo, mode='commits', base=base, head=head)
    scope = result['affected_callers']
    actual = {
        'matched_paths': sorted({site['path'] for site in scope['sites']}),
        'status': scope['status'],
        'limits': scope['limits_reached'],
    }
    return actual, {'base': base, 'head': head}, {'preview': result}


class MemoryHistory:
    def __init__(self, head, caller):
        self.head = head
        self.caller = caller
        self.signature = None

    def previous_ids(self, kind):
        assert kind == 'scan'
        return []

    def row(self, run_id, kind):
        assert run_id == 'synthetic-baseline' and kind == 'review'
        plan = {'comparison': {'version': comparison.VERSION, 'signature': self.signature, 'strategy': 'full'}}
        return {'plan': json.dumps(plan)}

    def report(self, run_id):
        assert run_id == 'synthetic-baseline'
        covered = [{'path': self.caller}]
        return {
            'head_sha': self.head,
            'status': 'completed',
            'workflow_status': 'completed',
            'errors': [],
            'coverage': {'selected': covered, 'completed': covered},
        }


def incremental(repo, env, fixture, suite):
    dependency, caller = suite['dependency_path'], suite['caller_path']
    write_files(repo, suite['base_files'] | {
        dependency: fixture['before'], caller: '# Before the first review\n' + fixture['caller'],
    })
    base = commit(repo, env, 'Base')
    write_files(repo, {caller: fixture['caller']})
    previous = commit(repo, env, 'Previous reviewed head')
    write_files(repo, {dependency: fixture['after']})
    head = commit(repo, env, 'Change the dependency')
    history = MemoryHistory(previous, caller)
    with snapshots.snapshot(repo, mode='commits', base=base, head=head) as snap:
        options = settings.load(snap.repo, snap.env, snap.settings_sha)
        options.update(incremental=True, review_mode='commits')
        kwargs = dict(connection='synthetic', profile=None, graph=None, decisions=[], assessments=[], stopped=lambda: False)
        initial = comparison.decide(snap, options, history, [], **kwargs)
        assert initial['reason'] == 'no_baseline'
        history.signature = initial['signature']
        result = comparison.decide(snap, options, history, ['synthetic-baseline'], **kwargs)
    actual = {key: result[key] for key in ('strategy', 'reason')} | {'reused_paths': result.get('reused_paths', [])}
    return actual, {'base': base, 'previous': previous, 'head': head}, {'selection': result}


def run():
    suites = json.loads((DIRECTORY / 'cases.json').read_text(encoding='utf-8'))
    observations = {}
    with tempfile.TemporaryDirectory(prefix='mortis-callers-fixtures-') as temp:
        root = Path(temp)
        for variable in ('XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME'):
            os.environ[variable] = str(root / variable)
        env = {
            'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_AUTHOR_NAME': 'Synthetic Fixture',
            'GIT_AUTHOR_EMAIL': 'fixture@example.invalid', 'GIT_COMMITTER_NAME': 'Synthetic Fixture',
            'GIT_COMMITTER_EMAIL': 'fixture@example.invalid', 'GIT_AUTHOR_DATE': '2026-01-01T00:00:00Z',
            'GIT_COMMITTER_DATE': '2026-01-01T00:00:00Z',
        }
        for name, evaluate in (('deletion', deletion), ('incremental', incremental)):
            suite = suites[name]
            for fixture in suite['cases']:
                case_id = fixture['id']
                repo = root / case_id
                repo.mkdir()
                git(repo, env, 'init', '--quiet', '--initial-branch=main', '--object-format=sha1')
                actual, revisions, details = evaluate(repo, env, fixture, suite)
                observations[case_id] = dict(actual=actual, revisions=revisions, details=details)

    expected = json.loads((DIRECTORY / 'expected.json').read_text(encoding='utf-8'))
    assert observations.keys() == expected.keys()
    for case_id, observation in observations.items():
        observation['expected'] = expected[case_id]
        observation['pass'] = observation['actual'] == expected[case_id]
    passed = sum(row['pass'] for row in observations.values())
    git_env = {'PATH': os.environ['PATH'], 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    return {
        'evidence': 'offline deterministic',
        'engine_revision': git(ENGINE, git_env, 'rev-parse', 'HEAD'),
        'engine_tracked_changes': bool(git(ENGINE, git_env, 'status', '--porcelain', '--untracked-files=no')),
        'tool_versions': {'python': platform.python_version(), 'git': git(ENGINE, git_env, '--version')},
        'platform': {'os': platform.system(), 'release': platform.release(), 'arch': platform.machine()},
        'sha256': {name: hashlib.sha256((DIRECTORY / name).read_bytes()).hexdigest()
                   for name in ('run.py', 'cases.json', 'expected.json', 'protocol.md')},
        'acceptance': {'passed': passed, 'total': len(expected), 'met': passed == len(expected)},
        'observations': observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output is None:
        print(rendered)
    else:
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(rendered + '\n')
        print(json.dumps(result['acceptance']))


if __name__ == '__main__':
    main()
