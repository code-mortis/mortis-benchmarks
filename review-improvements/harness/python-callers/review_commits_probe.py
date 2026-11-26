"""Corroborate incremental caller selection through the public review API."""

import argparse
import hashlib
import json
import os
import platform
import tempfile
from pathlib import Path
from unittest.mock import patch

from run import DIRECTORY, ENGINE, commit, git, write_files

from mortis_engine import gateway
from mortis_engine.review import review_commits
from mortis_engine.schemas import Response, Usage

CASES = (
    'incremental-required-parameter',
    'incremental-body-only',
    'incremental-removed-function',
    'incremental-renamed-optional-keyword',
)


def observe(repo, env, suite, fixture):
    caller, dependency = suite['caller_path'], suite['dependency_path']
    git(repo, env, 'init', '--quiet', '--initial-branch=main', '--object-format=sha1')
    write_files(repo, suite['base_files'] | {
        dependency: fixture['before'], caller: '# Before the first review\n' + fixture['caller'],
    })
    base_sha = commit(repo, env, 'Base')
    git(repo, env, 'switch', '-qc', 'topic')
    write_files(repo, {caller: fixture['caller']})
    previous_sha = commit(repo, env, 'Previous reviewed head')

    assigned = []

    async def scripted_response(connection, credentials, request, **kwargs):
        assert credentials == {}
        content = request.messages[0].content
        payload = json.loads(content.split('\n\n', 2)[1] if content.startswith('# ') else content)
        if 'narrative' in request.output_schema['properties']:
            output = {'narrative': 'Synthetic summary', 'groups': []}
        else:
            units = payload['assigned_units']
            assigned.extend(unit['path'] for unit in units)
            output = {'task_key': payload['task_key'], 'completed_units': [unit['key'] for unit in units], 'findings': []}
        return Response(output=output, usage=Usage(total_tokens=3))

    kwargs = {
        'base': 'main', 'head': 'topic', 'get_credentials': dict, 'concurrency': 1,
        'connection': {'provider': 'custom', 'protocol': 'openai', 'model': 'fixture', 'options': {}},
        'overrides': {'incremental': True},
    }
    with patch.object(gateway, 'send', scripted_response):
        first = review_commits(repo, **kwargs)
        assert first['head_sha'] == previous_sha and first['comparison']['reason'] == 'no_baseline', first
        assert first['status'] == first['workflow_status'] == 'completed' and assigned == [caller], first
        assigned.clear()
        write_files(repo, {dependency: fixture['after']})
        head_sha = commit(repo, env, 'Change the dependency')
        second = review_commits(repo, **kwargs)
    assert second['head_sha'] == head_sha, second
    assert second['status'] == second['workflow_status'] == 'completed', second
    assert second['comparison']['baseline_run_id'] == first['run_id'], second
    return {
        'revisions': {'base': base_sha, 'previous': previous_sha, 'head': head_sha},
        'actual': {
            'strategy': second['comparison']['strategy'], 'reason': second['comparison']['reason'],
            'reused_paths': sorted(row['path'] for row in second['coverage']['reused']),
            'assigned_paths': sorted(assigned),
        },
    }


def run():
    suite = json.loads((DIRECTORY / 'cases.json').read_text(encoding='utf-8'))['incremental']
    env = {
        'PATH': os.environ['PATH'], 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_AUTHOR_NAME': 'Synthetic Fixture',
        'GIT_AUTHOR_EMAIL': 'fixture@example.invalid', 'GIT_COMMITTER_NAME': 'Synthetic Fixture',
        'GIT_COMMITTER_EMAIL': 'fixture@example.invalid', 'GIT_AUTHOR_DATE': '2026-01-01T00:00:00Z',
        'GIT_COMMITTER_DATE': '2026-01-01T00:00:00Z',
    }
    with tempfile.TemporaryDirectory(prefix='mortis-review-corroboration-') as temp:
        root = Path(temp)
        environment = {f'XDG_{name}_HOME': str(root / name.lower()) for name in ('CONFIG', 'STATE', 'CACHE')}
        with patch.dict(os.environ, env | environment, clear=True):
            observations = {}
            for fixture in suite['cases']:
                case_id = fixture['id']
                if case_id not in CASES:
                    continue
                repo = root / case_id
                repo.mkdir()
                observations[case_id] = observe(repo, env, suite, fixture)

    assert observations.keys() == set(CASES)
    expected = json.loads((DIRECTORY / 'expected.json').read_text(encoding='utf-8'))
    for case_id, observation in observations.items():
        assigned = sorted({suite['dependency_path'], suite['caller_path']} - set(expected[case_id]['reused_paths']))
        observation['expected'] = expected[case_id] | {'assigned_paths': assigned}
        observation['pass'] = observation['actual'] == observation['expected']
    passed = sum(row['pass'] for row in observations.values())
    return {
        'evidence': 'mocked provider with real local Git and isolated SQLite review history',
        'engine_revision': git(ENGINE, env, 'rev-parse', 'HEAD'),
        'engine_tracked_changes': bool(git(ENGINE, env, 'status', '--porcelain', '--untracked-files=no')),
        'tool_versions': {'python': platform.python_version(), 'git': git(ENGINE, env, '--version')},
        'sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in (Path(__file__), DIRECTORY / 'run.py', DIRECTORY / 'cases.json', DIRECTORY / 'expected.json')},
        'acceptance': {'passed': passed, 'total': len(CASES), 'met': passed == len(CASES)},
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
