"""Create harmless shell-path fixtures, then optionally review them with a named connection."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

CASES = {
    'quoted': '"./scripts/rebuild cache.sh"',
    'escaped': r'./scripts/rebuild\ cache.sh',
    'clean': r'./scripts/refresh\ cache.sh',
}
DELETED = 'scripts/rebuild cache.sh'
RETAINED = 'scripts/refresh cache.sh'
CALLER = 'run.sh'
GIT_ENV = {
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_AUTHOR_NAME': 'Benchmark', 'GIT_AUTHOR_EMAIL': 'bench@example.invalid',
    'GIT_COMMITTER_NAME': 'Benchmark', 'GIT_COMMITTER_EMAIL': 'bench@example.invalid',
    'GIT_AUTHOR_DATE': '2026-01-01T00:00:00Z', 'GIT_COMMITTER_DATE': '2026-01-01T00:00:00Z',
}


def git(repo, *args):
    return subprocess.run(
        ['git', '-c', 'core.hooksPath=/dev/null', *args], check=True, cwd=repo,
        env={'PATH': os.environ['PATH'], **GIT_ENV}, capture_output=True, text=True,
    ).stdout.strip()


def prepare(root):
    root.mkdir(mode=0o700, parents=True)
    manifest = {}
    for case, operand in CASES.items():
        repo = root / case
        (repo / 'scripts').mkdir(parents=True)
        git(repo, 'init', '-q', '-b', 'main', '--object-format=sha1')
        for path in (DELETED, RETAINED):
            (repo / path).write_text('printf "%s\\n" ready\n', encoding='utf-8')
        command = f'sh {operand}'
        (repo / CALLER).write_text(f'#!/bin/sh\n# Run from the repository root.\n{command}\n', encoding='utf-8')
        (repo / 'version.py').write_text('VERSION = 1\n', encoding='utf-8')
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'Base')
        base = git(repo, 'rev-parse', 'HEAD')
        git(repo, 'switch', '-qc', 'topic')
        # Keep one ordinary changed unit even when caller discovery returns zero sites.
        (repo / 'version.py').write_text('VERSION = 2\n', encoding='utf-8')
        (repo / DELETED).unlink()
        git(repo, 'add', '-A')
        git(repo, 'commit', '-qm', 'Change')
        target = shlex.split(command)[1].removeprefix('./')
        manifest[case] = {'base': base, 'head': git(repo, 'rev-parse', 'HEAD'),
                          'literal_target': target, 'target_exists_after': (repo / target).is_file()}
    (root / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')


def run(root, cli, connection):
    manifest = json.loads((root / 'inputs.json').read_text(encoding='utf-8'))
    for case in CASES:
        repo = root / case
        if (git(repo, 'rev-parse', 'main') != manifest[case]['base']
                or git(repo, 'rev-parse', 'topic') != manifest[case]['head']):
            raise SystemExit('Fixture revisions changed')
        output = root / f'{case}.json'
        env = {**os.environ, **GIT_ENV, 'XDG_STATE_HOME': str(root / 'private-state' / case)}
        # Reserve the output before dispatch. An interrupted review must be inspected before any retry.
        with output.open('x', encoding='utf-8') as stdout, (root / f'{case}.log').open('x', encoding='utf-8') as stderr:
            start = time.monotonic()
            p = subprocess.run(
                [str(cli), 'review', '--repo', str(repo), '--base', 'main', '--head', 'topic',
                 '--connection', connection, '--concurrency', '1', '--timeout-seconds', '240', '--format', 'json'],
                stdout=stdout, stderr=stderr, env=env, check=False,
            )
        record = {'exit_code': p.returncode, 'wall_s': round(time.monotonic() - start, 3),
                  'raw_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
        (root / f'{case}-process.json').write_text(json.dumps(record) + '\n', encoding='utf-8')
        print(case, record, flush=True)
        if not output.stat().st_size:
            raise SystemExit('Review produced no report. Inspect the local diagnostic before continuing.')
        report = json.loads(output.read_text(encoding='utf-8'))
        if any(row.get('consumption_unknown') for row in report.get('usage', {}).get('requests', [])):
            raise SystemExit('Unknown usage. Inspect the result before considering further dispatch.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'review'])
    parser.add_argument('root', type=Path)
    parser.add_argument('--cli', type=Path)
    parser.add_argument('--connection')
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.root.resolve())
    elif args.cli and args.connection:
        run(args.root.resolve(), args.cli.resolve(), args.connection)
    else:
        parser.error('review requires --cli and --connection')
