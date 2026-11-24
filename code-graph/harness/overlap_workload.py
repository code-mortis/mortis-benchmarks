"""Disposable phase 2 overlap workload, invoked inside existing development containers.

Only the isolated mortis_test database is allowed. GitHub/model replies are stubbed;
Git, OCR scope, parser HTTP, Trivy, snapshot storage and workflow persistence are real.
"""

if __name__ == "__main__":
    raise SystemExit("This historical OCR/native overlap evaluation is retired; saved evidence remains available.")


import json
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select, text

from code_mortis import jobs
from code_mortis.code_graph import service as graph
from code_mortis.code_graph import store
from code_mortis.core.config import settings
from code_mortis.core.db import engine, transaction
from code_mortis.integrations import github, ocr, runner_client
from code_mortis.models import CodeGraphSnapshot, Repository, ReviewRun, SecurityScan, User
from code_mortis.reviews import delegated, graph_context
from code_mortis.schemas.common import RepoSettings
from code_mortis.schemas.security import SecurityScanInput
from code_mortis.security_scans import engine as security_engine
from code_mortis.security_scans import service as security

if engine().url.database != 'mortis_test':
    raise SystemExit('This workload must never use an application database')
ROOT = Path(__file__).resolve().parent
REPO = ROOT / 'repo'
ENV = ocr.child_environment()
BASE, HEAD = json.loads((ROOT / 'revisions.json').read_text())
START = time.monotonic()
MODE = sys.argv[1]
REMOTE = {'id': 22, 'full_name': 'team/project', 'default_branch': 'main', 'permissions': {'pull': True, 'push': True}}


def remote(method, path, *args, **kwargs):
    assert method == 'GET', 'The resource probe must never publish remotely'
    return {'sha': HEAD} if '/commits/' in path else REMOTE


def clone(target):
    # Only the fixed disposable fixture uses a local transport; application Git restrictions stay intact.
    subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--bare', '--no-hardlinks',
                    '--quiet', str(REPO), str(target)], check=True, env=ENV)


def acquire(repository_id, name, sha, snapshot_id, token, stopped):
    stopped()
    target = store.directory(repository_id)
    if not target.exists():
        clone(target)
    store.git(target, 'update-ref', store.reference(snapshot_id), sha)


@contextmanager
def snapshot(full_name, sha, previous, token, stopped):
    root = ROOT / 'security'
    root.mkdir()
    clone(root / 'git')
    item = security_engine.Snapshot(root, sha, ENV, stopped)
    item.populate()
    yield item


def inference(*args, **kwargs):
    # Hold work long enough for overlap; these numbers are fixtures, never measured model usage.
    time.sleep(.05)
    return {'findings': [], 'required_paths': []}, {'tokens': 1}


with patch.object(github, 'authorize_repo', return_value=REMOTE), \
     patch.object(github, 'installation_token', return_value='fixture-only'), \
     patch.object(github, 'repository_read_token', return_value='fixture-only'), \
     patch.object(github, 'request', side_effect=remote):
    if MODE in {'graph', 'review', 'database'}:
        for _attempt in range(3000):
            with transaction() as db:
                scan = db.scalar(select(SecurityScan))
                ready = scan and scan.stages.get('snapshot', {}).get('status') == 'completed'
            if ready:
                break
            time.sleep(.2)
        assert ready, 'Security snapshot did not become ready for overlap'
    if MODE == 'graph':
        settings().code_graph_store_dir = ROOT / 'objects'
        with patch.object(store, 'acquire', side_effect=acquire):
            graph.configure(22, 7, enabled=True)
            identity = graph.enqueue_snapshot(22)
            with transaction() as db:
                job = db.get(CodeGraphSnapshot, identity).job_id
            jobs.execute_job(job)
            with transaction() as db:
                row = db.get(CodeGraphSnapshot, identity)
                assert row.status in graph.USABLE, (row.status, row.error)
                result = {'snapshot': identity, 'status': row.status, 'commit': row.commit_sha}
    elif MODE == 'review':
        prompts = []
        def review(connection, identity, payload, stopped):
            assert not stopped()
            prompts.append(len(payload['prompt'].encode()))
            time.sleep(.2)
            return {'comments': []}, {'tokens': 1}
        options = RepoSettings(max_files=40, token_budget=None, timeout_seconds=600).model_dump()
        with transaction() as db:
            repository = db.get(Repository, 22)
            graph_options = {'version': graph_context.VERSION, 'repository_id': 22, 'actor_id': 7,
                             'policy_digest': store.policy_digest(store.policy(repository))}
        with patch.object(runner_client, 'review', side_effect=review):
            status, report, comments = delegated.review(REPO, ENV, BASE, HEAD, BASE,
                {'id': 'fixture', 'kind': 'chatgpt', 'model': 'fixture', 'options': {'prompt_token_ceiling': 200000}},
                options, 'overlap', lambda: False, lambda value: None, {}, graph_options=graph_options)
        assert status == 'completed' and not comments, (status, report)
        result = {'status': status, 'assignments': len(prompts), 'prompt_bytes': sum(prompts),
                  'graph_reasons': [value['reason'] for value in report['code_graph']['files'].values()]}
    elif MODE == 'security':
        original_command = ocr.command
        def offline(args, *a, **kw):
            if '--download-db-only' in args or (args and str(args[-1]).endswith('/check-update')):
                return 0, '', ''
            return original_command(args, *a, **kw)
        with patch.object(security_engine, 'snapshot', side_effect=snapshot), \
             patch.object(security_engine, 'ask', side_effect=inference), \
             patch.object(ocr, 'command', side_effect=offline):
            with transaction() as db:
                scan = security.create_scan(db, db.get(Repository, 22), db.get(User, 7),
                    SecurityScanInput(connection_id='connection', request_key='phase2-overlap-disposable',
                                      token_budget=None, timeout_seconds=900))
                identity = scan.id
            security.perform(identity, 'resource-evaluation:1')
            with transaction() as db:
                scan = db.get(SecurityScan, identity)
                assert scan.status in {'completed', 'partial'}, (scan.status, scan.error)
                result = {'status': scan.status, 'stages': scan.stages, 'error': scan.error,
                          'files': len(scan.coverage.get('inventory', {}))}
    elif MODE == 'database':
        # Read/write activity on disposable rows, alongside durable graph/security publications.
        with transaction() as db:
            before = db.scalar(text('SELECT pg_database_size(current_database())'))
        for _number in range(300):
            with transaction() as db:
                db.execute(text("UPDATE repositories SET full_name = full_name WHERE id = 22"))
                db.scalar(select(ReviewRun.id).limit(1))
            time.sleep(.1)
        with transaction() as db:
            after = db.scalar(text('SELECT pg_database_size(current_database())'))
        result = {'transactions': 300, 'database_before_bytes': before, 'database_after_bytes': after}
    else:
        raise ValueError('Unknown workload')
result.update(mode=MODE, seconds=round(time.monotonic() - START, 3),
              temporary_bytes=sum(path.stat().st_size for path in ROOT.rglob('*') if path.is_file()))
print(json.dumps(result), flush=True)
