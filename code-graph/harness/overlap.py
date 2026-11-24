"""Measure the running local stack during disposable concurrent workflows. No model/GitHub calls.

Run after backend tests have released mortis_test: python scripts/code_graph_eval/overlap.py.
Requires the development stack and isolated test database. Does not restart or resize Docker.
"""

if __name__ == "__main__":
    raise SystemExit("This historical OCR/native overlap evaluation is retired; saved evidence remains available.")


import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ['docker', 'compose', '--env-file', '.env.dev', '-f', 'compose.dev.yaml']
WORKLOAD_DIR = f'/tmp/cm-graph-overlap-{uuid4().hex}'
TEST_ENV = {
    'CM_DATABASE_URL': 'postgresql+psycopg://mortis:mortis-test-only@host.docker.internal:55439/mortis_test',
    'CM_REDIS_URL': 'redis://host.docker.internal:56389/0',
    'CM_ENCRYPTION_KEY': 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=',
    'CM_SENTRY_DSN': '', 'CM_WORK_DIR': WORKLOAD_DIR + '/work',
}
SERVICES = {'graph': 'code-graph-worker', 'review': 'review-worker', 'security': 'security-worker', 'database': 'api'}
STOP = f"import os,signal; from pathlib import Path; [(os.kill(int(p.parent.name),signal.SIGTERM)) for p in Path('/proc').glob('[0-9]*/cmdline') if b'{WORKLOAD_DIR}/workload.py' in p.read_bytes().split(b'\\0')]"


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs)


def inside(service, args):
    return COMPOSE + ['exec', '-T', *[v for key, value in TEST_ENV.items() for v in ('-e', key + '=' + value)], service, *args]


def summarize(samples):
    if not samples:
        return {'sample_count': 0, 'duration_seconds': None, 'peak_simultaneous_container_memory_bytes': None,
                'peak_aggregate_cpu_percent': None, 'container_peaks': {}}

    def memory(value):
        amount, unit = re.fullmatch(r'([0-9.]+)([A-Za-z]+)', value.split(' / ')[0]).groups()
        return round(float(amount) * {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3}[unit])
    peaks = {}
    for sample in samples:
        for row in sample['containers']:
            peak = peaks.setdefault(row['Name'], {'memory_bytes': 0, 'cpu_percent': 0})
            peak['memory_bytes'] = max(peak['memory_bytes'], memory(row['MemUsage']))
            peak['cpu_percent'] = max(peak['cpu_percent'], float(row['CPUPerc'].rstrip('%')))
    return {'sample_count': len(samples), 'duration_seconds': samples[-1]['elapsed_seconds'],
            'peak_simultaneous_container_memory_bytes': max(sum(memory(row['MemUsage']) for row in sample['containers']) for sample in samples),
            'peak_aggregate_cpu_percent': max(sum(float(row['CPUPerc'].rstrip('%')) for row in sample['containers']) for sample in samples),
            'container_peaks': peaks}


memory = int(command(['docker', 'info', '--format', '{{.MemTotal}}']))
assert memory <= 8 * 1024**3, 'Set an <=8 GiB Docker VM ceiling before claiming this benchmark'
# Refuse concurrent test runs; fixture cleanup would invalidate the measurement.
processes = command(['ps', '-axo', 'command='], text=True)
assert not any('python -m pytest' in line and 'ps -axo' not in line for line in processes.splitlines()), 'Wait for pytest to finish'
subprocess.run(['uv', 'run', 'python', '-c',
    "import sys; sys.path.insert(0,'tests'); import conftest; conftest.clean_database.__wrapped__(None); conftest.seed.__wrapped__()"],
    cwd=ROOT / 'backend', check=True, env={key: value for key, value in os.environ.items() if not key.startswith('CM_')})

containers = command(COMPOSE + ['ps', '-q'], text=True).split()
containers += command(
    ['docker', 'compose', '--project-directory', '.', '-f', 'docker/compose.test.yaml', 'ps', '-q'],
    text=True,
).split()
containers = sorted(set(containers))
fields = '{{json .Name}} {{json .State.OOMKilled}} {{json .RestartCount}} {{json .HostConfig.Memory}}'
before = {c: command(['docker', 'inspect', '--format', fields, c], text=True).strip() for c in containers}
result = {'docker_memory_ceiling_bytes': memory, 'cpus': int(command(['docker', 'info', '--format', '{{.NCPU}}'])),
          'source_commit': command(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'real': ['Git object snapshots', 'OCR scope', 'parser HTTP and extraction', 'Trivy offline scan', 'PostgreSQL workflow persistence'],
          'stubbed': ['GitHub authorization and fetch transport', 'model responses and usage'],
          'samples': [], 'workloads': {}, 'containers_before': before}

with tempfile.TemporaryDirectory(prefix='cm-graph-overlap-') as tmp:
    root = Path(tmp)
    repo = root / 'repo'
    repo.mkdir()
    archive = root / 'source.tar'
    archive.write_bytes(command(['git', 'archive', 'HEAD']))
    with tarfile.open(archive) as tar:
        tar.extractall(repo, filter='data')
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(repo), *args], text=True).strip()
    git('init', '-q')
    git('config', 'user.name', 'Resource fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    git('add', '.')
    git('commit', '-qm', 'Pinned source corpus')
    base = git('rev-parse', 'HEAD')
    paths = [p for p in sorted((repo / 'backend/code_mortis').rglob('*.py')) if 100 < p.stat().st_size < 12000][:12]
    for path in paths:
        path.write_text(path.read_text() + '\n# Resource evaluation change.\n')
    git('add', '.')
    git('commit', '-qm', 'Twelve-file review workload')
    head = git('rev-parse', 'HEAD')
    (root / 'revisions.json').write_text(json.dumps([base, head]))
    result['corpus'] = {'files': len(git('ls-tree', '-r', '--name-only', head).splitlines()),
                        'bytes': sum(p.stat().st_size for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts),
                        'changed_files': len(paths), 'base': base, 'head': head}
    bundle = root / 'payload.tar'
    with tarfile.open(bundle, 'w') as tar:
        tar.add(repo, arcname='repo')
        tar.add(root / 'revisions.json', arcname='revisions.json')
        tar.add(Path(__file__).with_name('overlap_workload.py'), arcname='workload.py')
    payload = bundle.read_bytes()
    started, jobs, logs = [], {}, {}
    try:
        for service in SERVICES.values():
            command(inside(service, ['mkdir', WORKLOAD_DIR]))
            started.append(service)
            command(inside(service, ['tar', '-xf', '-', '-C', WORKLOAD_DIR]), input=payload)
        for mode, service in SERVICES.items():
            logs[mode] = (root / (mode + '.log')).open('w+')
            jobs[mode] = subprocess.Popen(inside(service, ['python', WORKLOAD_DIR + '/workload.py', mode]),
                                         cwd=ROOT, stdout=logs[mode], stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 900
        while any(job.poll() is None for job in jobs.values()):
            if any(job.poll() not in {None, 0} for job in jobs.values()):
                break
            assert time.monotonic() < deadline, 'Overlap exceeded 15 minutes'
            sample = command(['docker', 'stats', '--no-stream', '--format', '{{json .}}', *containers], text=True)
            result['samples'].append({'elapsed_seconds': round(900 - (deadline - time.monotonic()), 2),
                                      'containers': [json.loads(line) for line in sample.splitlines()]})
            time.sleep(1)
        for mode, job in jobs.items():
            if job.poll() is None:
                command(inside(SERVICES[mode], ['python', '-c', STOP]))
                job.wait(timeout=10)
            logs[mode].seek(0)
            output = logs[mode].read()
            if job.returncode:
                result['workloads'][mode] = {'exit_code': job.returncode, 'error': output[-6000:]}
            else:
                result['workloads'][mode] = json.loads(output.strip().splitlines()[-1])
        result['containers_after'] = {c: command(['docker', 'inspect', '--format', fields, c], text=True).strip() for c in containers}
    finally:
        for mode, job in jobs.items():
            if job.poll() is None:
                command(inside(SERVICES[mode], ['python', '-c', STOP]))
                job.wait(timeout=10)
        for handle in logs.values():
            handle.close()
        for service in started:
            command(inside(service, ['rm', '-rf', WORKLOAD_DIR]))
result['resources'] = summarize(result.pop('samples'))
output = ROOT / 'docs/evidence/code-graph-phase2-overlap.json'
output.write_text(json.dumps(result, indent=2) + '\n')
print(output)
assert all('exit_code' not in item for item in result['workloads'].values()), result['workloads']

assert result['containers_before'] == result['containers_after'], 'Container OOM/restart state changed'
