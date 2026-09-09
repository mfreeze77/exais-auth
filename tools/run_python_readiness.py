"""Prove Python readiness against an actual owned PostgreSQL stop/start.

Reuses cached images and the existing private lab. Takes a private pg_dump first,
preserves the database container/volume, restores it in finally, and removes only
exact newly created application/probe IDs. No global Docker cleanup or builds.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid

from run_sdk_session_faults import ROOT, NETWORK, command, inspect, inventory, sha, require

PG_NAME = 'expertauth-oss-postgres'
CORE_NAME = 'expertauth-oss-core-a'
IMAGE = 'expertauth-python-app:0.1.0'
BASELINE_COMMIT = 'fefb9daa2d1da99e5aebbffe10a4785f183153da'
BASELINE_APP_SHA = '9be27ff8b94665acfa1721ba8011103569caa055dd5f0b1428d0cd3704ee191b'
SOURCE_INPUTS = ['tools/run_python_readiness.py', 'tools/run_sdk_session_faults.py',
                 'tests/operations/python_readiness.py', 'examples/python/app.py',
                 'examples/python/requirements.lock', 'examples/python/Dockerfile']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    require(args.name.isascii() and args.name and all(c.isalnum() or c in '-_' for c in args.name), 'Invalid run name')
    output = ROOT / 'evidence/operations/python-readiness' / args.name
    private = ROOT / '.runtime/python-readiness' / args.name
    require(not output.exists() and not private.exists(), 'Preserve earlier evidence/private backup; choose a new run name')
    pg, core = inspect('container', PG_NAME), inspect('container', CORE_NAME)
    require(pg['State']['Running'] and core['State']['Running'], 'Existing database/Core must already be running')
    require(pg['Config'].get('Labels', {}).get('org.expertauth.purpose') == 'oss-foundation', 'Database ownership differs')
    require(core['Config'].get('Labels', {}).get('org.expertauth.project') == 'expert-auth', 'Core ownership differs')
    for state in (pg, core):
        require(not state['HostConfig']['PortBindings'] and set(state['NetworkSettings']['Networks']) == {NETWORK}, 'Lab topology is not exclusively private')
    network = inspect('network', NETWORK)
    require(network['Internal'], 'Existing lab network must be internal')
    require({row['Name'] for row in network.get('Containers', {}).values()} == {PG_NAME, CORE_NAME}, 'Other active lab consumers must finish before controlled database outage')
    pg_volume = [row for row in pg['Mounts'] if row.get('Name') == 'expertauth-oss-proof-pg' and row['Destination'] == '/var/lib/postgresql/data']
    require(len(pg_volume) == 1 and pg_volume[0]['Type'] == 'volume', 'Expected owned persistent database volume')
    image = inspect('image', IMAGE)['Id']
    suffix = uuid.uuid4().hex[:8]
    names = {role: 'expertauth-python-ready-' + role + '-' + suffix for role in ('baseline', 'current', 'probe')}
    for name in names.values():
        require(command('container', 'inspect', name, check=False).returncode != 0, 'Generated container name exists')
    inputs = {path: sha(ROOT / path) for path in SOURCE_INPUTS}
    before = inventory()
    output.mkdir(parents=True)
    private.mkdir(parents=True)
    baseline_app = private / 'baseline-app.py'
    baseline_bytes = subprocess.run(['git', 'show', BASELINE_COMMIT + ':examples/python/app.py'], cwd=ROOT,
                                    check=True, capture_output=True).stdout
    require(hashlib.sha256(baseline_bytes).hexdigest() == BASELINE_APP_SHA, 'Pinned baseline source differs')
    baseline_app.write_bytes(baseline_bytes)
    env = private / 'probe.env'
    values = dict(line.split('=', 1) for line in (ROOT / '.runtime/oss-core/runtime.env').read_text().splitlines() if '=' in line)
    env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
    ids = {}
    cid_paths = {role: private / (role + '.cid') for role in names}
    report = {'schema': 'expertauth-python-readiness-lab-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'foundation_passed': False, 'input_sha256': inputs, 'base_python_image': image,
              'core_image': core['Image'], 'database_image': pg['Image'], 'database_id': pg['Id'],
              'database_volume': pg_volume[0]['Name'], 'controls': [], 'errors': [], 'created_containers': [],
              'new_images': 0, 'new_volumes': 0, 'new_networks': 0, 'published_ports': []}
    report['baseline_source'] = {'commit': BASELINE_COMMIT, 'path': 'examples/python/app.py', 'sha256': BASELINE_APP_SHA,
                                 'mode': 'read-only historical app overlay on the same dependency image; no obsolete image retained'}
    labels = ['--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=python-readiness-proof']
    common = ['--pull=never', '--network', NETWORK, *labels, '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=64m',
              '--env-file', str(env), '-e', 'SUPERTOKENS_CONNECTION_URI=http://core-a:3567']
    worker = None
    transcript = []
    database_touched = False

    def same_database():
        current = inspect('container', PG_NAME)
        require(current['Id'] == pg['Id'] and current['Image'] == pg['Image'] and current['Mounts'] == pg['Mounts'], 'Database identity/mounts changed; refusing mutation')
        return current

    def restore_database():
        state = same_database()
        if not state['State']['Running']:
            command('start', PG_NAME)
        for attempt in range(40):
            if command('exec', PG_NAME, 'pg_isready', '-U', 'expertauth', '-d', 'expertauth', check=False).returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError('Owned database did not regain pg_isready')

    try:
        for role in ('baseline', 'current'):
            origin = f'http://python-ready-{role}.example.test:8300'
            source_app = ROOT / 'examples/python/app.py' if role == 'current' else baseline_app
            overlay = ['-v', f'{source_app}:/app/app.py:ro']
            ids[role] = command('run', '-d', '--rm', '--name', names[role], '--cidfile', str(cid_paths[role]),
                                '--network-alias', f'python-ready-{role}.example.test', *common,
                                '-e', 'PYTHON_API_DOMAIN=' + origin, '-e', 'WEBSITE_DOMAIN=' + origin, *overlay, image).stdout.strip()
            actual = command('exec', names[role], 'sha256sum', '/app/app.py', '/app/requirements.lock').stdout.splitlines()
            report[role + '_file_sha256'] = {line.split()[1]: line.split()[0] for line in actual}
        require(report['current_file_sha256']['/app/app.py'] == inputs['examples/python/app.py'], 'Current app mount hash differs')
        require(report['baseline_file_sha256']['/app/app.py'] == BASELINE_APP_SHA, 'Baseline app mount hash differs')
        require(report['current_file_sha256']['/app/requirements.lock'] == report['baseline_file_sha256']['/app/requirements.lock'] == inputs['examples/python/requirements.lock'], 'Dependency lock differs')
        worker = subprocess.Popen(['docker', 'run', '--rm', '-i', '--name', names['probe'], '--cidfile', str(cid_paths['probe']),
                                   *common, '-e', 'EVIDENCE_DIR=/evidence', '-v', f'{ROOT}:/repo:ro', '-v', f'{output}:/evidence',
                                   '--entrypoint', 'python', image, '/repo/tests/operations/python_readiness.py'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', bufsize=1)
        lines = queue.Queue()
        def read_lines():
            for line in worker.stdout:
                lines.put(line)
            lines.put(None)
        threading.Thread(target=read_lines, daemon=True).start()
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=2)
            except queue.Empty:
                continue
            if line is None:
                break
            line = line.replace(values['EXPERTAUTH_CORE_API_KEY'], '[REDACTED]')
            transcript.append(line)
            print(line.strip(), flush=True)
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if 'control' not in message:
                continue
            action = message['control']
            if action == 'stop_owned_postgres':
                require(not database_touched and same_database()['State']['Running'], 'Duplicate or invalid stop request')
                backup = subprocess.run(['docker', 'exec', PG_NAME, 'pg_dump', '-U', 'expertauth', '-d', 'expertauth', '-Fc'], capture_output=True, timeout=35)
                require(backup.returncode == 0 and 100 < len(backup.stdout) < 32 * 1024 * 1024, 'Private backup failed or exceeded bound')
                backup_path = private / 'before-outage.pgdump'
                with backup_path.open('xb') as stream:
                    stream.write(backup.stdout)
                report['private_backup'] = {'path': backup_path.relative_to(ROOT).as_posix(), 'bytes': backup_path.stat().st_size, 'sha256': sha(backup_path), 'restore_tested': False}
                database_touched = True  # Restore even if Docker stop's observation fails.
                command('stop', '-t', '10', PG_NAME)
                stopped = same_database()
                require(not stopped['State']['Running'], 'Database was not stopped')
                report['controls'].append({'action': action, 'id': pg['Id'], 'exit_code': stopped['State']['ExitCode'], 'observed_stopped': True})
            elif action in ('start_owned_postgres', 'ensure_postgres_running'):
                restore_database()
                report['controls'].append({'action': action, 'id': pg['Id'], 'pg_isready': True})
            else:
                raise ValueError('Unknown control request')
            worker.stdin.write('{"ok":true}\n'); worker.stdin.flush()
        else:
            raise TimeoutError('Readiness proof exceeded bounded runtime')
        report['probe_exit_code'] = worker.wait(timeout=15)
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            if database_touched:
                restore_database()
            report['database_restored'] = same_database()['State']['Running']
        except Exception as error:
            report['database_restored'] = False
            report['errors'].append('DATABASE RESTORATION BLOCKED: ' + type(error).__name__)
        for role, path in cid_paths.items():
            if path.exists():
                cid = path.read_text().strip()
                if len(cid) == 64 and all(char in '0123456789abcdef' for char in cid):
                    ids[role] = cid
        report['created_containers'] = [{'name': names[role], 'id': cid} for role, cid in ids.items()]
        for role in ('probe', 'current', 'baseline'):
            try:
                existing = command('container', 'inspect', names[role], check=False)
                if existing.returncode:
                    continue
                state = json.loads(existing.stdout)[0]
                owner = state['Config'].get('Labels', {})
                require(state['Id'] == ids.get(role) and owner.get('org.expertauth.project') == 'expert-auth' and
                        owner.get('org.expertauth.purpose') == 'python-readiness-proof', 'Cleanup ownership differs')
                if state['State']['Running']:
                    command('stop', '-t', '5', names[role], check=False)
                command('rm', names[role], check=False)
            except Exception as error:
                report['errors'].append('Cleanup incomplete for ' + names[role] + ': ' + type(error).__name__)
        if worker and worker.poll() is None:
            worker.terminate(); worker.wait(timeout=15)
        (output / 'command-output.log').write_bytes(''.join(transcript).encode())
        try:
            after = inventory()
            report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                             'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
            report['temporary_containers_retired'] = all(cid not in after['containers'] for cid in ids.values())
            new_core = inspect('container', CORE_NAME)
            report['core_unchanged'] = new_core['Id'] == core['Id'] and new_core['Image'] == core['Image'] and new_core['State']['StartedAt'] == core['State']['StartedAt'] and new_core['State']['Running']
            report['database_started_before'] = pg['State']['StartedAt']
            report['database_started_after'] = same_database()['State']['StartedAt']
            report['inputs_unchanged'] = inputs == {path: sha(ROOT / path) for path in SOURCE_INPUTS}
            # Remove only exact nonrecursive temporary credential/CID files. Retain
            # the small private backup and its hash for recovery; never delete DB data.
            if report['temporary_containers_retired']:
                for path in [env, baseline_app, *cid_paths.values()]:
                    require(path.resolve().parent == private.resolve(), 'Private cleanup escaped exact run directory')
                    path.unlink(missing_ok=True)
            report['artifacts'] = [{'path': path.name, 'sha256': sha(path)} for path in sorted(output.iterdir()) if path.is_file()]
        except Exception as error:
            report['errors'].append('Final state inspection failed: ' + type(error).__name__)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        with (output / 'report.json').open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())
    passed = not report['errors'] and report.get('probe_exit_code') == 0 and all(report.get(key) for key in
              ['database_restored', 'temporary_containers_retired', 'core_unchanged', 'inputs_unchanged'])
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'proof_passed': passed, 'errors': report['errors'],
                      'database_restored': report['database_restored'], 'foundation_passed': False}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
