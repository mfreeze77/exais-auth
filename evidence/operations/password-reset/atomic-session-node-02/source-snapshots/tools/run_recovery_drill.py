"""Bounded, isolated recovery characterization using already cached images.

The source database is never stopped or restored. Only owned synthetic users are
created/deleted through the maintained SDK/Core. A fresh pg_dump is encrypted,
then restored into a separately named tmpfs PostgreSQL. No images are built or
pulled, ports published, persistent volumes created, or engine code changed.
This two-user lab does not qualify general recovery or its dependency gates.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
import uuid

from run_sdk_session_faults import ROOT, NETWORK, command, inspect, inventory, sha, require

PYTHON = 'sha256:5bffadb83aa3127f8339e6dcd3e8bc6a04dcbcabf3b66b7dcddfab81369e78fd'
CORE = 'sha256:5ec6ccc3fd5dc7eff16afa48b3bf6abdd4d378077f2428cae3abf8a8bc2e30bf'
POSTGRES = 'sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
SOURCE_CORE = 'expertauth-oss-core-a'
SOURCE_PG = 'expertauth-oss-postgres'
PURPOSE = 'encrypted-recovery-drill'
INPUTS = ['tools/run_recovery_drill.py', 'tools/run_sdk_session_faults.py',
          'tools/recovery_bundle.py', 'tests/operations/test_recovery_bundle.py',
          'tests/operations/recovery_probe.py', 'examples/python/app.py',
          'examples/python/requirements.lock', 'deploy/oss-core.Dockerfile']


def now():
    return datetime.now(timezone.utc).isoformat()


def projection(state):
    return {key: state[key] for key in ('Id', 'Name', 'Image', 'Mounts')} | {
        'started': state['State']['StartedAt'], 'running': state['State']['Running'],
        'ports': state['HostConfig']['PortBindings']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.name), 'Invalid run name')
    output = ROOT / 'evidence/operations/recovery' / args.name
    private = (ROOT / '.runtime/recovery' / args.name).resolve()
    keydir = (ROOT / '.runtime/recovery-keys' / args.name).resolve()
    require(not output.exists() and not private.exists() and not keydir.exists(), 'Preserve previous run')
    require(private.is_relative_to((ROOT / '.runtime/recovery').resolve()) and
            keydir.is_relative_to((ROOT / '.runtime/recovery-keys').resolve()), 'Private boundary differs')
    # Verify all local prerequisites before creating resources or test identities.
    source = {name: projection(inspect('container', name)) for name in (SOURCE_CORE, SOURCE_PG)}
    require(source[SOURCE_CORE]['Image'] == CORE and source[SOURCE_PG]['Image'] == POSTGRES,
            'Source image pins differ')
    require(all(row['running'] and not row['ports'] for row in source.values()), 'Source state differs')
    source_core = inspect('container', SOURCE_CORE)
    source_pg = inspect('container', SOURCE_PG)
    require(source_core['Config']['Labels'].get('org.expertauth.project') == 'expert-auth' and
            source_core['Config']['Labels'].get('org.expertauth.purpose') == 'oss-foundation', 'Unowned source Core')
    # The pre-existing database predates the project label; require its exact
    # pinned image, purpose, named volume and unchanged container projection.
    require(source_pg['Config']['Labels'].get('org.expertauth.purpose') == 'oss-foundation', 'Unowned source database')
    require(any(m['Type'] == 'volume' and m.get('Name') == 'expertauth-oss-proof-pg' and
                m['Destination'] == '/var/lib/postgresql/data' for m in source_pg['Mounts']), 'Source volume differs')
    require(inspect('network', NETWORK)['Internal'], 'Existing private network required')
    memory_text = command('info', '--format', '{{.MemTotal}}').stdout.strip()
    require(memory_text.isdigit() and int(memory_text) >= 8 * 1024 * 1024 * 1024, 'Docker memory is below the bounded lab prerequisite')
    for image_id in (PYTHON, CORE, POSTGRES):
        require(inspect('image', image_id)['Id'] == image_id, 'Required cached image absent')
    config = ROOT / '.runtime/oss-core/config.yaml'
    runtime_env = ROOT / '.runtime/oss-core/runtime.env'
    mounts = [m for m in source_core['Mounts'] if m['Destination'] == '/run/expertauth/config.yaml']
    require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and not mounts[0]['RW'] and
            Path(mounts[0]['Source']).resolve() == config.resolve(), 'Source Core configuration mount differs')
    values = dict(line.split('=', 1) for line in runtime_env.read_text().splitlines() if '=' in line)
    require(values['POSTGRES_USER'] == values['POSTGRES_DB'] == 'expertauth', 'Source database configuration differs')
    input_hashes = {name: sha(ROOT / name) for name in INPUTS}
    private_hashes = {'config': sha(config), 'runtime_env': sha(runtime_env)}
    before = inventory()
    output.mkdir(parents=True)
    private.mkdir(parents=True, mode=0o700)
    keydir.mkdir(parents=True, mode=0o700)
    (private / 'source').mkdir()
    (private / 'worker').mkdir()
    suffix = uuid.uuid4().hex[:12]
    names = {role: 'expertauth-recovery-' + role + '-' + suffix for role in
             ('source-app', 'restored-app', 'postgres', 'core', 'probe')}
    origin = 'http://recovery-' + suffix + '.example.test:8300'
    labels = ['--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=' + PURPOSE,
              '--label', 'org.expertauth.run=' + suffix]
    report = {'schema': 'expertauth-recovery-drill-v1', 'started': now(), 'inputs': input_hashes,
              'foundation_passed': False, 'full_recovery_qualified': False, 'errors': [],
              'images': {'python': PYTHON, 'core': CORE, 'postgres': POSTGRES},
              'docker_total_memory_bytes': int(memory_text),
              'created_containers': [], 'commands': [], 'controls': [], 'image_builds': 0, 'image_downloads': 0,
              'new_volumes': 0, 'new_networks': 0, 'published_ports': [],
              'limits': {'plaintext_bytes': 32 * 1024 * 1024, 'archive_bytes': 48 * 1024 * 1024,
                         'postgres_tmpfs_mib': 256, 'postgres_memory_mib': 512,
                         'core_memory_mib': 1024, 'python_memory_mib': 512, 'worker_timeout_seconds': 300},
              'private_directory': private.relative_to(ROOT).as_posix(),
              'external_key_directory': keydir.relative_to(ROOT).as_posix(),
              'limitations': ['Reference lab; foundation and WP-032 dependencies are unqualified.',
                              'Only two owned post-snapshot revoke/delete actions are replayed; no general durable reconciliation journal.',
                              'No off-machine key custody, key-loss recovery, key rotation, PITR, HA, scale or provider/native proof.',
                              'No independent human security review.']}
    ids, image_by_role = {}, {}
    worker = None
    worker_extra = None
    transcript = []
    helper_count = 0
    env = private / 'probe.env'
    env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
    pg_env = private / 'postgres.env'
    pg_env.write_text('POSTGRES_USER=expertauth\nPOSTGRES_DB=expertauth_restore\nPOSTGRES_PASSWORD=' + values['POSTGRES_PASSWORD'] + '\n')

    def execute(label, argv, *, timeout=45, check=True, input_bytes=None, stdout_path=None):
        """Retain exact raw outputs privately; public evidence has hashes/counts only."""
        index = len(report['commands']) + 1
        raw_out = stdout_path or private / f'command-{index:03d}.stdout'
        raw_err = private / f'command-{index:03d}.stderr'
        started = time.monotonic()
        result = None
        try:
            with raw_out.open('xb') as out, raw_err.open('xb') as err:
                result = subprocess.run(['docker', *argv], input=input_bytes, stdout=out, stderr=err, timeout=timeout)
            require(not check or result.returncode == 0, 'Docker operation failed: ' + label)
            return raw_out.read_bytes(), result.returncode
        finally:
            report['commands'].append({'label': label, 'argv': argv, 'exit_code': result.returncode if result else None,
                                       'elapsed_ms': round((time.monotonic() - started) * 1000, 2),
                                       'stdout': {'bytes': raw_out.stat().st_size, 'sha256': sha(raw_out)} if raw_out.exists() else None,
                                       'stderr': {'bytes': raw_err.stat().st_size, 'sha256': sha(raw_err)} if raw_err.exists() else None})

    def own(role):
        path = private / (role + '.cid')
        if path.exists():
            cid = path.read_text().strip()
            require(re.fullmatch('[0-9a-f]{64}', cid), 'Invalid saved container ID')
            ids[role] = cid
        state = inspect('container', names[role])
        actual_labels = state['Config'].get('Labels', {})
        require(state['Id'] == ids.get(role) and state['Name'] == '/' + names[role] and state['Image'] == image_by_role[role]
                and actual_labels.get('org.expertauth.project') == 'expert-auth'
                and actual_labels.get('org.expertauth.purpose') == PURPOSE
                and actual_labels.get('org.expertauth.run') == suffix
                and not state['HostConfig']['PortBindings'], 'Temporary container ownership differs')
        return state

    def launch_args(role, image_id, extra, *, interactive=False):
        image_by_role[role] = image_id
        return ['run', '--rm', '-i' if interactive else '-d', '--pull=never', '--name', names[role],
                '--cidfile', str(private / (role + '.cid')), *labels, *extra, image_id]

    def launch(role, image_id, extra):
        raw, _ = execute('launch-' + role, launch_args(role, image_id, extra))
        ids[role] = raw.decode().strip()
        own(role)

    python_common = ['--network', NETWORK, '--read-only', '--memory=512m', '--cpus=2', '--pids-limit=128',
                     '--cap-drop=ALL', '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,size=64m',
                     '--env-file', str(env)]

    def app(role, core_url):
        launch(role, PYTHON, [*python_common, '-e', 'SUPERTOKENS_CONNECTION_URI=' + core_url,
                             '-e', 'PYTHON_API_DOMAIN=' + origin, '-e', 'WEBSITE_DOMAIN=' + origin])
        installed = command('exec', ids[role], 'sha256sum', '/app/app.py', '/app/requirements.lock').stdout.splitlines()
        actual = {line.split()[1]: line.split()[0] for line in installed}
        require(actual['/app/app.py'] == input_hashes['examples/python/app.py'] and
                actual['/app/requirements.lock'] == input_hashes['examples/python/requirements.lock'], 'Installed app inputs differ')
        report.setdefault('installed_application', {})[role] = actual
        for _ in range(50):
            own(role)
            check = command('exec', ids[role], 'python', '-c',
                            'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8300/ready",timeout=4).status==200',
                            check=False, timeout=8)
            if check.returncode == 0:
                return
            time.sleep(0.4)
        raise ValueError('Temporary application readiness failed')

    def utility(label, arguments, *, unittest=False):
        nonlocal helper_count
        helper_count += 1
        role = 'utility-' + str(helper_count)
        names[role] = 'expertauth-recovery-' + role + '-' + suffix
        extra = ['--network=none', '--read-only', '--memory=512m', '--cpus=2', '--pids-limit=128', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,size=64m',
                 '-v', f'{ROOT}:/repo:ro', '-v', f'{private}:/private',
                 '-v', f'{keydir}:/keys' + ('' if label == 'keygen' else ':ro'), '--entrypoint', 'python']
        argv = launch_args(role, PYTHON, extra, interactive=True) + arguments
        raw, exit_code = execute(label, argv, timeout=60, check=False)
        if (private / (role + '.cid')).exists():
            ids[role] = (private / (role + '.cid')).read_text().strip()
        require(exit_code == 0, 'Recovery utility failed: ' + label)
        if unittest:
            stderr = (private / f'command-{len(report["commands"]):03d}.stderr').read_bytes()
            # unittest output contains only authored names/assertions; keep exact passing output.
            require(b'\nOK\n' in stderr and b'skipped=' not in stderr, 'Recovery format tests did not pass')
            (output / 'bundle-unittest.log').write_bytes(raw + stderr)
            return
        result = json.loads(raw)
        report[label] = result
        return result

    def source_unchanged():
        require(all(projection(inspect('container', name)) == old for name, old in source.items()), 'Source service process or mounts changed')
        require(private_hashes == {'config': sha(config), 'runtime_env': sha(runtime_env)}, 'Private source configuration changed')

    def snapshot():
        source_unchanged()
        started = time.monotonic()
        (private / 'source/core-config.yaml').write_bytes(config.read_bytes())
        (private / 'source/runtime.env').write_bytes(runtime_env.read_bytes())
        size = command('exec', source[SOURCE_PG]['Id'], 'psql', '-U', 'expertauth', '-d', 'expertauth', '-At',
                       '-c', "SELECT pg_database_size(current_database())").stdout.strip()
        require(size.isdigit() and int(size) < 16 * 1024 * 1024, 'Database exceeds bounded drill profile')
        report['source_database_bytes'] = int(size)
        report['snapshot_started'] = now()
        execute('source-pg-dump', ['exec', source[SOURCE_PG]['Id'], 'pg_dump', '-U', 'expertauth', '-d', 'expertauth', '-Fc'],
                timeout=45, stdout_path=private / 'source/database.pgdump')
        require(0 < (private / 'source/database.pgdump').stat().st_size <= 32 * 1024 * 1024, 'Dump size outside bound')
        report['snapshot_finished'] = now()
        utility('keygen', ['-B', '/repo/tools/recovery_bundle.py', 'keygen', '--key', '/keys/bundle.key'])
        utility('pack', ['-B', '/repo/tools/recovery_bundle.py', 'pack', '--source', '/private/source',
                         '--key', '/keys/bundle.key', '--archive', '/private/backup.fernet'])
        report['backup_elapsed_ms'] = round((time.monotonic() - started) * 1000, 2)

    def restore():
        source_unchanged()
        started = time.monotonic()
        utility('unpack', ['-B', '/repo/tools/recovery_bundle.py', 'unpack', '--archive', '/private/backup.fernet',
                           '--key', '/keys/bundle.key', '--destination', '/private/restored'])
        require(report['pack']['files'] == report['unpack']['files'], 'Restored bytes differ from encrypted inventory')
        text = (private / 'restored/core-config.yaml').read_text()
        text, host_count = re.subn(r'(?m)^postgresql_host: postgres\s*$', 'postgresql_host: ' + names['postgres'], text)
        text, db_count = re.subn(r'(?m)^postgresql_database_name: expertauth\s*$', 'postgresql_database_name: expertauth_restore', text)
        require(host_count == db_count == 1, 'Isolated configuration routing could not be proved')
        (private / 'restored-core.yaml').write_text(text)
        report['configuration_routing_changes'] = ['postgresql_host', 'postgresql_database_name']
        report['restored_config_sha256'] = sha(private / 'restored-core.yaml')
        launch('postgres', POSTGRES, ['--network', NETWORK, '--memory=512m', '--cpus=2', '--pids-limit=128',
                                     '--security-opt=no-new-privileges', '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,size=256m',
                                     '--tmpfs', '/var/run/postgresql:rw,nosuid,size=16m', '--env-file', str(pg_env)])
        state = own('postgres')
        require(not any(m['Type'] == 'volume' for m in state['Mounts']), 'Disposable database acquired a volume')
        require('/var/lib/postgresql/data' in state['HostConfig']['Tmpfs'], 'Disposable database storage is not bounded tmpfs')
        for _ in range(60):
            if command('exec', ids['postgres'], 'pg_isready', '-U', 'expertauth', '-d', 'expertauth_restore', check=False).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise ValueError('Disposable PostgreSQL did not become ready')
        own('postgres')
        execute('restore-into-new-local-database', ['exec', '-i', ids['postgres'], 'pg_restore', '--exit-on-error', '--single-transaction',
                                                 '--no-owner', '--no-privileges', '-U', 'expertauth', '-d', 'expertauth_restore'],
                timeout=60, input_bytes=(private / 'restored/database.pgdump').read_bytes())
        launch('core', CORE, ['--network', NETWORK, '--memory=1g', '--cpus=2', '--pids-limit=256',
                             '--security-opt=no-new-privileges', '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=16m',
                             '-v', f'{private / "restored-core.yaml"}:/run/expertauth/config.yaml:ro'])
        # The worker checks authenticated restored Core readiness before inspecting historical state.
        report['restore_requested_elapsed_ms'] = round((time.monotonic() - started) * 1000, 2)
        report['restored_database_isolated'] = True

    try:
        utility('bundle-tests', ['-B', '-m', 'unittest', 'discover', '-s', '/repo/tests/operations',
                                 '-p', 'test_recovery_bundle.py', '-v'], unittest=True)
        app('source-app', 'http://' + SOURCE_CORE + ':3567')
        worker_extra = [*python_common, '-v', f'{ROOT}:/repo:ro', '-v', f'{output}:/evidence',
                           '-v', f'{private / "worker"}:/private', '-e', 'EVIDENCE_DIR=/evidence', '-e', 'PRIVATE_DIR=/private',
                           '-e', 'SOURCE_APP_URL=http://' + names['source-app'] + ':8300',
                           '-e', 'RESTORED_APP_URL=http://' + names['restored-app'] + ':8300',
                           '-e', 'SOURCE_CORE_URL=http://' + SOURCE_CORE + ':3567',
                           '-e', 'RESTORED_CORE_URL=http://' + names['core'] + ':3567', '-e', 'LOGICAL_ORIGIN=' + origin,
                           '--entrypoint', 'python']
        argv = launch_args('probe', PYTHON, worker_extra, interactive=True) + ['-B', '/repo/tests/operations/recovery_probe.py']
        report['worker_argv'] = argv
        worker = subprocess.Popen(['docker', *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, encoding='utf-8', bufsize=1)
        lines = queue.Queue()
        def reader():
            for line in worker.stdout:
                lines.put(line)
            lines.put(None)
        threading.Thread(target=reader, daemon=True).start()
        deadline = time.monotonic() + 300
        expected = ['snapshot', 'restore', 'start_restored_app']
        while time.monotonic() < deadline:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                continue
            if line is None:
                break
            transcript.append(line)
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if 'control' not in message:
                continue
            action = message['control']
            require(len(report['controls']) < len(expected) and action == expected[len(report['controls'])], 'Unexpected worker control sequence')
            print(json.dumps({'control': action, 'state': 'running'}), flush=True)
            started = time.monotonic()
            if action == 'snapshot':
                snapshot()
            elif action == 'restore':
                restore()
            else:
                app('restored-app', 'http://' + names['core'] + ':3567')
            report['controls'].append({'action': action, 'completed': now(), 'elapsed_ms': round((time.monotonic() - started) * 1000, 2)})
            worker.stdin.write('{"ok":true}\n')
            worker.stdin.flush()
        require(worker.poll() is not None or time.monotonic() < deadline, 'Recovery worker exceeded bounded runtime')
        report['worker_exit_code'] = worker.wait(timeout=15)
        require(report['worker_exit_code'] == 0, 'Recovery HTTP worker failed')
        require([row['action'] for row in report['controls']] == expected, 'Recovery controls incomplete')
        probe = json.loads((output / 'probe-report.json').read_text())
        require(probe.get('ok') is True, 'Recovery HTTP evidence did not pass')
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        # Give a failed worker the opportunity to clean its own users before removal.
        if worker and worker.poll() is None:
            try:
                worker.stdin.write('{"ok":false}\n')
                worker.stdin.flush()
                worker.wait(timeout=25)
            except (OSError, subprocess.TimeoutExpired):
                report['errors'].append('Worker cleanup did not finish; private identity state preserved')
        # If normal cleanup was interrupted, retire that exact worker before a
        # separate idempotent, ownership-checked cleanup using its private state.
        if report['errors'] and (private / 'worker/state.json').exists() and worker_extra:
            try:
                if worker and worker.poll() is None:
                    own('probe')
                    execute('stop-failed-probe', ['stop', '-t', '5', ids['probe']], check=False)
                    worker.wait(timeout=10)
                role = 'cleanup'
                names[role] = 'expertauth-recovery-cleanup-' + suffix
                cleanup_argv = launch_args(role, PYTHON, worker_extra, interactive=True) + [
                    '-B', '/repo/tests/operations/recovery_probe.py', '--cleanup-only']
                _, cleanup_code = execute('fallback-identity-cleanup', cleanup_argv, timeout=60, check=False)
                report['fallback_cleanup_exit_code'] = cleanup_code
                require(cleanup_code == 0, 'Fallback identity cleanup failed')
            except Exception as error:
                report['errors'].append('Fallback identity cleanup failed: ' + type(error).__name__)
        try:
            (private / 'worker-output.log').write_text(''.join(transcript))
            report['worker_output'] = {'bytes': (private / 'worker-output.log').stat().st_size, 'sha256': sha(private / 'worker-output.log')}
        except OSError:
            report['errors'].append('Private transcript preservation failed')
        # Reverse creation order; exact ID, image and all three ownership labels required.
        for role in reversed(list(image_by_role)):
            try:
                cid_path = private / (role + '.cid')
                if cid_path.exists():
                    cid = cid_path.read_text().strip()
                    require(re.fullmatch('[0-9a-f]{64}', cid), 'Malformed cleanup CID')
                    ids[role] = cid
                if command('container', 'inspect', names[role], check=False).returncode:
                    continue
                state = own(role)
                if state['State']['Running']:
                    execute('stop-' + role, ['stop', '-t', '5', ids[role]], check=False)
                if command('container', 'inspect', ids[role], check=False).returncode == 0:
                    own(role)
                    execute('remove-' + role, ['rm', ids[role]])
            except Exception as error:
                report['errors'].append('Temporary cleanup failed: ' + role + ': ' + type(error).__name__)
        if worker and worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                report['errors'].append('Docker worker client did not exit')
        report['created_containers'] = [{'role': role, 'name': names[role], 'id': cid, 'image': image_by_role[role]} for role, cid in ids.items()]
        try:
            source_unchanged()
            report['source_services_unchanged'] = True
            after = inventory()
            report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                             'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
            report['resources_restored'] = before == after
            report['inputs_unchanged'] = input_hashes == {name: sha(ROOT / name) for name in INPUTS}
            require(report['resources_restored'] and report['inputs_unchanged'], 'Resource inventory or source inputs changed')
            require(all(not command('ps', '-aq', '--filter', 'name=^/' + name + '$').stdout.strip() for name in names.values()), 'Temporary container remains')
            report['private_artifacts'] = [{'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)}
                                           for p in sorted(private.rglob('*')) if p.is_file()]
            # Preserve encrypted archive, external key, reconciliation state and exact failure evidence.
            # Retire only known duplicate plaintext payloads after successful HTTP cleanup proof.
            if not report['errors']:
                probe = json.loads((output / 'probe-report.json').read_text())
                require(probe.get('ok') is True, 'Identity cleanup not proven; preserve private recovery inputs')
                removed = []
                for folder in ('source', 'restored'):
                    directory = (private / folder).resolve()
                    require(directory.parent == private, 'Plaintext cleanup boundary differs')
                    require({p.name for p in directory.iterdir()} == {'database.pgdump', 'core-config.yaml', 'runtime.env'}, 'Unexpected private payload')
                    for p in directory.iterdir():
                        require(p.is_file() and not p.is_symlink(), 'Unexpected payload type')
                        p.unlink()
                        removed.append(p.relative_to(ROOT).as_posix())
                    directory.rmdir()
                for p in [env, pg_env, private / 'restored-core.yaml', *[private / (role + '.cid') for role in image_by_role]]:
                    require(p.resolve().parent == private, 'Scratch cleanup boundary differs')
                    p.unlink(missing_ok=True)
                report['duplicate_plaintext_removed'] = removed
            report['private_bytes_retained'] = sum(p.stat().st_size for p in private.rglob('*') if p.is_file())
            report['external_key_retained'] = (keydir / 'bundle.key').is_file()
        except Exception as error:
            report['errors'].append('Final verification failed: ' + type(error).__name__)
        report['finished'] = now()
        report['bounded_drill_passed'] = not report['errors'] and report.get('worker_exit_code') == 0 and report.get('resources_restored', False)
        try:
            report['artifacts'] = [{'path': p.name, 'sha256': sha(p)} for p in sorted(output.iterdir()) if p.is_file()]
        except OSError:
            report['errors'].append('Public artifact hashing failed')
            report['bounded_drill_passed'] = False
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'bounded_drill_passed': report['bounded_drill_passed'],
                      'full_recovery_qualified': False, 'errors': report['errors']}))
    return 0 if report['bounded_drill_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
