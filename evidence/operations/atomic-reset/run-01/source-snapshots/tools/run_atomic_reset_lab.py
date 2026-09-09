"""Exercise the adapted Core against one new disposable database and two replicas.

Cached images only. No source database access, new images/volumes/networks or
published ports. Every resource is owned by this run and retired in finally.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

from run_recovery_drill import projection, SOURCE_CORE, SOURCE_PG, CORE, POSTGRES
from run_sdk_session_faults import inspect, inventory, NETWORK

ROOT = Path(__file__).resolve().parents[1]
PROBE = 'tests/operations/AtomicResetProbe.java'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.name), 'Invalid run name')
    output = ROOT / 'evidence/operations/atomic-reset' / args.name
    private = (ROOT / '.runtime/atomic-reset' / args.name).resolve()
    need(not output.exists() and not private.exists() and private.is_relative_to(ROOT / '.runtime/atomic-reset'), 'Preserve prior evidence/private data')
    build_path = ROOT / 'evidence/operations/core-reset-build/compile-03/report.json'
    build = json.loads(build_path.read_text())
    need(build['passed'] and all(sha(ROOT / name) == value for name, value in build['inputs'].items()), 'Current Core extension differs from compiled source')
    jar = ROOT / build['candidate']['path']; need(sha(jar) == build['candidate']['sha256'], 'Adapted Core JAR differs')
    source_before = {name: projection(inspect('container', name)) for name in (SOURCE_CORE, SOURCE_PG)}
    network = inspect('network', NETWORK); need(network['Internal'], 'Existing private network must block egress')
    for image in (CORE, POSTGRES): need(inspect('image', image)['Id'] == image, 'Cached image differs')
    before = inventory()
    output.mkdir(parents=True); (private / 'secrets').mkdir(parents=True)
    suffix = uuid.uuid4().hex[:12]
    names = {role: 'expertauth-reset-' + role + '-' + suffix for role in ['postgres', 'core-a', 'core-b', 'ready', 'worker']}
    password, key = secrets.token_hex(32), secrets.token_hex(32)
    pg_env, worker_env, config = (private / 'secrets' / p for p in ['postgres.env', 'worker.env', 'core.yaml'])
    pg_env.write_text('POSTGRES_USER=expertauth_reset\nPOSTGRES_DB=expertauth_reset\nPOSTGRES_PASSWORD=' + password + '\n')
    worker_env.write_text('RESET_CORE_A=http://' + names['core-a'] + ':3567\nRESET_CORE_B=http://' + names['core-b'] + ':3567\n'
        'RESET_CORE_API_KEY=' + key + '\nRESET_DATABASE_PASSWORD=' + password + '\nRESET_JDBC_URL=jdbc:postgresql://' + names['postgres'] + ':5432/expertauth_reset\n')
    config.write_text('core_config_version: 0\npostgresql_config_version: 0\nhost: 0.0.0.0\nport: 3567\n'
        'api_keys: "' + key + '"\npostgresql_host: ' + names['postgres'] + '\npostgresql_port: 5432\npostgresql_user: expertauth_reset\n'
        'postgresql_password: "' + password + '"\npostgresql_database_name: expertauth_reset\ndisable_telemetry: true\n'
        'access_token_validity: 60\naccess_token_validity_jitter: 0\nrefresh_token_rotation_grace_period: 0\n'
        'recent_token_reuse_behaviour: TOKEN_THEFT\nmax_server_pool_size: 12\npostgresql_connection_pool_size: 12\npassword_reset_token_lifetime: 6000\n')
    sources = ['tools/run_atomic_reset_lab.py', 'tools/run_recovery_drill.py', 'tools/run_sdk_session_faults.py', PROBE,
               'engine-extensions/core-reset/reuse.json', *build['inputs'].keys()]
    report = {'kind': 'isolated-atomic-reset-lab', 'started': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'foundation_passed': False, 'full_PWD_006_qualified': False, 'independent_human_review': False,
              'images_built': 0, 'image_downloads': 0, 'new_volumes': 0, 'new_networks': 0, 'published_ports': [],
              'source_database_contacted': False, 'run_id': suffix, 'inputs': {p: sha(ROOT / p) for p in sources},
              'compiled_jar_sha256': sha(jar), 'build_report_sha256': sha(build_path), 'commands': [], 'errors': [],
              'created_containers': [], 'retired_containers': [], 'resources_before': before, 'source_before': source_before}
    for name in sources:
        target = output / 'source-snapshots' / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((ROOT / name).read_bytes())
    ids = {}; labels = {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': 'atomic-reset-lab', 'org.expertauth.run': suffix}

    def persist():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def call(argv, timeout=35, required=True):
        index = len(report['commands']) + 1; row = {'argv': argv, 'exit_code': None, 'timed_out': False}
        report['commands'].append(row); result = None
        files = {stream: private / f'command-{index:03d}.{stream}' for stream in ['stdout', 'stderr']}
        try:
            with files['stdout'].open('xb') as out, files['stderr'].open('xb') as err:
                result = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, stdin=subprocess.DEVNULL, timeout=timeout)
            row['exit_code'] = result.returncode
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
        finally:
            for stream, p in files.items(): row[stream] = {'bytes': p.stat().st_size, 'sha256': sha(p)}
            persist()
        need(result is not None, 'Command deadline exceeded: ' + str(index))
        need(not required or result.returncode == 0, 'Command failed: ' + str(index))
        return result.returncode, files['stdout'].read_bytes()

    def own(role):
        reference = ids.get(role, names[role])
        fmt = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"mounts":{{json .Mounts}},"ports":{{json .HostConfig.PortBindings}}}'
        code, raw = call(['docker', 'inspect', '--format', fmt, reference], required=False)
        if code: return None
        state = json.loads(raw)
        need(state['name'] == '/' + names[role] and state['image'] == (POSTGRES if role == 'postgres' else CORE) and
             all((state['labels'] or {}).get(k) == v for k, v in labels.items()) and not state['ports'] and
             not any(row['Type'] == 'volume' for row in state['mounts']), 'Owned container identity, ports or volume boundary differs')
        if role in ids: need(state['id'] == ids[role], 'Container ID changed')
        ids[role] = state['id']; return state

    def launch(role, extra, *, arguments=(), wait=False, timeout=40):
        image = POSTGRES if role == 'postgres' else CORE
        need(not call(['docker', 'ps', '-aq', '--filter', 'name=^/' + names[role] + '$'])[1].strip(), 'Container name occupied')
        argv = ['docker', 'run', '--rm', '--pull=never', '--name', names[role], '--cidfile', str(private / (role + '.cid')),
                '--network', NETWORK, '--cpus=2', '--security-opt=no-new-privileges', '--log-driver=local', '--log-opt=max-size=1m', '--log-opt=max-file=1']
        for k, v in labels.items(): argv += ['--label', k + '=' + v]
        if not wait: argv += ['-d']
        argv += [*extra, image, *arguments]
        try:
            return call(argv, timeout=timeout)
        finally:
            cidfile = private / (role + '.cid')
            if cidfile.exists():
                cid = cidfile.read_text().strip(); need(re.fullmatch('[0-9a-f]{64}', cid), 'Incomplete CID file')
                ids[role] = cid; report['created_containers'].append({'role': role, 'id': cid, 'name': names[role], 'image': image}); persist()

    def worker(role, args=()):
        extra = ['--read-only', '--memory=512m', '--pids-limit=128', '--cap-drop=ALL', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                 '--tmpfs', '/home/gradle/.gradle:rw,nosuid,nodev,noexec,size=1m', '--env-file', str(worker_env),
                 '--mount', f'type=bind,source={ROOT/PROBE},target=/src/AtomicResetProbe.java,readonly',
                 '--mount', f'type=bind,source={output},target=/out', '--entrypoint', 'java']
        return launch(role, extra, arguments=['-Xmx256m', '-cp', '/opt/expertauth/lib/*:/opt/expertauth/plugin/*', '/src/AtomicResetProbe.java', *args], wait=True, timeout=180)

    try:
        launch('postgres', ['--memory=512m', '--pids-limit=128', '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,size=256m',
               '--tmpfs', '/var/run/postgresql:rw,nosuid,size=16m', '--env-file', str(pg_env)])
        need(own('postgres') is not None, 'Temporary database missing')
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            code, _ = call(['docker', 'exec', ids['postgres'], 'pg_isready', '-U', 'expertauth_reset', '-d', 'expertauth_reset'], required=False)
            if code == 0: break
            time.sleep(0.3)
        else: raise ValueError('Temporary database readiness failed')
        for role in ['core-a', 'core-b']:
            launch(role, ['--memory=1g', '--pids-limit=256', '--tmpfs', '/tmp:rw,nosuid,noexec,size=64m',
                '--tmpfs', '/home/gradle/.gradle:rw,nosuid,noexec,size=1m',
                '--mount', f'type=bind,source={config},target=/run/expertauth/config.yaml,readonly',
                '--mount', f'type=bind,source={jar},target=/opt/expertauth/lib/core-12.2.0.jar,readonly'])
            need(own(role) is not None, 'Temporary Core missing')
            _, raw = call(['docker', 'exec', ids[role], 'sha256sum', '/opt/expertauth/lib/core-12.2.0.jar'])
            need(raw.decode().split()[0] == sha(jar), 'Actual mounted Core JAR differs')
            if role == 'core-a': worker('ready', ['--ready-a'])
        print('Two temporary adapted Core replicas started against their own database.', flush=True)
        worker('worker')
        result = json.loads((output / 'probe-report.json').read_text())
        need(result['subset_passed'] and len(result['rows']) == 8 and all(row['status'] == 'passed' for row in result['rows']), 'Actual Core cases incomplete')
        need(not result['full_PWD_006_qualified'] and not result['foundation_passed'], 'Overbroad acceptance claim')
        report['probe_sha256'] = sha(output / 'probe-report.json'); report['work_passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        for role in reversed(list(names)):
            try:
                state = own(role)
                if state:
                    if role.startswith('core') and report['errors']:
                        call(['docker', 'logs', '--tail', '120', state['id']], required=False)
                    if state['running']: call(['docker', 'stop', '--time=5', state['id']], timeout=20, required=False)
                    if own(role): call(['docker', 'rm', '-f', state['id']], timeout=20, required=False)
                need(not call(['docker', 'ps', '-aq', '--filter', 'name=^/' + names[role] + '$'])[1].strip(), 'Temporary resource remains')
                if role in ids:
                    need(ids[role] not in call(['docker', 'ps', '-aq', '--no-trunc'])[1].decode().splitlines(), 'Exact container remains')
                    report['retired_containers'].append({'role': role, 'id': ids[role]})
            except Exception as error:
                report['errors'].append(str(error) if isinstance(error, ValueError) else 'Retirement failed: ' + type(error).__name__)
        try:
            report['resources_after'] = inventory(); report['resources_unchanged'] = before == report['resources_after']
            report['source_after'] = {name: projection(inspect('container', name)) for name in source_before}
            report['source_unchanged'] = report['source_after'] == source_before
            report['inputs_unchanged'] = report['inputs'] == {p: sha(ROOT / p) for p in sources} and sha(jar) == report['compiled_jar_sha256']
            need(report['resources_unchanged'] and report['source_unchanged'] and report['inputs_unchanged'], 'Source or resource preservation failed')
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
        report['passed'] = not report['errors'] and report.get('work_passed') is True
        report['finished'] = datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'passed': report['passed'], 'foundation_passed': False, 'created': len(report['created_containers']),
                     'retired': len(report['retired_containers']), 'errors': report['errors'], 'report': output.relative_to(ROOT).as_posix()}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
