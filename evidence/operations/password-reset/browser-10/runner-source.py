"""Bounded real SMTP/HTTP/browser reset lab; retire every temporary container.

One existing authoritative database is preserved. Only synthetic identities are
created/removed via SDK/Core APIs. A temporary unchanged Core instance sets a
short reset-token TTL; no database tables, source engine, or clock are patched.
Application sources are mounted over the cached dependency image for this lab.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

from run_sdk_session_faults import ROOT, NETWORK, command, inspect, inventory, require, sha, BROWSER
from run_recovery_drill import projection, PYTHON, CORE, SOURCE_CORE, SOURCE_PG

NODE = 'sha256:a0cf7009def4f1fb626e67c2e43103dbc6d654fc2697aab28a4390868d869eaf'
MAIL = 'ghcr.io/axllent/mailpit:v1.31.1@sha256:3856f9327f3f228afe8c4ce2dcca3cb2aa00f6ec60b569f36483f7ebb1ff44f7'
PURPOSE = 'password-reset-lab'
INPUTS = ['tools/run_password_reset_lab.py', 'tools/run_sdk_session_faults.py', 'tools/run_recovery_drill.py',
          'tests/operations/password_reset_cleanup.py',
          'tests/operations/password_reset_tls.py', 'tests/operations/password_reset_probe.mjs',
          'tests/browser/password-reset.mjs', 'tests/browser/package-lock.json',
          'examples/node-react/server.js', 'examples/node-react/email-delivery.js',
          'examples/node-react/test/email-delivery.test.js', 'examples/node-react/package-lock.json',
          'examples/node-react/client.jsx', 'examples/node-react/Dockerfile']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--browser-only', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.name), 'Invalid run name')
    private = (ROOT / '.runtime/password-reset' / args.name).resolve()
    output = ROOT / 'evidence/operations/password-reset' / args.name
    require(private.parent == (ROOT / '.runtime/password-reset').resolve() and not private.exists() and not output.exists(), 'Preserve existing evidence')
    source = {name: projection(inspect('container', name)) for name in (SOURCE_CORE, SOURCE_PG)}
    require(source[SOURCE_CORE]['Image'] == CORE and all(row['running'] and not row['ports'] for row in source.values()), 'Preserved service state differs')
    require(inspect('container', SOURCE_CORE)['Config']['Labels'].get('org.expertauth.project') == 'expert-auth', 'Core ownership differs')
    require(inspect('container', SOURCE_PG)['Config']['Labels'].get('org.expertauth.purpose') == 'oss-foundation', 'Database ownership differs')
    require(inspect('network', NETWORK)['Internal'], 'Private existing network required')
    images = {role: inspect('image', ref)['Id'] for role, ref in [('python', PYTHON), ('node', NODE), ('core', CORE), ('browser', BROWSER), ('mail', MAIL)]}
    inputs = {path: sha(ROOT / path) for path in INPUTS}
    config, runtime_env = ROOT / '.runtime/oss-core/config.yaml', ROOT / '.runtime/oss-core/runtime.env'
    private_hashes = {'config': sha(config), 'runtime_env': sha(runtime_env)}
    require(not re.search(r'^password_reset_token_lifetime:', config.read_text(), re.M), 'Source TTL already customized; re-evaluate lab')
    values = dict(line.split('=', 1) for line in runtime_env.read_text().splitlines() if '=' in line)
    private.mkdir(parents=True)
    output.mkdir(parents=True)
    secrets = private / 'secrets'
    secrets.mkdir()
    suffix = uuid.uuid4().hex[:10]
    mailhost = 'reset-mail-' + suffix + '.example.test'
    labels = {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': PURPOSE, 'org.expertauth.run': suffix}
    common = ['--network', NETWORK, '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges']
    resources_before = inventory()
    report = {'schema': 'expertauth-password-reset-orchestration-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'inputs': inputs, 'images': images, 'application_mode': 'cached dependency image with exact read-only source mounts',
              'passed': False, 'foundation_passed': False, 'full_PWD_006_qualified': False, 'mode': 'browser-only' if args.browser_only else 'full-reference-lab',
              'image_builds': 0, 'image_downloads': 0, 'new_volumes': 0, 'new_networks': 0, 'published_ports': [],
              'commands': [], 'created_containers': [], 'retired_containers': [], 'errors': [],
              'tmpfs_limits_mib': {'mail_database': 64, 'mail_tmp': 16, 'core_gradle': 16, 'node_tmp': 16, 'browser_tmp': 256, 'browser_shm': 256},
              'private_directory': private.relative_to(ROOT).as_posix()}
    containers = {}
    service_processes = {}

    def execute(label, argv, timeout=40, required=True):
        index = len(report['commands']) + 1
        stdout, stderr = private / f'command-{index:03d}.stdout', private / f'command-{index:03d}.stderr'
        result = None
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                result = subprocess.run(['docker', *argv], stdout=out, stderr=err, timeout=timeout)
            require(not required or result.returncode == 0, 'Docker operation failed: ' + label)
            return stdout.read_bytes(), result.returncode
        finally:
            report['commands'].append({'label': label, 'argv': argv, 'exit_code': result.returncode if result else None,
                                       'stdout': {'bytes': stdout.stat().st_size, 'sha256': sha(stdout)},
                                       'stderr': {'bytes': stderr.stat().st_size, 'sha256': sha(stderr)}})

    def own(role):
        row = containers[role]
        if row['cidfile'].exists():
            row['id'] = row['cidfile'].read_text().strip()
        require(re.fullmatch('[0-9a-f]{64}', row.get('id', '')), 'Missing owned container ID')
        found = command('container', 'inspect', row['id'], check=False)
        if found.returncode:
            require(not command('ps', '-aq', '--filter', 'name=^/' + row['name'] + '$').stdout.strip(), 'Name reused')
            return None
        state = json.loads(found.stdout)[0]
        require(state['Id'] == row['id'] and state['Name'] == '/' + row['name'] and state['Image'] == row['image'] and
                all(state['Config']['Labels'].get(k) == v for k, v in labels.items()) and not state['HostConfig']['PortBindings'], 'Temporary container ownership differs')
        return state

    def launch(role, image, extra, arguments=None, *, foreground=False, timeout=40):
        name = 'expertauth-reset-' + role + '-' + suffix
        require(command('container', 'inspect', name, check=False).returncode != 0, 'Temporary name collision')
        row = containers[role] = {'name': name, 'image': image, 'cidfile': private / (role + '.cid')}
        argv = ['run', '--rm', '--pull=never', '--name', name, '--cidfile', str(row['cidfile'])]
        for key, value in labels.items():
            argv += ['--label', key + '=' + value]
        argv += extra + [image] + (arguments or [])
        if foreground:
            raw, code = execute('launch-' + role, argv, timeout, required=False)
        else:
            # Attach from process creation so --rm cannot erase a startup error
            # before a subsequent `docker logs` request reaches the daemon.
            index = len(report['commands']) + 1
            paths = [private / f'command-{index:03d}.{stream}' for stream in ('stdout', 'stderr')]
            handles = [path.open('xb') for path in paths]
            process = subprocess.Popen(['docker', *argv], stdin=subprocess.DEVNULL, stdout=handles[0], stderr=handles[1])
            entry = {'label': 'launch-' + role, 'argv': argv, 'exit_code': None}
            report['commands'].append(entry)
            service_processes[role] = (process, handles, paths, entry)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                if row['cidfile'].exists() and re.fullmatch('[0-9a-f]{64}', row['cidfile'].read_text().strip()):
                    break
                time.sleep(0.05)
            raw, code = b'', process.poll() or 0
        state = own(role)
        report['created_containers'].append({'role': role, 'name': name, 'id': row['id'], 'image': image})
        if not foreground:
            require(state and state['State']['Running'], 'Temporary service failed: ' + role)
        require(code == 0, 'Temporary operation failed: ' + role)
        return raw

    def utility(role, arguments):
        return launch(role, images['python'], [*common, '--user=0', '--memory=256m', '--cpus=1', '--pids-limit=64',
          '-v', f'{ROOT / "tests/operations/password_reset_tls.py"}:/script.py:ro',
          '-v', f'{secrets}:/private', '-v', f'{output}:/out', '--entrypoint', 'python'],
          ['-B', '/script.py', *arguments], foreground=True, timeout=70)

    def retire(role):
        row = containers[role]
        state = own(role)
        if state:
            execute('retire-' + role, ['stop', '--timeout=3', row['id']])
        deadline = time.monotonic() + 5
        while command('ps', '-aq', '--no-trunc', '--filter', 'id=' + row['id']).stdout.strip() and time.monotonic() < deadline:
            time.sleep(0.1)
        require(not command('ps', '-aq', '--no-trunc', '--filter', 'id=' + row['id']).stdout.strip(), 'Owned helper remains')
        report['retired_containers'].append({'role': role, 'id': row['id']})

    try:
        utility('certificates', ['prepare', '--directory', '/private', '--mail-host', mailhost])
        mail_env = secrets / 'mail.env'
        mail_env.write_text('\n'.join(['MP_SMTP_BIND_ADDR=0.0.0.0:1025', 'MP_SMTP_TLS_CERT=/run/mailpit/tls.crt',
            'MP_SMTP_TLS_KEY=/run/mailpit/tls.key', 'MP_SMTP_REQUIRE_TLS=true', 'MP_SMTP_AUTH_FILE=/run/mailpit/smtp-auth',
            'MP_UI_AUTH_FILE=/run/mailpit/ui-auth', 'MP_UI_TLS_CERT=/run/mailpit/tls.crt', 'MP_UI_TLS_KEY=/run/mailpit/tls.key',
            'MP_DISABLE_VERSION_CHECK=true', 'MP_SMTP_DISABLE_RDNS=true', 'MP_MAX_MESSAGES=50', 'MP_MAX_MESSAGE_SIZE=5',
            'MP_ALLOWED_HOSTS=' + mailhost + ':8025', 'MP_DATABASE=/data/mailpit.db']) + '\n')
        launch('mail', images['mail'], [*common, '--memory=256m', '--cpus=1', '--pids-limit=128',
            '--network-alias', mailhost, '--tmpfs', '/data:rw,nosuid,noexec,size=64m', '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m',
            '--env-file', str(mail_env), '-v', f'{secrets}:/run/mailpit:ro'])
        time.sleep(0.8)
        if not args.browser_only:
            utility('tls-proof', ['verify', '--directory', '/private', '--output', '/out/tls-results.json'])
        launch('client-file-ownership', images['python'], ['--network=none', '--read-only', '--user=0',
            '--memory=128m', '--cpus=1', '--pids-limit=32', '--cap-drop=ALL', '--cap-add=CHOWN',
            '--security-opt=no-new-privileges', '-v', f'{secrets}:/private', '--entrypoint', 'python'],
            ['-B', '-c', 'from pathlib import Path; import os; p=Path("/private"); '
             '[(os.chmod(p/n,0o400),os.chown(p/n,1000,1000)) for n in ["smtp-password","wrong-password"]]; '
             'os.chmod(p/"ca.crt",0o444)'], foreground=True)
        ttl_config = secrets / 'expiry-config.yaml'
        ttl_config.write_text(config.read_text() + '\npassword_reset_token_lifetime: 5000\n')
        # Reuse the proven Core launch profile. A read-only-root hardening profile
        # needs its own complete writable-path audit and is not this reset test.
        if not args.browser_only:
            launch('expiry-core', images['core'], [*[value for value in common if value != '--read-only'], '--memory=1g', '--cpus=2', '--pids-limit=256',
            '--tmpfs', '/tmp:rw,exec,nosuid,size=64m,uid=1000,gid=1000',
            '--tmpfs', '/opt/expertauth/webserver-temp:rw,nosuid,noexec,size=32m,uid=1000,gid=1000',
            '--tmpfs', '/opt/expertauth/logs:rw,nosuid,noexec,size=16m,uid=1000,gid=1000',
            '--tmpfs', '/opt/expertauth/.started:rw,nosuid,noexec,size=1m,uid=1000,gid=1000',
            '--tmpfs', '/home/gradle/.gradle:rw,nosuid,noexec,size=16m', '-v', f'{ttl_config}:/run/expertauth/config.yaml:ro'])
        settings = json.loads((secrets / 'settings.json').read_text())
        apps = {}
        for role in (['good'] if args.browser_only else ['good', 'expiry', 'wrong-auth', 'untrusted', 'outage', 'disabled']):
            host = 'reset-' + role + '-' + suffix + '.example.test'
            apps[role] = 'http://' + host + ':3000'
            env = secrets / (role + '.env')
            lines = ['EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'], 'EXPERTAUTH_PUBLIC_ORIGIN=' + apps[role],
                     'EXPERTAUTH_LOCAL_PROBE=true', 'EXPERTAUTH_CORE_URL=http://' + (containers['expiry-core']['name'] if role == 'expiry' else 'core-a') + ':3567']
            if role != 'disabled':
                lines += ['EXPERTAUTH_SMTP_HOST=' + mailhost, 'EXPERTAUTH_SMTP_PORT=' + ('1026' if role == 'outage' else '1025'),
                          'EXPERTAUTH_SMTP_USERNAME=' + settings['smtp_username'], 'EXPERTAUTH_SMTP_FROM_EMAIL=recovery@example.test',
                          'EXPERTAUTH_SMTP_PASSWORD_FILE=/run/mailpit/smtp-password']
                if role != 'untrusted':
                    lines += ['NODE_EXTRA_CA_CERTS=/run/mailpit/ca.crt']
            env.write_text('\n'.join(lines) + '\n')
            launch(role, images['node'], [*common, '--memory=256m', '--cpus=1', '--pids-limit=128',
                '--network-alias', host, '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m', '--env-file', str(env),
                '-v', f'{secrets / "ca.crt"}:/run/mailpit/ca.crt:ro',
                '-v', f'{secrets / ("wrong-password" if role == "wrong-auth" else "smtp-password")}:/run/mailpit/smtp-password:ro',
                '-v', f'{ROOT / "examples/node-react/server.js"}:/app/server.js:ro',
                '-v', f'{ROOT / "examples/node-react/email-delivery.js"}:/app/email-delivery.js:ro'])
            installed = command('exec', containers[role]['id'], 'sha256sum', '/app/server.js', '/app/email-delivery.js', '/app/package-lock.json').stdout.splitlines()
            expected = [inputs['examples/node-react/' + name] for name in ['server.js', 'email-delivery.js', 'package-lock.json']]
            require([line.split()[0] for line in installed] == expected, 'Installed app source/dependencies differ')
            report.setdefault('installed_input_hashes', {})[role] = installed
            ready = False
            for _ in range(45):
                require(own(role) is not None, 'Application exited before readiness: ' + role)
                result = command('exec', containers[role]['id'], 'node', '-e',
                    'fetch("http://127.0.0.1:3000/health/ready").then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))', check=False, timeout=6)
                if result.returncode == 0:
                    ready = True
                    break
                time.sleep(0.3)
            require(ready, 'Application readiness failed: ' + role)
        worker_env = secrets / 'worker.env'
        worker_env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\nRESET_APPS=' + json.dumps(apps) + '\nRESET_BROWSER_ONLY=' + str(args.browser_only).lower() + '\n')
        launch('worker', images['browser'], [*common, '--memory=2g', '--cpus=2', '--pids-limit=256', '--shm-size=256m',
            '--tmpfs', '/tmp:rw,nosuid,size=256m', '--env-file', str(worker_env), '-e', 'NODE_EXTRA_CA_CERTS=/private/ca.crt',
            '-e', 'PRIVATE_DIR=/private', '-e', 'EVIDENCE_DIR=/out', '-v', f'{ROOT}:/repo:ro',
            '-v', f'{secrets}:/private', '-v', f'{output}:/out', '--entrypoint', 'node'],
            ['/repo/tests/operations/password_reset_probe.mjs'], foreground=True, timeout=220)
        require(json.loads((output / 'probe-results.json').read_text())['passed'], 'Product probe did not pass')
        report['passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        for role in reversed(list(containers)):
            try:
                retire(role)
            except Exception as error:
                report['errors'].append('Cleanup ' + role + ': ' + type(error).__name__)
        try:
            probe = json.loads((output / 'probe-results.json').read_text()) if (output / 'probe-results.json').exists() else {}
            cleaned = any(row['id'] == 'RESET-OWNED-FIXTURE-CLEANUP' and row['status'] == 'passed' for row in probe.get('rows', []))
            if (secrets / 'fixtures.json').exists() and not cleaned:
                require('worker' not in containers or own('worker') is None, 'Do not clean while worker can mutate identities')
                launch('cleanup-fallback', images['python'], [*common, '--user=0', '--memory=256m', '--cpus=1', '--pids-limit=64',
                    '--env-file', str(secrets / 'worker.env'), '-v', f'{secrets / "fixtures.json"}:/private/fixtures.json:ro',
                    '-v', f'{ROOT / "tests/operations/password_reset_cleanup.py"}:/script.py:ro', '-v', f'{output}:/out', '--entrypoint', 'python'],
                    ['-B', '/script.py', '--fixtures', '/private/fixtures.json', '--output', '/out/cleanup-followup.json'], foreground=True, timeout=100)
                retire('cleanup-fallback')
                report['identity_cleanup_fallback'] = json.loads((output / 'cleanup-followup.json').read_text())['ok']
        except Exception as error:
            report['errors'].append('Identity cleanup fallback: ' + type(error).__name__)
        for role, (process, handles, paths, entry) in service_processes.items():
            try:
                process.wait(timeout=10)
                for handle in handles:
                    handle.close()
                entry['exit_code'] = process.returncode
                for name, path in zip(('stdout', 'stderr'), paths):
                    entry[name] = {'bytes': path.stat().st_size, 'sha256': sha(path)}
            except Exception as error:
                report['errors'].append('Attached service finalization ' + role + ': ' + type(error).__name__)
        for key, observation in {
            'source_processes_and_mounts_unchanged': lambda: all(projection(inspect('container', name)) == old for name, old in source.items()),
            'source_configuration_unchanged': lambda: private_hashes == {'config': sha(config), 'runtime_env': sha(runtime_env)},
            'resources_restored': lambda: resources_before == inventory(),
            'inputs_unchanged': lambda: inputs == {path: sha(ROOT / path) for path in INPUTS},
        }.items():
            try:
                report[key] = observation()
            except Exception as error:
                report[key] = False
                report['errors'].append('Final observation ' + key + ': ' + type(error).__name__)
        report['passed'] = report['passed'] and not report['errors'] and all(report[k] for k in
            ['source_processes_and_mounts_unchanged', 'source_configuration_unchanged', 'resources_restored', 'inputs_unchanged'])
        report['finished'] = datetime.now(timezone.utc).isoformat()
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'errors': report['errors'], 'containers_created': len(containers),
                          'containers_retired': len(report['retired_containers']), 'resources_restored': report['resources_restored']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
