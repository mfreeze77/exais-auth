"""Bounded real SDK/session lab. Reuses images, retires all temporary containers.

No image builds/downloads, Docker socket mounts, new networks/volumes, public
ports, engine patches, production mutations or persistent test credentials.
Only the newly created Core B is deliberately killed and restarted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
NETWORK = 'expertauth-oss-proof'
BROWSER = 'mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e'
INPUTS = ['tools/run_sdk_session_faults.py', 'tests/foundation/sdk_session_faults.mjs',
          'contracts/session-policy-oss-node-cdi54-v1.json',
          'tests/browser/session-coordination.mjs', 'tests/browser/package-lock.json',
          'examples/node-react/server.js', 'examples/node-react/client.jsx', 'examples/node-react/package-lock.json',
          '.cache/engine-build/supertokens-core/src/main/java/io/supertokens/session/Session.java',
          '.cache/engine-build/supertokens-core/src/main/java/io/supertokens/webserver/api/session/RefreshSessionAPI.java']


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def command(*args, check=True, timeout=35):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, encoding='utf-8', timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Docker operation failed: ' + ' '.join(args[:2]))
    return result


def inspect(kind, name):
    return json.loads(command(kind, 'inspect', name).stdout)[0]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    return {kind: sorted(set(command(*args).stdout.splitlines())) for kind, args in {
        'containers': ('ps', '-aq', '--no-trunc'), 'images': ('image', 'ls', '-q', '--no-trunc'),
        'volumes': ('volume', 'ls', '-q'), 'networks': ('network', 'ls', '-q', '--no-trunc')}.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    require(args.name.isascii() and all(c.isalnum() or c in '-_' for c in args.name), 'Invalid evidence name')
    output = ROOT / 'evidence/foundation/sdk-session-faults' / args.name
    require(not output.exists(), 'Evidence run exists; choose a new name')
    original = inspect('container', 'expertauth-oss-core-a')
    pg = inspect('container', 'expertauth-oss-postgres')
    require(original['State']['Running'] and pg['State']['Running'], 'Preserved Core/database must already be running')
    require(original['Config'].get('Labels', {}).get('org.expertauth.project') == 'expert-auth', 'Unowned Core')
    require(not original['HostConfig']['PortBindings'] and not pg['HostConfig']['PortBindings'], 'Unexpected public lab ports')
    require(inspect('network', NETWORK)['Internal'], 'Expected existing internal network')
    config = (ROOT / '.runtime/oss-core/config.yaml').resolve()
    mounts = [row for row in original['Mounts'] if row['Destination'] == '/run/expertauth/config.yaml']
    require(len(mounts) == 1 and not mounts[0]['RW'], 'Expected read-only preserved Core config')
    core_image = original['Image']
    node_image = inspect('image', 'expertauth-node-react:0.0.5')['Id']
    browser_image = inspect('image', BROWSER)['Id']  # Require already cached; never pull.
    suffix = uuid.uuid4().hex[:8]
    core_name = 'expertauth-session-core-' + suffix
    sdk_name = 'expertauth-session-sdk-' + suffix
    browser_name = 'expertauth-session-browser-' + suffix
    for alias in ['session-core-b', 'session-sdk.example.test']:
        for container in inspect('network', NETWORK).get('Containers', {}).values():
            state = inspect('container', container['Name'])
            require(alias not in state['NetworkSettings']['Networks'][NETWORK].get('Aliases', []), 'Temporary network alias occupied')
    inputs = {name: sha(ROOT / name) for name in INPUTS}
    before = inventory()
    output.mkdir(parents=True)
    report = {'schema': 'expertauth-sdk-session-lab-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'foundation_passed': False, 'input_sha256': inputs, 'network': NETWORK,
              'images': {'core': core_image, 'node': node_image, 'browser': browser_image},
              'config_sha256': sha(config), 'created_containers': [], 'controls': [], 'errors': [],
              'published_ports': [], 'image_builds': 0, 'image_downloads': 0}
    labels = ['--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=session-fault-proof']
    worker = None
    try:
        core_id = command('run', '-d', '--pull=never', '--name', core_name, '--network', NETWORK, '--network-alias', 'session-core-b',
                          *labels, '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=16m',
                          '-v', f'{config}:/run/expertauth/config.yaml:ro', core_image).stdout.strip()
        report['created_containers'].append({'name': core_name, 'id': core_id})
        # Credentials copied only to an automatically removed, ignored private directory.
        runtime = ROOT / '.runtime/session-faults'
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='env-', dir=runtime) as temporary:
            values = dict(line.split('=', 1) for line in (ROOT / '.runtime/oss-core/runtime.env').read_text().splitlines() if '=' in line)
            env = Path(temporary) / 'probe.env'
            env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
            sdk_cid = Path(temporary) / 'sdk.cid'
            browser_cid = Path(temporary) / 'browser.cid'
            common = ['--pull=never', '--network', NETWORK, *labels, '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=128m',
                      '--env-file', str(env), '-e', 'EVIDENCE_DIR=/evidence', '-v', f'{ROOT}:/repo:ro', '-v', f'{output}:/evidence']
            worker = subprocess.Popen(['docker', 'run', '--rm', '-i', '--name', sdk_name, '--cidfile', str(sdk_cid), '--network-alias', 'session-sdk.example.test',
                                       *common, '--entrypoint', 'node', node_image, '/repo/tests/foundation/sdk_session_faults.mjs'],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', bufsize=1)
            lines = queue.Queue()
            def read_lines():
                for line in worker.stdout:
                    lines.put(line)
                lines.put(None)
            threading.Thread(target=read_lines, daemon=True).start()
            transcript = []
            deadline = time.monotonic() + 420
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
                require(action not in [row['action'] for row in report['controls']], 'Duplicate control request')
                if action == 'kill_and_restart_owned_b':
                    state = inspect('container', core_name)
                    require(state['Id'] == core_id and state['Image'] == core_image and state['State']['Running'], 'Disposable Core identity/state differs')
                    command('kill', '--signal', 'KILL', core_name)
                    killed = inspect('container', core_name)
                    require(not killed['State']['Running'] and killed['State']['ExitCode'] == 137, 'SIGKILL not observed')
                    command('start', core_name)
                    report['controls'].append({'action': action, 'id': core_id, 'killed_exit_code': 137, 'restart_requested': True})
                elif action == 'browser_coordination':
                    require(not inspect('container', sdk_name)['HostConfig']['PortBindings'], 'Application unexpectedly published')
                    result = command('run', '--rm', '--name', browser_name, '--cidfile', str(browser_cid), *common, '--ipc=private', '--shm-size=256m',
                                     '--entrypoint', 'node', browser_image, '/repo/tests/browser/session-coordination.mjs', check=False, timeout=160)
                    if browser_cid.exists():
                        report['created_containers'].append({'name': browser_name, 'id': browser_cid.read_text().strip()})
                    text = (result.stdout + result.stderr).replace(values['EXPERTAUTH_CORE_API_KEY'], '[REDACTED]')
                    (output / 'browser-output.log').write_bytes(text.encode())
                    print(text, flush=True)
                    report['controls'].append({'action': action, 'exit_code': result.returncode})
                else:
                    raise ValueError('Unknown worker control request')
                worker.stdin.write('{"ok":true}\n'); worker.stdin.flush()
            else:
                raise TimeoutError('SDK lab exceeded bounded runtime')
            report['worker_exit_code'] = worker.wait(timeout=15)
            if sdk_cid.exists():
                report['created_containers'].append({'name': sdk_name, 'id': sdk_cid.read_text().strip()})
            (output / 'worker-output.log').write_bytes(''.join(transcript).encode())
            sdk = json.loads((output / 'sdk-results.json').read_text())
            for path in ('server.js', 'client.jsx', 'package-lock.json'):
                require(sdk['inputs'][path] == sha(ROOT / 'examples/node-react' / path), 'Image application input differs from repository')
            report['checks'] = {'passed': sdk['passed'], 'failed': sdk['failed'], 'fatal': sdk['fatal']}
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        for name in (browser_name, sdk_name, core_name):
            state = command('container', 'inspect', name, check=False)
            if state.returncode:
                continue
            state = json.loads(state.stdout)[0]
            if state['Config'].get('Labels', {}).get('org.expertauth.purpose') != 'session-fault-proof':
                report['errors'].append('Refused cleanup of changed ownership: ' + name)
                continue
            if not any(row['id'] == state['Id'] for row in report['created_containers']):
                report['created_containers'].append({'name': name, 'id': state['Id']})
            if state['State']['Running']:
                command('stop', '-t', '5', name, check=False)
            command('rm', name, check=False)  # --rm workers may already have disappeared.
        if worker and worker.poll() is None:
            worker.terminate(); worker.wait(timeout=15)
        after = inventory()
        report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                        'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
        report['owned_containers_retired'] = all(row['id'] not in after['containers'] for row in report['created_containers'])
        current = inspect('container', 'expertauth-oss-core-a')
        current_pg = inspect('container', 'expertauth-oss-postgres')
        report['preserved_services_unchanged'] = all(old['Id'] == new['Id'] and old['Image'] == new['Image'] and
                                                   old['State']['StartedAt'] == new['State']['StartedAt'] and new['State']['Running']
                                                   for old, new in [(original, current), (pg, current_pg)])
        report['inputs_unchanged'] = inputs == {name: sha(ROOT / name) for name in INPUTS}
        report['config_unchanged'] = report['config_sha256'] == sha(config)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        report['artifacts'] = [{'path': path.name, 'sha256': sha(path)} for path in sorted(output.iterdir()) if path.is_file()]
        with (output / 'report.json').open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps({'evidence': output.relative_to(ROOT).as_posix(), 'checks': report.get('checks'),
                      'errors': report['errors'], 'owned_containers_retired': report['owned_containers_retired'], 'foundation_passed': False}))
    return int(bool(report['errors']) or not report['owned_containers_retired'] or not report['inputs_unchanged'] or
               not report['preserved_services_unchanged'] or not report['config_unchanged'] or report.get('worker_exit_code') != 0 or
               any(row.get('exit_code', 0) != 0 for row in report['controls']))


if __name__ == '__main__':
    raise SystemExit(main())
