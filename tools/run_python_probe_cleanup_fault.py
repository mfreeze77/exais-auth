"""Run one real Python probe transport fault using the cached image and Core.

No builds, downloads, database restarts, public ports or new volumes/networks.
Temporary containers are removed by exact CID plus project and purpose labels.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
import uuid

from run_sdk_session_faults import ROOT, NETWORK, command, inspect, inventory, sha, require

IMAGE = 'sha256:7a4bb6dcfd634a98f603d65bc2c1219fef5b3a46a00be705631201c4f78802f1'
PURPOSE = 'python-probe-cleanup-fault'
INPUTS = ['tools/run_python_probe_cleanup_fault.py', 'tools/run_sdk_session_faults.py',
          'tests/operations/python_probe_cleanup_fault.py', 'tests/clients/python_probe.py',
          'examples/python/app.py', 'examples/python/requirements.lock', 'examples/python/Dockerfile']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    require(args.name and args.name.isascii() and all(char.isalnum() or char in '-_' for char in args.name), 'Invalid run name')
    output = ROOT / 'evidence/operations/python-probe-cleanup-fault' / args.name
    require(not output.exists(), 'Preserve previous fault evidence')
    network = inspect('network', NETWORK)
    require(network['Internal'], 'Existing network must be private')
    original = {name: inspect('container', name) for name in ['expertauth-oss-core-a', 'expertauth-oss-postgres']}
    for value in original.values():
        require(value['State']['Running'] and not value['HostConfig']['PortBindings'], 'Core/database must already run privately')
    require(inspect('image', IMAGE)['Id'] == IMAGE, 'Exact cached image unavailable')
    suffix = uuid.uuid4().hex[:10]
    names = {role: 'expertauth-python-cleanup-fault-' + role + '-' + suffix for role in ('app', 'probe')}
    alias = 'python-cleanup-fault-' + suffix + '.example.test'
    for name in names.values():
        require(command('container', 'inspect', name, check=False).returncode != 0, 'Generated name exists')
    before = inventory()
    inputs = {path: sha(ROOT / path) for path in INPUTS}
    output.mkdir(parents=True)
    (output / 'probe').mkdir()
    runtime = (ROOT / '.runtime/python-probe-cleanup-fault').resolve()
    runtime.mkdir(exist_ok=True)
    private = tempfile.TemporaryDirectory(prefix='run-', dir=runtime)
    ids = {}
    cid_paths = {role: Path(private.name) / (role + '.cid') for role in names}
    report = {'schema': 'expertauth-python-probe-cleanup-fault-host-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'foundation_passed': False, 'command_argv': sys.argv, 'image': IMAGE, 'inputs': inputs, 'errors': [], 'new_images': 0,
              'new_networks': 0, 'new_volumes': 0, 'published_ports': [], 'created_containers': []}
    try:
        values = dict(line.split('=', 1) for line in (ROOT / '.runtime/oss-core/runtime.env').read_text().splitlines() if '=' in line)
        env = Path(private.name) / 'probe.env'
        env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
        common = ['--pull=never', '--rm', '--network', NETWORK, '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=64m',
                  '--memory', '256m', '--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=' + PURPOSE,
                  '--env-file', str(env)]
        origin = 'http://' + alias + ':8300'
        started = command('run', '-d', '--name', names['app'], '--cidfile', str(cid_paths['app']), *common,
                          '-e', 'PYTHON_API_DOMAIN=' + origin, '-e', 'WEBSITE_DOMAIN=' + origin, IMAGE)
        ids['app'] = started.stdout.strip()
        actual = command('exec', ids['app'], 'sha256sum', '/app/app.py', '/app/requirements.lock').stdout.splitlines()
        report['installed_sha256'] = {line.split()[1]: line.split()[0] for line in actual}
        require(report['installed_sha256']['/app/app.py'] == inputs['examples/python/app.py'] and
                report['installed_sha256']['/app/requirements.lock'] == inputs['examples/python/requirements.lock'], 'Cached image source differs')
        for attempt in range(30):
            ready = command('exec', ids['app'], 'python', '-c',
                            'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8300/ready",timeout=5).status == 200', check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError('Application did not become ready')
        probe = command('run', '--name', names['probe'], '--cidfile', str(cid_paths['probe']), '--network-alias', alias, *common,
                        '-e', 'FAULT_ORIGIN=' + origin, '-e', 'FAULT_UPSTREAM=http://' + names['app'] + ':8300',
                        '-e', 'EVIDENCE_DIR=/evidence', '-v', f'{ROOT}:/repo:ro', '-v', f'{output / "probe"}:/evidence',
                        '--entrypoint', 'python', IMAGE, '/repo/tests/operations/python_probe_cleanup_fault.py', check=False, timeout=105)
        report['probe_exit_code'] = probe.returncode
        (output / 'command-output.log').write_text((probe.stdout + probe.stderr).replace(values['EXPERTAUTH_CORE_API_KEY'], '[REDACTED]'))
        result = json.loads((output / 'probe/fault-report.json').read_text())
        require(probe.returncode == 0 and result['passed'] == 4 and result['failed'] == 0 and result['fallback_users_removed'] == 0,
                'Actual transport-fault cleanup regression did not pass')
        report['checks'] = {'passed': 4, 'failed': 0, 'skipped': 0}
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        for role, path in cid_paths.items():
            if path.exists():
                cid = path.read_text().strip()
                if len(cid) == 64 and all(char in '0123456789abcdef' for char in cid):
                    ids[role] = cid
        report['created_containers'] = [{'name': names[role], 'id': cid} for role, cid in ids.items()]
        for role in ('probe', 'app'):
            try:
                if role not in ids:
                    continue
                current = command('container', 'inspect', ids[role], check=False)
                if current.returncode:
                    continue
                state = json.loads(current.stdout)[0]
                labels = state['Config'].get('Labels', {})
                require(state['Id'] == ids[role] and labels.get('org.expertauth.project') == 'expert-auth' and
                        labels.get('org.expertauth.purpose') == PURPOSE, 'Container cleanup ownership differs')
                if state['State']['Running']:
                    command('stop', '-t', '5', ids[role], check=False)
                command('rm', ids[role], check=False)
            except Exception as error:
                report['errors'].append('Container retirement: ' + type(error).__name__)
        try:
            after = inventory()
            report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                             'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
            report['temporary_containers_retired'] = all(cid not in after['containers'] for cid in ids.values())
            report['preserved_services'] = {}
            for name, old in original.items():
                new = inspect('container', name)
                unchanged = all(new[key] == old[key] for key in ['Id', 'Image', 'Mounts']) and new['State']['Running'] and new['State']['StartedAt'] == old['State']['StartedAt']
                report['preserved_services'][name] = {'id': old['Id'], 'unchanged': unchanged}
                require(unchanged, 'Preserved Core/database changed')
            report['inputs_unchanged'] = inputs == {path: sha(ROOT / path) for path in INPUTS}
            require(report['temporary_containers_retired'] and report['inputs_unchanged'], 'Cleanup or input stability failed')
            require(all(not values for row in report['resource_delta'].values() for values in row.values()), 'Unexpected Docker resource delta')
        except Exception as error:
            report['errors'].append('Final verification: ' + type(error).__name__)
        require(Path(private.name).resolve().parent == runtime, 'Private scratch path escaped ownership')
        private.cleanup()
        report['artifacts'] = [{'path': path.relative_to(output).as_posix(), 'sha256': sha(path)} for path in sorted(output.rglob('*')) if path.is_file()]
        report['finished'] = datetime.now(timezone.utc).isoformat()
        with (output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
    passed = not report['errors'] and report.get('probe_exit_code') == 0
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'passed': passed, 'errors': report['errors'],
                      'temporary_containers_retired': report.get('temporary_containers_retired')}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
