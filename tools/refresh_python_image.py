"""Qualify an existing Python application image with real HTTP behavior.

No network downloads, database interruption, public ports, volume/network creation,
production replacement or global image pruning. All temporary containers retire.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from run_sdk_session_faults import ROOT, NETWORK, command, inspect, inventory, sha, require

TAG = 'expertauth-python-app:0.1.0'
INPUTS = ['tools/refresh_python_image.py', 'tools/run_sdk_session_faults.py', 'examples/python/app.py',
          'examples/python/Dockerfile', 'examples/python/.dockerignore', 'examples/python/requirements.lock',
          'tests/clients/python_probe.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--test-existing', action='store_true', help='Test the current image without building when only the harness changed')
    parser.add_argument('--test-image', help='Test an owned candidate by immutable image ID without changing any tag or retiring any image')
    args = parser.parse_args()
    require(not (args.test_existing and args.test_image), 'Choose one existing-image test mode')
    if args.test_image:
        require(args.test_image.startswith('sha256:') and len(args.test_image) == 71 and
                all(c in '0123456789abcdef' for c in args.test_image[7:]), 'Immutable candidate image ID required')
    require(args.name.isascii() and args.name and all(c.isalnum() or c in '-_' for c in args.name), 'Invalid run name')
    output = ROOT / 'evidence/operations/python-readiness' / args.name
    require(not output.exists(), 'Preserve previous image evidence')
    old = inspect('image', TAG)
    require(inspect('network', NETWORK)['Internal'], 'Expected private network')
    inputs = {path: sha(ROOT / path) for path in INPUTS}
    before = inventory()
    output.mkdir(parents=True)
    (output / 'regression').mkdir()
    report = {'schema': 'expertauth-python-image-refresh-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'foundation_passed': False, 'inputs': inputs, 'old_image': old['Id'], 'errors': [], 'created_containers': [],
              'new_networks': 0, 'new_volumes': 0, 'published_ports': [], 'build_network': 'none', 'build_pull': False}
    names = {role: 'expertauth-python-image-' + role + '-' + uuid.uuid4().hex[:8] for role in ('app', 'probe')}
    ids = {}
    labels = ['--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=python-image-proof']
    runtime = (ROOT / '.runtime/python-image-refresh').resolve()
    runtime.mkdir(exist_ok=True)
    private = Path(tempfile.mkdtemp(prefix='run-', dir=runtime)).resolve()
    require(private.parent == runtime, 'Private scratch boundary differs')
    cid_paths = {role: private / (role + '.cid') for role in names}
    qualified = False
    regression_passed = False
    image = None
    try:
        report['build_skipped'] = args.test_existing or bool(args.test_image)
        report['candidate_test_only'] = bool(args.test_image)
        if not report['build_skipped']:
            require(False, 'Legacy build path is retired; use tools/build_python_runtime.py for the offline BuildKit build')
        new = inspect('image', args.test_image or TAG)
        image = new['Id']
        require(new['Config'].get('Labels', {}).get('org.expertauth.project') == 'expert-auth', 'Unowned Python image')
        report['new_image'] = image
        # Rebuilt candidates are separately checked against all locked wheel bytes
        # before this behavior-only runner is invoked. It never promotes them.
        report['dependency_layers_unchanged'] = new['RootFS']['Layers'][:-1] == old['RootFS']['Layers'][:-1]
        require(args.test_image or report['dependency_layers_unchanged'], 'Dependency/base filesystem layers changed')
        report['rootfs_layers'] = new['RootFS']['Layers']
        values = dict(line.split('=', 1) for line in (ROOT / '.runtime/oss-core/runtime.env').read_text().splitlines() if '=' in line)
        env = private / 'probe.env'
        env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
        common = ['--pull=never', '--network', NETWORK, *labels, '--read-only', '--memory=512m', '--cpus=2',
                  '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--tmpfs', '/tmp:rw,nosuid,size=64m', '--env-file', str(env)]
        hostname = names['app'] + '.example.test'
        origin = 'http://' + hostname + ':8300'
        report['test_origin'] = origin
        ids['app'] = command('run', '-d', '--rm', '--name', names['app'], '--cidfile', str(cid_paths['app']),
                             '--network-alias', hostname, *common, '-e', 'PYTHON_API_DOMAIN=' + origin,
                             '-e', 'WEBSITE_DOMAIN=' + origin, image).stdout.strip()
        actual = command('exec', names['app'], 'sha256sum', '/app/app.py', '/app/requirements.lock').stdout.splitlines()
        report['installed_sha256'] = {line.split()[1]: line.split()[0] for line in actual}
        require(report['installed_sha256']['/app/app.py'] == inputs['examples/python/app.py'] and
                report['installed_sha256']['/app/requirements.lock'] == inputs['examples/python/requirements.lock'], 'Installed app/lock differs')
        # Readiness is retried only while this exact newly started process boots.
        for attempt in range(40):
            ready = command('exec', names['app'], 'python', '-c',
                            'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8300/ready",timeout=5); assert r.status==200', check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError('Built application did not become ready')
        run = command('run', '--rm', '--name', names['probe'], '--cidfile', str(cid_paths['probe']), *common,
                      '-v', f'{ROOT}:/repo:ro', '-v', f'{output / "regression"}:/evidence', '--entrypoint', 'python', image,
                      '/repo/tests/clients/python_probe.py', '--url', origin, '--origin', origin,
                      '--evidence-dir', '/evidence', '--cleanup-created-users', check=False, timeout=100)
        (output / 'regression-output.log').write_bytes((run.stdout + run.stderr).replace(values['EXPERTAUTH_CORE_API_KEY'], '[REDACTED]').encode())
        result = json.loads((output / 'regression/probe-report.json').read_text())
        require(run.returncode == 0 and result['executed'] == result['passed'] == 19 and result['skipped'] == 0 and
                result['synthetic_cleanup']['created'] == result['synthetic_cleanup']['removed'] == 2, 'Full representative regression/cleanup did not pass')
        report['regression'] = {'passed': 19, 'failed': 0, 'skipped': 0, 'synthetic_users_removed': 2}
        regression_passed = True
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        for role, path in cid_paths.items():
            try:
                if path.exists():
                    cid = path.read_text().strip()
                    require(len(cid) == 64 and all(char in '0123456789abcdef' for char in cid), 'Malformed private CID')
                    ids[role] = cid
            except Exception as error:
                report['errors'].append('CID recovery failed: ' + type(error).__name__)
        report['created_containers'] = [{'name': names[role], 'id': cid} for role, cid in ids.items()]
        for role in ('probe', 'app'):
            try:
                state = command('container', 'inspect', names[role], check=False)
                if state.returncode:
                    continue
                state = json.loads(state.stdout)[0]
                labels_now = state['Config'].get('Labels', {})
                require(state['Id'] == ids.get(role) and state['Name'] == '/' + names[role] and state['Image'] == image and
                        labels_now.get('org.expertauth.project') == 'expert-auth' and
                        labels_now.get('org.expertauth.purpose') == 'python-image-proof', 'Container cleanup ownership differs')
                if state['State']['Running']:
                    command('stop', '-t', '5', names[role], check=False)
                command('rm', names[role], check=False)
            except Exception as error:
                report['errors'].append('Container retirement failed: ' + type(error).__name__)
        report['temporary_containers_retired'] = False
        report['inputs_unchanged'] = False
        report['private_scratch_removed'] = False
        report['image_promoted'] = False  # This runner never changes image tags.
        try:
            after = inventory()
            report['temporary_containers_retired'] = all(cid not in after['containers'] for cid in ids.values())
            # Also check generated names when a launch failed before its CID was recovered.
            for name in names.values():
                remaining = command('ps', '-aq', '--filter', 'name=^/' + name + '$')
                require(not remaining.stdout.strip(), 'Temporary container still present')
            report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                             'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
            report['inputs_unchanged'] = inputs == {path: sha(ROOT / path) for path in INPUTS}
            require(report['inputs_unchanged'], 'Qualification inputs changed')
            require(report['temporary_containers_retired'], 'Temporary containers remain')
            require(inspect('image', TAG)['Id'] == old['Id'], 'Current image tag changed during qualification')
            require(private.parent == runtime, 'Private scratch cleanup escaped exact directory')
            for path in [private / 'probe.env', *cid_paths.values()]:
                path.unlink(missing_ok=True)
            require(not any(private.iterdir()), 'Unknown private scratch file; preserve directory')
            private.rmdir()
            report['private_scratch_removed'] = True
            qualified = regression_passed and not report['errors']
        except Exception as error:
            report['errors'].append('Final qualification/cleanup failed: ' + type(error).__name__ + ': ' + str(error))
            report['private_recovery_directory'] = private.relative_to(ROOT).as_posix()
        try:
            report['artifacts'] = [{'path': path.relative_to(output).as_posix(), 'sha256': sha(path)}
                                   for path in sorted(output.rglob('*')) if path.is_file()]
        except OSError as error:
            report['errors'].append('Artifact hashing failed: ' + type(error).__name__)
        report['finished'] = datetime.now(timezone.utc).isoformat()
        with (output / 'report.json').open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())
    passed = qualified and not report['errors'] and report['temporary_containers_retired'] and report['inputs_unchanged']
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'image': image, 'passed': passed,
                      'regression': report.get('regression'), 'retired_image': report.get('retired_image'), 'errors': report['errors']}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
