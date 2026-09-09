"""Build changed Python app with cached dependency layers; test and retire old image.

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
    args = parser.parse_args()
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
    private = tempfile.TemporaryDirectory(prefix='run-', dir=runtime)
    cid_paths = {role: Path(private.name) / (role + '.cid') for role in names}
    promoted = False
    regression_passed = False
    image = None
    try:
        # Reuse the retained image's cache even when legacy intermediate image
        # metadata was retired. Force removal of intermediates on failed builds.
        report['cache_from'] = old['Id']
        built = command('build', '--pull=false', '--network=none', '--force-rm', '--cache-from', old['Id'],
                        '--label', 'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=python-foundation',
                        '-t', TAG, str(ROOT / 'examples/python'), timeout=180, check=False)
        (output / 'build-output.log').write_bytes((built.stdout + built.stderr).encode())
        report['build_exit_code'] = built.returncode
        require(built.returncode == 0, 'Docker build failed; exact output preserved in build-output.log')
        new = inspect('image', TAG)
        image = new['Id']
        report['new_image'] = image
        # Only final COPY app.py layer changes; SDK/interpreter/dependency layers stay exact.
        require(new['RootFS']['Layers'][:-1] == old['RootFS']['Layers'][:-1], 'Dependency/base filesystem layers changed')
        report['dependency_layers_unchanged'] = True
        report['rootfs_layers'] = new['RootFS']['Layers']
        values = dict(line.split('=', 1) for line in (ROOT / '.runtime/oss-core/runtime.env').read_text().splitlines() if '=' in line)
        env = Path(private.name) / 'probe.env'
        env.write_text('EXPERTAUTH_CORE_API_KEY=' + values['EXPERTAUTH_CORE_API_KEY'] + '\n')
        common = ['--pull=never', '--network', NETWORK, *labels, '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=64m', '--env-file', str(env)]
        origin = 'http://python-image.example.test:8300'
        ids['app'] = command('run', '-d', '--rm', '--name', names['app'], '--cidfile', str(cid_paths['app']),
                             '--network-alias', 'python-image.example.test', *common, '-e', 'PYTHON_API_DOMAIN=' + origin,
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
            if path.exists():
                cid = path.read_text().strip()
                if len(cid) == 64 and all(char in '0123456789abcdef' for char in cid):
                    ids[role] = cid
        report['created_containers'] = [{'name': names[role], 'id': cid} for role, cid in ids.items()]
        for role in ('probe', 'app'):
            try:
                state = command('container', 'inspect', names[role], check=False)
                if state.returncode:
                    continue
                state = json.loads(state.stdout)[0]
                labels_now = state['Config'].get('Labels', {})
                require(state['Id'] == ids.get(role) and labels_now.get('org.expertauth.project') == 'expert-auth' and
                        labels_now.get('org.expertauth.purpose') == 'python-image-proof', 'Container cleanup ownership differs')
                if state['State']['Running']:
                    command('stop', '-t', '5', names[role], check=False)
                command('rm', names[role], check=False)
            except Exception as error:
                report['errors'].append('Container retirement failed: ' + type(error).__name__)
        # Source stability and resource retirement precede promotion and removal
        # of the prior image. A failed qualification must keep its rollback image.
        retired_inventory = inventory()
        report['temporary_containers_retired'] = all(cid not in retired_inventory['containers'] for cid in ids.values())
        try:
            report['inputs_unchanged'] = inputs == {path: sha(ROOT / path) for path in INPUTS}
        except OSError as error:
            report['inputs_unchanged'] = False
            report['errors'].append('Qualification input unreadable: ' + type(error).__name__)
        if not report['inputs_unchanged']:
            report['errors'].append('Qualification inputs changed; preserving the prior image')
        if not report['temporary_containers_retired']:
            report['errors'].append('Temporary containers remain; preserving the prior image')
        promoted = regression_passed and not report['errors'] and report['inputs_unchanged'] and report['temporary_containers_retired']
        report['promotion_checks_completed_before_image_retirement'] = True
        if not promoted and image:
            command('image', 'tag', old['Id'], TAG)
        obsolete = old['Id'] if promoted else image
        if obsolete and obsolete != (image if promoted else old['Id']):
            try:
                used = command('ps', '-aq', '--filter', 'ancestor=' + obsolete).stdout.strip()
                tags = inspect('image', obsolete).get('RepoTags') or []
                require(not used and not tags, 'Obsolete image is still referenced; preserve it')
                command('image', 'rm', obsolete)
                report['retired_image'] = obsolete
            except Exception as error:
                report['errors'].append('Image retirement incomplete: ' + type(error).__name__)
        require(Path(private.name).resolve().parent == runtime, 'Private scratch cleanup escaped exact directory')
        private.cleanup()
        after = inventory()
        report['resource_delta'] = {kind: {'added': sorted(set(after[kind]) - set(before[kind])),
                                         'removed': sorted(set(before[kind]) - set(after[kind]))} for kind in before}
        report['temporary_containers_retired'] = all(cid not in after['containers'] for cid in ids.values())
        report['artifacts'] = [{'path': path.relative_to(output).as_posix(), 'sha256': sha(path)}
                               for path in sorted(output.rglob('*')) if path.is_file()]
        report['finished'] = datetime.now(timezone.utc).isoformat()
        report['image_promoted'] = promoted
        with (output / 'report.json').open('xb') as stream:
            stream.write((json.dumps(report, indent=2) + '\n').encode())
    passed = promoted and not report['errors'] and report['temporary_containers_retired'] and report['inputs_unchanged']
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'image': image, 'passed': passed,
                      'regression': report.get('regression'), 'retired_image': report.get('retired_image'), 'errors': report['errors']}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
