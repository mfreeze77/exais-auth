"""Build the pinned Python app offline, qualify installed bytes and HTTP behavior.

Acquisition is explicit and bounded. Keep the current component image until the
candidate passes byte checks, real HTTP tests, source stability and cleanup.
No engine/database replacement, new networks/volumes, or public ports.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
from build_oss_runtime import buildx_command
from fetch_python_wheels import MAX_CACHE, locked_wheels, verify_wheel

ROOT = Path(__file__).resolve().parents[1]
TAG = 'expertauth-python-app:0.1.0'
BASE = 'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'
PROJECT = 'expert-auth'
INPUTS = ['tools/build_python_runtime.py', 'tools/build_oss_runtime.py', 'tools/fetch_python_wheels.py',
          'tools/verify_python_distribution.py', 'tools/refresh_python_image.py', 'tools/run_sdk_session_faults.py',
          'examples/python/Dockerfile', 'examples/python/.dockerignore', 'examples/python/app.py',
          'examples/python/requirements.lock', 'examples/python/dependency-resolution.json',
          'reuse/files/supertokens__supertokens-python.json', 'tests/clients/python_probe.py']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--fetch-wheels', action='store_true', help='Acquire only missing hash-pinned wheels from the approved public origin')
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]+', args.name), 'Invalid evidence name')
    output = ROOT / 'evidence/operations/python-offline-build' / args.name
    need(not output.exists(), 'Preserve prior build evidence')
    wheel_output = ROOT / 'evidence/reuse/python-wheel-cache' / args.name
    need(not wheel_output.exists(), 'Preserve prior acquisition evidence')
    run_id = uuid.uuid4().hex
    private = (ROOT / '.runtime/python-offline-build' / run_id).resolve()
    need(private.parent == (ROOT / '.runtime/python-offline-build').resolve(), 'Private scratch boundary differs')
    cache = (ROOT / '.cache/python-wheels').resolve()
    need(cache.parent == (ROOT / '.cache').resolve() and cache.is_relative_to(ROOT.resolve()), 'Wheel cache boundary differs')
    inputs = {path: sha(ROOT / path) for path in INPUTS}
    output.mkdir(parents=True)
    wheel_output.mkdir(parents=True)
    private.mkdir(parents=True)
    cache.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'expertauth-python-offline-build-v1', 'started': datetime.now(timezone.utc).isoformat(),
              'passed': False, 'foundation_passed': False, 'full_distribution_approved': False,
              'input_sha256': inputs, 'run_id': run_id, 'commands': [], 'errors': [],
              'build_network': 'none', 'image_promoted': False, 'inspection_containers_removed': [],
              'new_networks': 0, 'new_volumes': 0, 'published_ports': []}
    old = candidate = None
    promoted = False
    promotion_attempted = False

    def call(argv, *, required=True, timeout=60):
        error = None
        try:
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
            raw = result.stdout + result.stderr
        except subprocess.TimeoutExpired as caught:
            raw = (caught.stdout or b'') + (caught.stderr or b'')
            error, result = caught, None
        path = output / f'command-{len(report["commands"]) + 1:02d}.log'
        path.write_bytes(raw)
        report['commands'].append({'argv': argv, 'exit_code': result.returncode if result else None,
                                   'timed_out': error is not None, 'log': path.name, 'sha256': sha(path)})
        if error:
            raise error
        need(not required or result.returncode == 0, 'Command failed: ' + path.name)
        return result

    def image(identifier):
        return json.loads(call(['docker', 'image', 'inspect', identifier]).stdout)[0]

    def resources():
        return {kind: sorted(call(['docker', *argv]).stdout.decode().splitlines()) for kind, argv in {
            'containers': ['ps', '-aq', '--no-trunc', '--filter', 'name=expertauth'],
            'networks': ['network', 'ls', '-q', '--no-trunc', '--filter', 'name=expertauth'],
            'volumes': ['volume', 'ls', '-q', '--filter', 'name=expertauth']}.items()}

    def preserved_services():
        template = ('{"id":{{json .Id}},"image":{{json .Image}},"started":{{json .State.StartedAt}},'
                    '"running":{{json .State.Running}},"mounts":{{json .Mounts}},'
                    '"ports":{{json .HostConfig.PortBindings}}}')
        rows = {name: json.loads(call(['docker', 'container', 'inspect', '--format', template, name]).stdout)
                for name in ['expertauth-oss-core-a', 'expertauth-oss-postgres']}
        need(all(row['running'] and not row['ports'] for row in rows.values()), 'Private services must already be running without published ports')
        return rows

    def run_container(role, image_id, mounts, command, *, network='none', timeout=180):
        name = 'expertauth-python-' + role + '-' + run_id[:12]
        cidfile = private / (role + '.cid')
        labels = {'org.expertauth.project': PROJECT, 'org.expertauth.purpose': 'python-offline-' + role,
                  'org.expertauth.build-run': run_id}
        argv = ['docker', 'run', '--rm', '--pull=never', '--name', name, '--cidfile', str(cidfile),
                '--read-only', '--network', network, '--memory=256m', '--cpus=1', '--pids-limit=64',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,noexec,size=32m']
        for key, value in labels.items():
            argv += ['--label', key + '=' + value]
        for source, target, writable in mounts:
            argv += ['--mount', f'type=bind,source={source},target={target}' + ('' if writable else ',readonly')]
        argv += ['--entrypoint', 'python', image_id, '-B', *command]
        try:
            return call(argv, timeout=timeout)
        finally:
            cid = cidfile.read_text().strip() if cidfile.exists() else None
            if cid:
                need(re.fullmatch('[0-9a-f]{64}', cid), 'Malformed helper CID; removal refused')
                template = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}'
                found = call(['docker', 'container', 'inspect', '--format', template, cid], required=False)
                if found.returncode == 0:
                    row = json.loads(found.stdout)
                    need(row['id'] == cid and row['name'] == '/' + name and row['image'] == image_id and
                         all((row['labels'] or {}).get(k) == v for k, v in labels.items()),
                         'Helper ownership differs; removal refused')
                    call(['docker', 'container', 'rm', '-f', cid], timeout=30)
                remaining = call(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'id=' + cid])
            else:
                remaining = call(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$'])
            need(not remaining.stdout.strip(), 'Temporary helper remains')
            report['inspection_containers_removed'].append({'role': role, 'name': name, 'id': cid})
            cidfile.unlink(missing_ok=True)

    def retire_image(identifier, *, built_here):
        row = image(identifier)
        labels = row['Config'].get('Labels') or {}
        need(row['Id'] == identifier and labels.get('org.expertauth.project') == PROJECT and
             not row.get('RepoTags') and not row.get('RepoDigests'), 'Image ownership/references differ; preserve')
        if built_here:
            need(labels.get('org.expertauth.build-run') == run_id and
                 labels.get('org.expertauth.purpose') == 'python-foundation' and
                 identifier not in report['image_ids_before'], 'Candidate not owned by this build')
        else:
            need(identifier == old['Id'] and labels == old['Config'].get('Labels'), 'Old image identity changed')
        need(not call(['docker', 'ps', '-aq', '--filter', 'ancestor=' + identifier]).stdout.strip(), 'Image still used')
        call(['docker', 'image', 'rm', identifier])

    try:
        report['resources_before'] = resources()
        report['preserved_services_before'] = preserved_services()
        need((ROOT / 'examples/python/Dockerfile').read_text().splitlines()[0] == 'FROM ' + BASE,
             'Dockerfile base differs from required cached digest')
        old = image(TAG)
        need(old['Config'].get('Labels', {}).get('org.expertauth.project') == PROJECT, 'Current component image is unowned')
        report['previous_image_id'] = old['Id']
        base = image(BASE)
        report['base_image_id'] = base['Id']
        report['image_ids_before'] = sorted(set(call(['docker', 'image', 'ls', '-aq', '--no-trunc']).stdout.decode().splitlines()))
        buildx = buildx_command()
        report['buildx_command'] = buildx
        if len(buildx) == 1:
            report['buildx_sha256'] = sha(Path(buildx[0]))
        call(buildx + ['version'])
        builder = call(buildx + ['inspect', 'default']).stdout.decode()
        need(re.search(r'^Driver:\s+docker\s*$', builder, re.M) and re.search(r'^Status:\s+running\s*$', builder, re.M),
             'Existing running Docker-driver builder required')
        source_paths = ['tools/fetch_python_wheels.py', 'examples/python/requirements.lock', 'examples/python/dependency-resolution.json']
        mounts = [(ROOT / p, '/repo/' + p, False) for p in source_paths]
        mounts += [(cache, '/repo/.cache/python-wheels', True),
                   (wheel_output, '/repo/evidence/reuse/python-wheel-cache/' + args.name, True)]
        run_container('wheels', base['Id'], mounts,
                      ['/repo/tools/fetch_python_wheels.py', '--output',
                       '/repo/evidence/reuse/python-wheel-cache/' + args.name + '/acquisition.json'] +
                      ([] if args.fetch_wheels else ['--offline']),
                      network='bridge' if args.fetch_wheels else 'none', timeout=900)
        acquisition = json.loads((wheel_output / 'acquisition.json').read_bytes())
        need(acquisition['passed'] and len(acquisition['results']) == 49, 'Wheel acquisition incomplete')
        rows = locked_wheels()
        for row in rows:
            verify_wheel((cache / row['filename']).read_bytes(), row)
        need(sum(p.stat().st_size for p in cache.iterdir()) <= MAX_CACHE, 'Wheel cache exceeds bound')
        report['wheel_acquisition'] = {'path': (wheel_output / 'acquisition.json').relative_to(ROOT).as_posix(),
                                      'sha256': sha(wheel_output / 'acquisition.json'), 'cache_bytes': acquisition['cache_bytes'],
                                      'downloaded': sum(row['downloaded'] for row in acquisition['results'])}
        need(image(TAG)['Id'] == old['Id'], 'Task tag changed before build')
        iidfile = private / 'image.id'
        call(buildx + ['build', '--builder', 'default', '--pull=false', '--network=none',
                       '--resource', 'memory=512m', '--resource', 'cpu-quota=200000',
                       '--progress=plain', '--provenance=false', '--iidfile', str(iidfile),
                       '--metadata-file', str(output / 'build-metadata.json'),
                       '--build-context', 'python_wheels=' + str(cache),
                       '--label', 'org.expertauth.project=' + PROJECT,
                       '--label', 'org.expertauth.purpose=python-foundation',
                       '--label', 'org.expertauth.build-run=' + run_id, str(ROOT / 'examples/python')], timeout=600)
        metadata = json.loads((output / 'build-metadata.json').read_bytes())
        need(metadata['containerimage.config.digest'] == iidfile.read_text().strip(), 'Build configuration digest differs')
        built = image(metadata['containerimage.digest'])
        candidate = built['Id']
        need(candidate not in report['image_ids_before'] and
             built['Config'].get('Labels', {}).get('org.expertauth.build-run') == run_id, 'Candidate image is not unique to this run')
        report.update(candidate_image_id=candidate, candidate_image_size=built['Size'],
                      build_config_digest=metadata['containerimage.config.digest'], build_export_digest=metadata['containerimage.digest'])
        audit = output / 'distribution'
        audit.mkdir()
        mounts = [(ROOT / p, '/repo/' + p, False) for p in source_paths +
                  ['tools/verify_python_distribution.py', 'reuse/files/supertokens__supertokens-python.json']]
        mounts += [(cache, '/repo/.cache/python-wheels', False), (audit, '/evidence', True)]
        run_container('distribution', candidate, mounts, ['/repo/tools/verify_python_distribution.py'], timeout=180)
        distribution = json.loads((audit / 'distribution.json').read_bytes())
        need(distribution['passed'], 'Installed distribution qualification incomplete')
        report['distribution_report'] = {'path': (audit / 'distribution.json').relative_to(ROOT).as_posix(),
                                         'sha256': sha(audit / 'distribution.json')}
        regression_name = 'offline-build-' + args.name
        # The child owns bounded per-command timeouts and cleanup; do not kill
        # its parent while it can own live HTTP-test containers.
        result = subprocess.run([sys.executable, '-B', 'tools/refresh_python_image.py', '--test-image', candidate,
                                 '--name', regression_name], cwd=ROOT, capture_output=True)
        (output / 'http-regression.log').write_bytes(result.stdout + result.stderr)
        regression_path = ROOT / 'evidence/operations/python-readiness' / regression_name / 'report.json'
        regression = json.loads(regression_path.read_bytes())
        need(result.returncode == 0 and regression['candidate_test_only'] and not regression['image_promoted'] and
             regression['new_image'] == candidate and regression['regression']['passed'] == 19 and
             regression['regression']['skipped'] == 0 and regression['temporary_containers_retired'], 'Candidate HTTP regression incomplete')
        report['regression_report'] = {'path': regression_path.relative_to(ROOT).as_posix(), 'sha256': sha(regression_path)}
        need(inputs == {path: sha(ROOT / path) for path in INPUTS}, 'Build/qualification inputs changed')
        for row in rows:
            verify_wheel((cache / row['filename']).read_bytes(), row)
        report['inputs_unchanged'] = True
        report['resources_after_qualification'] = resources()
        need(report['resources_after_qualification'] == report['resources_before'], 'Task resources changed during qualification')
        report['preserved_services_after'] = preserved_services()
        need(report['preserved_services_after'] == report['preserved_services_before'], 'Core/database changed during qualification')
        iidfile.unlink()
        need(not any(private.iterdir()), 'Private scratch still contains files')
        private.rmdir()
        report['private_scratch_removed_before_promotion'] = True
        need(image(TAG)['Id'] == old['Id'], 'Current image tag changed; refuse promotion')
        promotion_attempted = True
        call(['docker', 'image', 'tag', candidate, TAG])
        need(image(TAG)['Id'] == candidate, 'Tag promotion failed')
        promoted = True
        report['image_promoted'] = True
        retire_image(old['Id'], built_here=False)
        report['retired_previous_image'] = old['Id']
        report['passed'] = True
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            if not promoted:
                if promotion_attempted and candidate and old:
                    current = image(TAG)['Id']
                    need(current in {candidate, old['Id']}, 'Tag changed externally; refuse rollback')
                    if current == candidate:
                        call(['docker', 'image', 'tag', old['Id'], TAG])
                        report['previous_tag_restored'] = True
                candidates = call(['docker', 'image', 'ls', '-aq', '--no-trunc', '--filter',
                                   'label=org.expertauth.build-run=' + run_id]).stdout.decode().splitlines()
                report['failed_candidates_removed'] = []
                for identifier in sorted(set(candidates)):
                    retire_image(identifier, built_here=True)
                    report['failed_candidates_removed'].append(identifier)
                if old:
                    need(image(TAG)['Id'] == old['Id'], 'Failed build changed current image tag')
            if private.exists():
                (private / 'image.id').unlink(missing_ok=True)
                if not any(private.iterdir()):
                    private.rmdir()
            report['private_scratch_removed'] = not private.exists()
            need(report['private_scratch_removed'], 'Unresolved helper state retained privately')
        except Exception as error:
            report['passed'] = False
            report['errors'].append('Cleanup: ' + type(error).__name__ + ': ' + str(error))
        report['finished'] = datetime.now(timezone.utc).isoformat()
        (output / 'report.json').write_bytes((json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'passed': report['passed'],
                      'image': candidate, 'image_promoted': report['image_promoted'], 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
