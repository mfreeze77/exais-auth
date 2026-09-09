"""Build and inspect the pinned OSS runtime image without starting a service.

The image contains exact preserved notices; full distribution remains unapproved.
Temporary context and the named inspection container are always retired.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from assemble_runtime_licenses import assemble
from fetch_runtime_notice_sources import ROOT, require, sha

IMAGE = 'expertauth-oss-core:12.2.0-probe'
PROJECT = 'expert-auth'
PURPOSE = 'runtime-notice-inspection'


def buildx_command():
    # Docker Desktop may install the official CLI plugin outside PATH.
    candidates = [Path('C:/Program Files/Docker/cli-plugins/docker-buildx.exe'),
                  Path('C:/Program Files/Docker/Docker/resources/cli-plugins/docker-buildx.exe')]
    return [str(path) for path in candidates if path.is_file()][:1] or ['docker', 'buildx']


def prepare_context(context):
    context = context.resolve()
    cache = (ROOT / '.cache').resolve()
    require(cache.is_relative_to(ROOT.resolve()) and context.parent == cache and
            context.name.startswith('runtime-image-'), 'Runtime context outside bounded scratch')
    require(context.exists() and not any(context.iterdir()), 'Runtime context must be empty')
    build = ROOT / '.cache/engine-build'
    evidence = ROOT / 'evidence/build/oss-core'
    require(json.loads((evidence / 'command.json').read_bytes())['exit_code'] == 0, 'Successful source build required')
    expected = {row['path']: row['sha256'] for row in json.loads((evidence / 'artifacts.json').read_bytes())}
    copied = {}
    seen = set()
    for project, destination in [('supertokens-core', 'lib'), ('supertokens-plugin-interface', 'lib'),
                                 ('supertokens-postgresql-plugin', 'plugin')]:
        for folder in ['libs', 'dependencies']:
            for jar in sorted((build / project / 'build' / folder).glob('*.jar')):
                relative = jar.relative_to(build).as_posix()
                digest = sha(jar.read_bytes())
                require(relative in expected and expected[relative] == digest, 'Unreviewed or changed build artifact')
                require('ee.jar' not in jar.name.lower(), 'Restricted artifact name')
                with zipfile.ZipFile(jar) as archive:
                    require(not any(name.startswith(('io/supertokens/ee/', 'ee/')) or name.endswith('/ee.jar')
                                    for name in archive.namelist()), 'Restricted artifact member')
                target = context / destination / jar.name
                require(not target.exists(), 'Runtime JAR destination collision')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(jar, target)
                copied[target.relative_to(context).as_posix()] = digest
                seen.add(relative)
    require(seen == set(expected) and len(seen) == 87, 'Incomplete runtime artifact inventory')
    notices = assemble(context / 'licenses')
    shutil.copyfile(ROOT / 'deploy/oss-core.Dockerfile', context / 'Dockerfile')
    (context / 'version.yaml').write_bytes(b'core_version: 12.2.0\nplugin_interface_version: 10.0.0\nplugin_version: 9.8.0\nplugin_name: postgresql\n')
    installed = {**copied, 'version.yaml': sha((context / 'version.yaml').read_bytes()),
                 'licenses/manifest.json': sha((context / 'licenses/manifest.json').read_bytes())}
    installed.update({'licenses/' + row['path']: row['sha256'] for row in notices['files']})
    return installed, notices


def build_runtime_image(*, evidence_name=None):
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = evidence_name or stamp + '-' + uuid.uuid4().hex[:6]
    require(name.replace('-', '').replace('_', '').isalnum(), 'Unsafe evidence name')
    evidence = ROOT / 'evidence/runtime/oss-core-notices' / name
    evidence.mkdir(parents=True, exist_ok=False)
    report = {'timestamp_utc': stamp, 'status': 'FAILED', 'authentication_complete': False,
              'full_distribution_approved': False, 'services_started': False, 'commands': [],
              'source_sha256': {path: sha((ROOT / path).read_bytes()) for path in
                                ['tools/build_oss_runtime.py', 'tools/assemble_runtime_licenses.py',
                                 'tools/fetch_runtime_notice_sources.py', 'reuse/runtime-source-archives.lock.json',
                                 'deploy/oss-core.Dockerfile', 'evidence/build/oss-core/artifacts.json']}}
    run_id = uuid.uuid4().hex
    probe = 'expertauth-runtime-notices-' + run_id[:12]
    private = ROOT / '.runtime/runtime-image-build' / run_id
    private.mkdir(parents=True, exist_ok=False)
    iidfile, cidfile = private / 'image.id', private / 'container.id'
    report.update({'run_id': run_id, 'image_tag': IMAGE, 'image_tag_promoted': False,
                   'inspection_container_removed': False, 'scratch_removed': False})
    candidate = None
    previous = None
    promotion_attempted = False
    context = None
    expected = None
    notices = None

    def run(argv, *, required=True, timeout=240):
        error = None
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout)
            raw = result.stdout + result.stderr
        except subprocess.TimeoutExpired as caught:
            error = caught
            raw = (caught.stdout or b'') + (caught.stderr or b'')
            result = None
        log = evidence / f'command-{len(report["commands"])+1:02d}.log'
        log.write_bytes(raw)
        report['commands'].append({'argv': argv, 'exit_code': result.returncode if result else None,
                                   'log': log.name, 'sha256': sha(raw), 'timed_out': error is not None})
        if error:
            raise error
        require(not required or result.returncode == 0, 'Command failed; see ' + log.name)
        return result

    def image_record(identifier):
        return json.loads(run(['docker', 'image', 'inspect', identifier]).stdout)[0]

    def retire_probe():
        if cidfile.exists():
            cid = cidfile.read_text().strip()
            require(re.fullmatch('[0-9a-f]{64}', cid), 'Malformed inspection container identity')
            report['inspection_container_id'] = cid
            found = run(['docker', 'container', 'inspect', cid], required=False)
            if found.returncode == 0:
                row = json.loads(found.stdout)[0]
                labels = row['Config'].get('Labels') or {}
                require(row['Id'] == cid and row['Name'] == '/' + probe and row['Image'] == candidate and
                        labels.get('org.expertauth.project') == PROJECT and
                        labels.get('org.expertauth.purpose') == PURPOSE and
                        labels.get('org.expertauth.build-run') == run_id,
                        'Inspection container ownership changed; refuse removal')
                run(['docker', 'container', 'rm', '-f', cid], timeout=30)
            remaining = run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'id=' + cid], timeout=30)
        else:
            remaining = run(['docker', 'ps', '-aq', '--filter', 'name=^/' + probe + '$'], timeout=30)
        require(not remaining.stdout.strip(), 'Inspection container remains')
        report['inspection_container_removed'] = True
        cidfile.unlink(missing_ok=True)

    scratch = ROOT / '.cache'
    scratch.mkdir(exist_ok=True)
    try:
        previous = image_record(IMAGE)['Id']
        report['previous_image_id'] = previous
        require(image_record(previous)['Config'].get('Labels', {}).get('org.expertauth.project') == PROJECT,
                'Current task image must be owned')
        buildx = buildx_command()
        report['buildx_command'] = buildx
        if len(buildx) == 1:
            report['buildx_executable_sha256'] = sha(Path(buildx[0]).read_bytes())
        run(buildx + ['version'])
        builder = run(buildx + ['inspect', 'default']).stdout.decode()
        require(re.search(r'^Driver:\s+docker\s*$', builder, re.M) and
                re.search(r'^Status:\s+running\s*$', builder, re.M), 'Existing Docker-driver builder required')
        before = run(['docker', 'image', 'ls', '-aq', '--no-trunc']).stdout.decode().splitlines()
        report['image_ids_before'] = sorted(set(before))
        with tempfile.TemporaryDirectory(prefix='runtime-image-', dir=scratch) as temporary:
            context = Path(temporary).resolve()
            require(context.parent == scratch.resolve(), 'Runtime cleanup boundary')
            report['scratch_directory'] = context.relative_to(ROOT).as_posix()
            expected, notices = prepare_context(context)
            (evidence / 'notice-manifest.json').write_bytes((context / 'licenses/manifest.json').read_bytes())
            base = (context / 'Dockerfile').read_text().splitlines()[0].removeprefix('FROM ')
            require('@sha256:' in base, 'Pinned runtime base required')
            report['cached_base_image_id'] = image_record(base)['Id']
            report['context_bytes'] = sum(path.stat().st_size for path in context.rglob('*') if path.is_file())
            require(report['context_bytes'] <= 200 * 1024 * 1024, 'Runtime context exceeds200MiB budget')
            run(buildx + ['build', '--builder', 'default', '--pull=false', '--network=none',
                          '--resource', 'memory=512m', '--resource', 'cpu-quota=100000',
                          '--progress=plain', '--provenance=false', '--iidfile', str(iidfile),
                          '--metadata-file', str(evidence / 'build-metadata.json'),
                          '--label', 'org.expertauth.project=' + PROJECT,
                          '--label', 'org.expertauth.purpose=runtime-notice-image',
                          '--label', 'org.expertauth.build-run=' + run_id, str(context)], timeout=600)
            config_digest = iidfile.read_text().strip()
            metadata = json.loads((evidence / 'build-metadata.json').read_bytes())
            require(re.fullmatch('sha256:[0-9a-f]{64}', config_digest) and
                    metadata['containerimage.config.digest'] == config_digest, 'Built configuration identity differs')
            export_digest = metadata['containerimage.digest']
            require(re.fullmatch('sha256:[0-9a-f]{64}', export_digest), 'Malformed exported image digest')
            # Containerd-backed Docker stores address images by manifest digest;
            # BuildKit's iidfile contains the distinct configuration digest.
            built = image_record(export_digest)
            candidate = built['Id']
            report['build_config_digest'] = config_digest
            report['build_export_digest'] = export_digest
            report['image_id'] = candidate
            report['image_size_bytes'] = built['Size']
            require(built['Config']['Labels'].get('org.expertauth.build-run') == run_id and
                    candidate not in report['image_ids_before'], 'Candidate is not unique to this build')
            require(image_record(IMAGE)['Id'] == previous, 'Current image tag changed before qualification')
            result = run(['docker', 'run', '--rm', '--pull=never', '--name', probe, '--cidfile', str(cidfile),
                          '--label', 'org.expertauth.project=' + PROJECT, '--label', 'org.expertauth.purpose=' + PURPOSE,
                          '--label', 'org.expertauth.build-run=' + run_id, '--network', 'none', '--read-only',
                          '--memory=256m', '--cpus=1', '--pids-limit=64', '--cap-drop=ALL',
                          '--security-opt=no-new-privileges', '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=16m',
                          '--entrypoint', '/bin/sh', candidate, '-c',
                          'cd /opt/expertauth && find lib plugin licenses version.yaml -type f -exec sha256sum {} +'])
            actual = {}
            for line in result.stdout.decode().splitlines():
                digest, path = line.split('  ', 1)
                require(path not in actual, 'Duplicate installed path')
                actual[path] = digest
            require(actual == expected, 'Installed runtime/notice files differ from prepared context')
            require(all(sha((ROOT / path).read_bytes()) == digest for path, digest in report['source_sha256'].items()),
                    'Build inputs changed during image qualification')
            require(all(sha((ROOT / path).read_bytes()) == digest for path, digest in notices['input_sha256'].items()),
                    'Notice inputs changed during image qualification')
            report.update({'status': 'IMAGE_CONTENTS_VERIFIED', 'installed_file_count': len(actual),
                           'runtime_jar_count': 87, 'runtime_dependency_count': notices['runtime_dependency_count'],
                           'binary_notice_text_count': notices['binary_notice_text_count'],
                           'source_notice_text_count': notices['source_notice_text_count'],
                           'installed_files': [{'path': path, 'sha256': digest} for path, digest in sorted(actual.items())]})
        report['scratch_removed'] = not context.exists()
        retire_probe()
        require(report['scratch_removed'], 'Runtime context remains')
        require(image_record(IMAGE)['Id'] == previous, 'Current task tag changed; refuse promotion')
        promotion_attempted = True
        run(['docker', 'image', 'tag', candidate, IMAGE])
        require(image_record(IMAGE)['Id'] == candidate, 'Image tag promotion failed')
        report['image_tag_promoted'] = True
    except Exception as error:
        report['status'] = 'FAILED'
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            if not report['inspection_container_removed']:
                retire_probe()
            if not report['image_tag_promoted']:
                if promotion_attempted and candidate is not None and previous is not None:
                    current = image_record(IMAGE)['Id']
                    require(current in {candidate, previous}, 'Task tag changed externally; refuse rollback')
                    if current == candidate:
                        run(['docker', 'image', 'tag', previous, IMAGE])
                        report['previous_image_tag_restored'] = True
                # Find only images carrying this unpredictable per-run label.
                candidates = run(['docker', 'image', 'ls', '-aq', '--no-trunc', '--filter',
                                  'label=org.expertauth.build-run=' + run_id]).stdout.decode().splitlines()
                removed = []
                for identifier in sorted(set(candidates)):
                    row = image_record(identifier)
                    labels = row['Config'].get('Labels') or {}
                    require(identifier != previous and identifier not in report.get('image_ids_before', []) and
                            labels.get('org.expertauth.project') == PROJECT and
                            labels.get('org.expertauth.purpose') == 'runtime-notice-image' and
                            labels.get('org.expertauth.build-run') == run_id and not row.get('RepoTags') and
                            not row.get('RepoDigests'), 'Candidate image ownership/references changed')
                    require(not run(['docker', 'ps', '-aq', '--filter', 'ancestor=' + identifier]).stdout.strip(),
                            'Candidate image is still used')
                    run(['docker', 'image', 'rm', identifier])
                    removed.append(identifier)
                report['failed_candidate_images_removed'] = removed
                if previous is not None:
                    require(image_record(IMAGE)['Id'] == previous, 'Failure changed the protected task tag')
                    report['previous_image_tag_preserved'] = True
            report['scratch_removed'] = context is None or not context.exists()
            iidfile.unlink(missing_ok=True)
            if not any(private.iterdir()):
                private.rmdir()
        except Exception as error:
            report['status'] = 'FAILED_CLEANUP'
            report['cleanup_error'] = str(error)
        (evidence / 'report.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    require(report['status'] == 'IMAGE_CONTENTS_VERIFIED' and report.get('scratch_removed') and
            report['inspection_container_removed'] and report['image_tag_promoted'],
            'Runtime image qualification failed; see ' + evidence.relative_to(ROOT).as_posix())
    print(json.dumps({'report': (evidence / 'report.json').relative_to(ROOT).as_posix(), 'image_id': report['image_id'],
                      'files_verified': report['installed_file_count'], 'services_started': False,
                      'scratch_removed': True, 'full_distribution_approved': False}))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-name')
    arguments = parser.parse_args()
    build_runtime_image(evidence_name=arguments.evidence_name)
