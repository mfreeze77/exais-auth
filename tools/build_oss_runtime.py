"""Build and inspect the pinned OSS runtime image without starting a service.

The image contains exact preserved notices; full distribution remains unapproved.
Temporary context and the named inspection container are always retired.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from assemble_runtime_licenses import assemble
from fetch_runtime_notice_sources import ROOT, require, sha

IMAGE = 'expertauth-oss-core:12.2.0-probe'


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
    probe = 'expertauth-runtime-notices-' + uuid.uuid4().hex[:12]

    def run(argv, *, required=True, timeout=240):
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        raw = result.stdout + result.stderr
        log = evidence / f'command-{len(report["commands"])+1:02d}.log'
        log.write_bytes(raw)
        report['commands'].append({'argv': argv, 'exit_code': result.returncode,
                                   'log': log.name, 'sha256': sha(raw)})
        require(not required or result.returncode == 0, 'Command failed; see ' + log.name)
        return result

    scratch = ROOT / '.cache'
    scratch.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='runtime-image-', dir=scratch) as temporary:
            context = Path(temporary).resolve()
            require(context.parent == scratch.resolve(), 'Runtime cleanup boundary')
            report['scratch_directory'] = context.relative_to(ROOT).as_posix()
            expected, notices = prepare_context(context)
            (evidence / 'notice-manifest.json').write_bytes((context / 'licenses/manifest.json').read_bytes())
            run(['docker', 'build', '--pull=false', '--network=none', '--label',
                 'org.expertauth.project=expert-auth', '-t', IMAGE, str(context)])
            image_id = run(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}']).stdout.decode().strip()
            report['image_id'] = image_id
            report['image_tag'] = IMAGE
            result = run(['docker', 'run', '--rm', '--pull=never', '--name', probe, '--label',
                          'org.expertauth.project=expert-auth', '--network', 'none', '--read-only',
                          '--entrypoint', '/bin/sh', image_id, '-c',
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
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            present = run(['docker', 'ps', '-aq', '--filter', 'name=^/' + probe + '$'], timeout=30)
            if present.stdout.strip():
                run(['docker', 'stop', '--timeout', '5', probe], required=False, timeout=30)
                run(['docker', 'rm', probe], timeout=30)
            report['inspection_container_removed'] = True
        except Exception as error:
            report['status'] = 'FAILED_CLEANUP'
            report['cleanup_error'] = str(error)
        (evidence / 'report.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    require(report['status'] == 'IMAGE_CONTENTS_VERIFIED' and report.get('scratch_removed'),
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
