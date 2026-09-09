"""Replace the owned private Core only when all87 executable JARs are unchanged.

This is notice-image maintenance, not a general auth upgrade or migration tool.
Preserves PostgreSQL, private configuration, rollback container and private logs.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import uuid
from fetch_runtime_notice_sources import ROOT, require, sha

CORE = 'expertauth-oss-core-a'
NETWORK = 'expertauth-oss-proof'
PYTHON = 'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-report', type=Path, required=True)
    args = parser.parse_args()
    image_report = json.loads(args.image_report.read_bytes())
    require(image_report['status'] == 'IMAGE_CONTENTS_VERIFIED', 'Qualified image-content report required')
    require(all(sha((ROOT / path).read_bytes()) == digest for path, digest in image_report['source_sha256'].items()),
            'Image-builder inputs changed after qualification')
    notice_manifest = args.image_report.parent / 'notice-manifest.json'
    notice_identity = next(row['sha256'] for row in image_report['installed_files'] if row['path'] == 'licenses/manifest.json')
    require(sha(notice_manifest.read_bytes()) == notice_identity, 'Qualified notice manifest differs')
    require(all(sha((ROOT / path).read_bytes()) == digest for path, digest in
                json.loads(notice_manifest.read_bytes())['input_sha256'].items()), 'Qualified notice input changed')
    expected = {row['path']: row['sha256'] for row in image_report['installed_files'] if row['path'].startswith(('lib/', 'plugin/'))}
    require(len(expected) == 87, 'Full87-JAR equality guard required')
    image = image_report['image_id']
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    evidence = ROOT / 'evidence/runtime/oss-core-notices' / ('replacement-' + stamp)
    evidence.mkdir(parents=True, exist_ok=False)
    private = ROOT / '.runtime/retired-core-logs' / stamp
    private.mkdir(parents=True, exist_ok=False)
    env = ROOT / '.runtime/oss-core/runtime.env'
    config = ROOT / '.runtime/oss-core/config.yaml'
    secrets = [line.partition('=')[2] for line in env.read_text().splitlines()
               if line.partition('=')[2] and any(word in line.partition('=')[0] for word in ('PASSWORD', 'API_KEY'))]
    record = {'status': 'FAILED', 'authentication_complete': False, 'full_distribution_approved': False,
              'source_sha256': sha(Path(__file__).read_bytes()), 'commands': [],
              'readiness_helper_sha256': sha((ROOT / 'tools/wait_oss_storage.py').read_bytes()),
              'qualified_image_report': {'path': str(args.image_report), 'sha256': sha(args.image_report.read_bytes())},
              'config_sha256': sha(config.read_bytes()), 'database_container_replaced': False, 'volumes_deleted': [],
              'new_image': image}
    backup = 'expertauth-oss-core-rollback-' + uuid.uuid4().hex[:12]
    helpers = []
    renamed = False
    disconnected = False
    new_started = False
    promoted = False
    old = None
    new_cidfile = private / 'new-core.cid'
    python_image = None
    transition_started = False

    def database_state():
        row = json.loads(run(['docker', 'container', 'inspect', 'expertauth-oss-postgres'], private_output=True).stdout)[0]
        return {'id': row['Id'], 'image': row['Image'], 'started_at': row['State']['StartedAt'],
                'running': row['State']['Running'], 'mounts': row['Mounts']}

    def run(argv, *, required=True, private_output=False, timeout=60):
        error = None
        try:
            process = subprocess.run(argv, capture_output=True, timeout=timeout)
            raw = process.stdout + process.stderr
        except subprocess.TimeoutExpired as caught:
            error = caught
            raw = (caught.stdout or b'') + (caught.stderr or b'')
            process = None
        if not private_output:
            text = raw.decode('utf-8', errors='replace')
            for secret in secrets:
                text = text.replace(secret, '[REDACTED]')
            log = evidence / f'command-{len(record["commands"])+1:02d}.log'
            raw = text.encode('utf-8')
            log.write_bytes(raw)
            record['commands'].append({'argv': argv, 'exit_code': process.returncode if process else None,
                                       'timed_out': error is not None, 'log': log.name, 'sha256': sha(raw)})
        if error:
            raise error
        require(not required or process.returncode == 0, 'Command failed: ' + ' '.join(argv[:3]))
        return process

    def ready():
        require(sha((ROOT / 'tools/wait_oss_storage.py').read_bytes()) == record['readiness_helper_sha256'],
                'Readiness helper changed before execution')
        name = 'expertauth-notice-readiness-' + uuid.uuid4().hex[:12]
        cidfile = private / (name + '.cid')
        helpers.append({'name': name, 'cidfile': cidfile})
        return run(['docker', 'run', '--rm', '--pull=never', '--name', name, '--cidfile', str(cidfile), '--label',
                    'org.expertauth.project=expert-auth', '--label', 'org.expertauth.purpose=runtime-notice-readiness',
                    '--read-only', '--memory=128m', '--cpus=1', '--pids-limit=64', '--cap-drop=ALL',
                    '--security-opt=no-new-privileges', '--network', NETWORK, '--env-file', str(env),
                    '--mount', f'type=bind,source={ROOT / "tools/wait_oss_storage.py"},target=/wait.py,readonly',
                    PYTHON, 'python', '/wait.py', 'http://core-a:3567'], timeout=120)

    def owned_container(identifier, name, expected_image, purpose):
        require(re.fullmatch('[0-9a-f]{64}', identifier), 'Invalid owned container identity')
        row = json.loads(run(['docker', 'container', 'inspect', identifier], private_output=True).stdout)[0]
        labels = row['Config'].get('Labels') or {}
        require(row['Id'] == identifier and row['Name'] == '/' + name and row['Image'] == expected_image and
                labels.get('org.expertauth.project') == 'expert-auth' and
                labels.get('org.expertauth.purpose') == purpose, 'Container ownership changed; refuse mutation')
        return row

    try:
        record['database_before'] = database_state()
        require(record['database_before']['running'], 'Existing database must be running')
        old = json.loads(run(['docker', 'inspect', CORE], private_output=True).stdout)[0]
        owned_container(old['Id'], CORE, old['Image'], 'oss-foundation')
        require(old['State']['Running'], 'Owned running Core required')
        candidate = json.loads(run(['docker', 'image', 'inspect', image], private_output=True).stdout)[0]
        require(candidate['Id'] == image and candidate['Config'].get('Labels', {}).get('org.expertauth.project') == 'expert-auth',
                'Qualified task image ownership differs')
        python_image = json.loads(run(['docker', 'image', 'inspect', PYTHON], private_output=True).stdout)[0]['Id']
        require(not old['HostConfig']['PortBindings'] and set(old['NetworkSettings']['Networks']) == {NETWORK}, 'Unexpected Core exposure/network')
        net = json.loads(run(['docker', 'network', 'inspect', NETWORK], private_output=True).stdout)[0]
        require(net['Internal'], 'Private internal network required')
        mounts = old['Mounts']
        configs = [mount for mount in mounts if mount['Destination'] == '/run/expertauth/config.yaml']
        gradle = [mount for mount in mounts if mount['Destination'] == '/home/gradle/.gradle']
        require(len(configs) == 1 and len(gradle) <= 1 and len(mounts) == len(configs) + len(gradle) and
                configs[0]['Type'] == 'bind' and not configs[0]['RW'] and
                Path(configs[0]['Source']).resolve() == config.resolve() and
                all(mount['Type'] in ('volume', 'tmpfs') for mount in gradle), 'Unexpected Core data/config mount')
        # The Gradle build base declares an inherited VOLUME. The runtime does not
        # use Gradle; preserve an existing volume and use bounded tmpfs henceforth.
        record['preserved_inherited_gradle_volumes'] = [mount['Name'] for mount in gradle if mount['Type'] == 'volume']
        actual = {}
        output = run(['docker', 'exec', CORE, '/bin/sh', '-c',
                      'cd /opt/expertauth && find lib plugin -type f -exec sha256sum {} +']).stdout.decode()
        for line in output.splitlines():
            digest, path = line.split('  ', 1)
            require(path not in actual, 'Duplicate runtime path')
            actual[path] = digest
        require(actual == expected, 'Refuse general binary upgrade: existing87 JARs must match exactly')
        record['executable_jars_unchanged'] = 87
        record['old_image'] = old['Image']
        record['old_container_id'] = old['Id']
        require(old['Image'] != image, 'Core already uses the qualified notice image')
        logs = run(['docker', 'logs', CORE], private_output=True)
        raw = logs.stdout + logs.stderr
        (private / 'previous-core.log').write_bytes(raw)
        record['private_previous_log'] = {'path': (private / 'previous-core.log').relative_to(ROOT).as_posix(), 'sha256': sha(raw)}
        ready()
        owned_container(old['Id'], CORE, old['Image'], 'oss-foundation')
        transition_started = True
        run(['docker', 'stop', '--timeout', '15', old['Id']])
        run(['docker', 'rename', old['Id'], backup])
        renamed = True
        run(['docker', 'network', 'disconnect', NETWORK, old['Id']])
        disconnected = True
        new_started = True
        run(['docker', 'run', '-d', '--pull=never', '--name', CORE, '--cidfile', str(new_cidfile), '--label', 'org.expertauth.project=expert-auth',
             '--label', 'org.expertauth.purpose=oss-foundation', '--network', NETWORK, '--network-alias', 'core-a',
             '--memory=1g', '--cpus=2', '--pids-limit=256',
             '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=16m',
             '--mount', f'type=bind,source={config},target=/run/expertauth/config.yaml,readonly', image])
        ready()
        new_id = new_cidfile.read_text().strip()
        new = owned_container(new_id, CORE, image, 'oss-foundation')
        record['new_container_id'] = new_id
        require(new['State']['Running'] and sha(config.read_bytes()) == record['config_sha256'], 'Actual state or configuration differs')
        require(sha(Path(__file__).read_bytes()) == record['source_sha256'], 'Replacement source changed during execution')
        require(sha((ROOT / 'tools/wait_oss_storage.py').read_bytes()) == record['readiness_helper_sha256'],
                'Readiness helper changed during qualification')
        installed = {}
        output = run(['docker', 'exec', new_id, '/bin/sh', '-c',
                      'cd /opt/expertauth && find lib plugin licenses version.yaml -type f -exec sha256sum {} +']).stdout.decode()
        for line in output.splitlines():
            digest, path = line.split('  ', 1)
            require(path not in installed, 'Duplicate installed file')
            installed[path] = digest
        require(installed == {row['path']: row['sha256'] for row in image_report['installed_files']},
                'Running image contents differ from qualified package')
        record['running_installed_files_verified'] = len(installed)
        record['database_after'] = database_state()
        require(record['database_after'] == record['database_before'], 'Database container state/mounts changed during replacement')
        record['database_state_unchanged'] = True
        promoted = True
        owned_container(old['Id'], backup, old['Image'], 'oss-foundation')
        run(['docker', 'rm', old['Id']])
        renamed = False
        record['status'] = 'NOTICE_IMAGE_RUNNING_STORAGE_READY'
        record['rollback_container_removed_after_readiness'] = True
        # The prior image is retired only if no container, tag or digest needs it.
        used = run(['docker', 'ps', '-aq', '--filter', 'ancestor=' + old['Image']]).stdout.strip()
        old_image = json.loads(run(['docker', 'image', 'inspect', old['Image']], private_output=True).stdout)[0]
        if not used and not old_image.get('RepoTags') and not old_image.get('RepoDigests'):
            run(['docker', 'image', 'rm', old['Image']])
            record['old_image_removed'] = True
        else:
            record['old_image_removed'] = False
            record['old_image_retention_reason'] = 'Referenced by container/tag/digest; no forced removal'
    except Exception as error:
        record['status'] = 'FAILED'
        record['error'] = {'type': type(error).__name__, 'message': str(error)}
        if transition_started and not promoted:
            try:
                restored_old = json.loads(run(['docker', 'container', 'inspect', old['Id']], private_output=True).stdout)[0]
                require(restored_old['Name'] in {'/' + CORE, '/' + backup}, 'Rollback container name changed unexpectedly')
                rollback_name = restored_old['Name'].removeprefix('/')
                owned_container(old['Id'], rollback_name, old['Image'], 'oss-foundation')
                if new_started:
                    if new_cidfile.exists():
                        new_id = new_cidfile.read_text().strip()
                        owned_container(new_id, CORE, image, 'oss-foundation')
                        run(['docker', 'stop', '--timeout', '5', new_id], required=False)
                        run(['docker', 'rm', new_id])
                    else:
                        require(not run(['docker', 'ps', '-aq', '--filter', 'name=^/' + CORE + '$']).stdout.strip(),
                                'Unidentified new Core remains; refuse name-only rollback removal')
                if NETWORK not in restored_old['NetworkSettings']['Networks']:
                    run(['docker', 'network', 'connect', '--alias', 'core-a', NETWORK, old['Id']])
                if rollback_name != CORE:
                    run(['docker', 'rename', old['Id'], CORE])
                if not restored_old['State']['Running']:
                    run(['docker', 'start', old['Id']])
                ready()
                record['rollback_restored'] = True
            except Exception as rollback_error:
                record['rollback_error'] = str(rollback_error)
                record['retained_rollback_container'] = backup
    finally:
        for helper in helpers:
            try:
                cidfile = helper['cidfile']
                if cidfile.exists():
                    cid = cidfile.read_text().strip()
                    require(re.fullmatch('[0-9a-f]{64}', cid), 'Invalid readiness container ID')
                    present = run(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'id=' + cid]).stdout.strip()
                    if present:
                        owned_container(cid, helper['name'], python_image, 'runtime-notice-readiness')
                        run(['docker', 'rm', '-f', cid])
                    require(not run(['docker', 'ps', '-aq', '--filter', 'id=' + cid]).stdout.strip(), 'Readiness container remains')
                    record.setdefault('readiness_containers_removed', []).append({'name': helper['name'], 'id': cid})
                    cidfile.unlink()
                else:
                    require(not run(['docker', 'ps', '-aq', '--filter', 'name=^/' + helper['name'] + '$']).stdout.strip(),
                            'Readiness container present without retained identity')
            except Exception as error:
                record.setdefault('cleanup_errors', []).append({'container': helper['name'], 'error': str(error)})
        if promoted or record.get('rollback_restored'):
            new_cidfile.unlink(missing_ok=True)
        (evidence / 'report.json').write_bytes((json.dumps(record, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'status': record['status'], 'report': (evidence / 'report.json').relative_to(ROOT).as_posix(),
                      'authentication_complete': False, 'full_distribution_approved': False}))
    return 0 if record['status'] == 'NOTICE_IMAGE_RUNNING_STORAGE_READY' and not record.get('cleanup_errors') else 1


if __name__ == '__main__':
    raise SystemExit(main())
