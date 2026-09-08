"""Replace the owned private Core only when all87 executable JARs are unchanged.

This is notice-image maintenance, not a general auth upgrade or migration tool.
Preserves PostgreSQL, private configuration, rollback container and private logs.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
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
               if any(word in line.partition('=')[0] for word in ('PASSWORD', 'API_KEY'))]
    record = {'status': 'FAILED', 'authentication_complete': False, 'full_distribution_approved': False,
              'source_sha256': sha(Path(__file__).read_bytes()), 'commands': [],
              'qualified_image_report': {'path': str(args.image_report), 'sha256': sha(args.image_report.read_bytes())},
              'config_sha256': sha(config.read_bytes()), 'database_container_replaced': False, 'volumes_deleted': [],
              'new_image': image}
    backup = 'expertauth-oss-core-rollback-' + uuid.uuid4().hex[:12]
    helpers = []
    renamed = False
    disconnected = False
    new_started = False
    promoted = False

    def run(argv, *, required=True, private_output=False, timeout=60):
        process = subprocess.run(argv, capture_output=True, timeout=timeout)
        if not private_output:
            text = (process.stdout + process.stderr).decode('utf-8', errors='replace')
            for secret in secrets:
                text = text.replace(secret, '[REDACTED]')
            log = evidence / f'command-{len(record["commands"])+1:02d}.log'
            raw = text.encode('utf-8')
            log.write_bytes(raw)
            record['commands'].append({'argv': argv, 'exit_code': process.returncode, 'log': log.name, 'sha256': sha(raw)})
        require(not required or process.returncode == 0, 'Command failed: ' + ' '.join(argv[:3]))
        return process

    def ready():
        name = 'expertauth-notice-readiness-' + uuid.uuid4().hex[:12]
        helpers.append(name)
        return run(['docker', 'run', '--rm', '--pull=never', '--name', name, '--label',
                    'org.expertauth.project=expert-auth', '--network', NETWORK, '--env-file', str(env),
                    '--mount', f'type=bind,source={ROOT / "tools/wait_oss_storage.py"},target=/wait.py,readonly',
                    PYTHON, 'python', '/wait.py', 'http://core-a:3567'], timeout=120)

    try:
        old = json.loads(run(['docker', 'inspect', CORE], private_output=True).stdout)[0]
        require(old['State']['Running'] and old['Config'].get('Labels', {}).get('org.expertauth.purpose') == 'oss-foundation', 'Owned running Core required')
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
        run(['docker', 'stop', '--timeout', '15', CORE])
        run(['docker', 'rename', CORE, backup])
        renamed = True
        run(['docker', 'network', 'disconnect', NETWORK, backup])
        disconnected = True
        new_started = True
        run(['docker', 'run', '-d', '--pull=never', '--name', CORE, '--label', 'org.expertauth.project=expert-auth',
             '--label', 'org.expertauth.purpose=oss-foundation', '--network', NETWORK, '--network-alias', 'core-a',
             '--tmpfs', '/home/gradle/.gradle:rw,noexec,nosuid,size=16m',
             '--mount', f'type=bind,source={config},target=/run/expertauth/config.yaml,readonly', image])
        ready()
        observed = run(['docker', 'inspect', CORE, '--format', '{{.Image}}']).stdout.decode().strip()
        require(observed == image and sha(config.read_bytes()) == record['config_sha256'], 'Actual image or configuration differs')
        promoted = True
        run(['docker', 'rm', backup])
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
        if renamed and not promoted:
            try:
                if new_started:
                    run(['docker', 'stop', '--timeout', '5', CORE], required=False)
                    run(['docker', 'rm', CORE], required=False)
                if disconnected:
                    run(['docker', 'network', 'connect', '--alias', 'core-a', NETWORK, backup])
                run(['docker', 'rename', backup, CORE])
                run(['docker', 'start', CORE])
                ready()
                record['rollback_restored'] = True
            except Exception as rollback_error:
                record['rollback_error'] = str(rollback_error)
                record['retained_rollback_container'] = backup
    finally:
        for helper in helpers:
            try:
                if run(['docker', 'ps', '-aq', '--filter', 'name=^/' + helper + '$']).stdout.strip():
                    run(['docker', 'stop', '--timeout', '5', helper], required=False)
                    run(['docker', 'rm', helper])
            except Exception as error:
                record.setdefault('cleanup_errors', []).append({'container': helper, 'error': str(error)})
        (evidence / 'report.json').write_bytes((json.dumps(record, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'status': record['status'], 'report': (evidence / 'report.json').relative_to(ROOT).as_posix(),
                      'authentication_complete': False, 'full_distribution_approved': False}))
    return 0 if record['status'] == 'NOTICE_IMAGE_RUNNING_STORAGE_READY' and not record.get('cleanup_errors') else 1


if __name__ == '__main__':
    raise SystemExit(main())
