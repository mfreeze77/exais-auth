"""Retire only the two recorded, unused and completely empty Core Gradle caches.

These came from the build image's inherited VOLUME; no database volume is eligible.
Nonempty or referenced volumes are retained. New Core containers use bounded tmpfs.
"""
from datetime import datetime, timezone
import json
import re
import subprocess
import uuid
from fetch_runtime_notice_sources import ROOT, require, sha

PYTHON = 'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    origin = ROOT / 'evidence/operations/hygiene/20260908T223704Z/containers-before.json'
    inventory = json.loads(origin.read_bytes())
    eligible = []
    for container in inventory:
        if container['Name'] not in ('/expertauth-oss-core-a', '/expertauth-oss-core-b'):
            continue
        for mount in container['Mounts']:
            if mount['Type'] == 'volume' and mount['Destination'] == '/home/gradle/.gradle':
                require(re.fullmatch(r'[0-9a-f]{64}', mount['Name']) is not None, 'Only recorded anonymous caches qualify')
                eligible.append({'volume': mount['Name'], 'original_container': container['Name']})
    require(len(eligible) == 2 and len({row['volume'] for row in eligible}) == 2, 'Unexpected legacy cache inventory')
    report = {'source_sha256': sha(__import__('pathlib').Path(__file__).read_bytes()),
              'original_inventory_sha256': sha(origin.read_bytes()), 'execute': args.execute,
              'database_volumes_touched': False, 'authentication_complete': False, 'results': [], 'commands': []}
    def run(argv, *, required=True):
        result = subprocess.run(argv, capture_output=True, timeout=30)
        report['commands'].append({'argv': argv, 'exit_code': result.returncode,
                                   'output_sha256': sha(result.stdout + result.stderr)})
        require(not required or result.returncode == 0, 'Docker command failed: ' + ' '.join(argv[:3]))
        return result
    for row in eligible:
        name = 'expertauth-empty-gradle-' + uuid.uuid4().hex[:12]
        try:
            if run(['docker', 'volume', 'inspect', row['volume']], required=False).returncode:
                report['results'].append({**row, 'status': 'already-absent'})
                continue
            if run(['docker', 'ps', '-aq', '--filter', 'volume=' + row['volume']]).stdout.strip():
                report['results'].append({**row, 'status': 'retained-referenced'})
                continue
            empty = run(['docker', 'run', '--rm', '--pull=never', '--name', name, '--label',
                         'org.expertauth.project=expert-auth', '--network', 'none', '--read-only',
                         '--mount', f'type=volume,source={row["volume"]},target=/audit,readonly,volume-nocopy',
                         PYTHON, 'python', '-c',
                         'from pathlib import Path; import sys; sys.exit(42 if any(Path("/audit").iterdir()) else 0)'], required=False)
            require(empty.returncode in (0, 42), 'Cache emptiness inspection failed')
            if empty.returncode == 42:
                report['results'].append({**row, 'status': 'retained-nonempty'})
                continue
            if args.execute:
                # Docker itself also refuses removal if a reference appeared.
                run(['docker', 'volume', 'rm', row['volume']])
            report['results'].append({**row, 'status': 'removed-empty-cache' if args.execute else 'verified-empty-cache'})
        finally:
            if run(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip():
                run(['docker', 'stop', '--timeout', '5', name], required=False)
                run(['docker', 'rm', name])
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = ROOT / 'evidence/operations/hygiene' / f'empty-gradle-caches-{stamp}.json'
    with path.open('xb') as stream:
        stream.write((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'report': path.relative_to(ROOT).as_posix(), 'results': report['results'], 'database_volumes_touched': False}))


if __name__ == '__main__':
    main()
