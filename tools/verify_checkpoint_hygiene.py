"""Read-only verification of the 2026-09-08 cleanup and preserved diagnostics.

No builds, downloads, container mutations, environment inspection or deletions.
The report is a resource/preservation check, never authentication acceptance.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'evidence/operations/hygiene/20260908T223704Z'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker(*argv):
    return subprocess.run(['docker', *argv], check=True, capture_output=True,
                          text=True, timeout=30).stdout.splitlines()


def main():
    plan = json.loads((ORIGINAL / 'plan.json').read_text(encoding='utf-8-sig'))
    before = json.loads((ORIGINAL / 'containers-before.json').read_text(encoding='utf-8-sig'))
    containers = [json.loads(line) for line in docker(
        'ps', '-a', '--no-trunc', '--filter', 'name=expertauth',
        '--format', '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}"}')]
    images = [json.loads(line) for line in docker(
        'image', 'ls', '--filter', 'reference=expertauth*', '--no-trunc',
        '--format', '{"tag":"{{.Repository}}:{{.Tag}}","id":"{{.ID}}","size":"{{.Size}}"}')]
    dangling_task_images = docker('image', 'ls', '--filter', 'dangling=true',
                                  '--filter', 'label=org.expertauth.project=expert-auth',
                                  '--no-trunc', '--format', '{{.ID}}')
    networks = docker('network', 'ls', '--filter', 'name=expertauth', '--format', '{{.Name}}')
    volumes = docker('volume', 'ls', '--filter', 'name=expertauth', '--format', '{{.Name}}')
    checks = []

    def check(name, passed, **detail):
        checks.append({'check': name, 'passed': bool(passed), **detail})

    retired = {row['Id'] for row in before if row['Retire']}
    check('15 original retired container IDs absent', len(retired) == 15 and not retired.intersection(row['id'] for row in containers))
    check('only retained Core and PostgreSQL containers remain',
          {row['name'] for row in containers} == {'expertauth-oss-core-a', 'expertauth-oss-postgres'})
    check('8 original stale tags absent', len(plan['RemoveImageTags']) == 8 and
          not set(plan['RemoveImageTags']).intersection(row['tag'] for row in images))
    check('6 bounded retained task tags', len(images) == 6 and {row['tag'] for row in images} == set(plan['KeepImages']))
    check('no dangling project-labeled images remain', not dangling_task_images)
    check('6 obsolete scratch directories absent', len(plan['RemoveScratch']) == 6 and
          all(not (ROOT / path).exists() for path in plan['RemoveScratch']))
    check('only owned OSS network remains', networks == ['expertauth-oss-proof'])
    check('Core database and reusable Gradle volumes preserved',
          {'expertauth-oss-proof-pg', 'expertauth-gradle-cache'}.issubset(volumes))
    backup_files = []
    for manifest in ORIGINAL.glob('*-backup-hashes.json'):
        for row in json.loads(manifest.read_text(encoding='utf-8-sig')):
            path = Path(row['Path'])
            # Private data stays outside tracked evidence; only hashes/counts appear.
            backup_files.append(path.exists() and sha(path).lower() == row['Hash'].lower())
    check('all 6 H2 backup file hashes unchanged', len(backup_files) == 6 and all(backup_files), checked_files=len(backup_files))
    logs = []
    extracted_reports = []
    for run in ['20260908T222718Z-a632c0', '20260908T222920Z-23f3d2']:
        path = ROOT / 'evidence/extracted-checkpoint' / run / 'report.json'
        report = json.loads(path.read_text())
        extracted_reports.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path)})
        for command in report['commands']:
            backup = ROOT / '.runtime/retired-proof-logs/20260908T223704Z' / run / 'raw-command-logs' / Path(command['private_raw_log']).name
            logs.append(backup.exists() and sha(backup) == command['raw_output_sha256'])
    check('all extracted-run raw command logs retained unchanged', bool(logs) and all(logs), checked_logs=len(logs))
    passed = all(row['passed'] for row in checks)
    report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'hygiene_verified': passed,
              'authentication_complete': False, 'docker_mutations': 0, 'checks': checks,
              'containers': containers, 'images': images, 'networks': networks, 'volumes': volumes,
              'dangling_task_images': dangling_task_images,
              'historical_reports': extracted_reports, 'verifier_sha256': sha(Path(__file__)),
              'limits': ['Docker shared layers are not summed as freed physical host disk',
                         'Unrelated Docker resources and volumes were not cleanup targets',
                         'Historical raw-log paths remain in immutable reports; verified copies now live in private retired-proof-logs']}
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = ORIGINAL.parent / f'verification-{stamp}.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'passed': sum(row['passed'] for row in checks),
                      'failed': sum(not row['passed'] for row in checks), 'containers': len(containers), 'image_tags': len(images)}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
