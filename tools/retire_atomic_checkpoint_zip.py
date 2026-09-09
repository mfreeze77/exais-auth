"""One-time exact generated-ZIP retention after complete verification.

Preserves every sidecar, Git history, immutable baseline and two newer ZIPs.
Only a single regular file is removed; no recursive filesystem action.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    '8bc7ab687c25': '69a8343a65f27144ba824bcbebdbc57476253aa55a1472d345c168e6a4eb0288',
    '35a24792711a': 'e873ac63534f53242f336c5b3f145eb9764b44ea1cd0f4934e547f9bb5e96a04',
    'c170edafe830': '871d63dbf6ce64cf3e5989ef15b02cd72c6eb2e6076c0f48aadd0500189dcc63',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    output = ROOT / 'evidence/operations/hygiene/checkpoint-retention-before-atomic-reset.json'
    need(not output.exists(), 'Preserve previous retention evidence')
    folder = (ROOT / 'artifacts').resolve()
    need(folder.parent == ROOT.resolve() and not (ROOT / 'artifacts').is_symlink(), 'Artifact boundary differs')
    report = {'started': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'tool_sha256': sha(Path(__file__)), 'rows': [], 'errors': [], 'deletion_performed': False,
              'scope': 'Retire only 8bc7ab687c25 generated ZIP after all three pins/CRC/members/ancestry verified; retain all sidecars and two newer ZIPs',
              'maximum_after_next_checkpoint': 3}

    def persist():
        output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    persist()
    try:
        expected_names = {f'expertauth-partial-checkpoint-{pin}.zip' for pin in PINS}
        need({p.name for p in folder.glob('*.zip')} == expected_names, 'Unexpected ZIP retention set')
        for pin, expected_sha in PINS.items():
            path = folder / f'expertauth-partial-checkpoint-{pin}.zip'
            need(path.is_file() and not path.is_symlink() and not getattr(path.lstat(), 'st_file_attributes', 0) & 0x400 and path.resolve().parent == folder, 'ZIP path is not an owned regular file')
            need(sha(path) == expected_sha, 'ZIP hash differs')
            manifest_path = path.with_suffix('.manifest.json')
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            validation_path = path.with_suffix('.validation.json')
            validation = json.loads(validation_path.read_text())
            need(manifest['kind'] == 'PARTIAL_SOURCE_CHECKPOINT' and manifest['complete'] is False and manifest['commit'].startswith(pin), 'Source checkpoint manifest differs')
            need(validation['sha256'] == expected_sha and validation['bundle_clone_head'] == manifest['commit'] and validation['complete'] is False, 'Prior validation identity differs')
            need(path.with_suffix('.zip.sha256').read_text().split() == [expected_sha, path.name], 'Checksum sidecar differs')
            subprocess.run(['git', 'merge-base', '--is-ancestor', manifest['commit'], 'HEAD'], cwd=ROOT, check=True, timeout=15)
            with zipfile.ZipFile(path) as archive:
                need(archive.testzip() is None, 'ZIP CRC mismatch')
                names = archive.namelist()
                wanted = {'expert-auth/' + row['path'] for row in manifest['files']} | {'expert-auth/CHECKPOINT_MANIFEST.json'}
                need(len(names) == len(set(names)) == len(wanted) and set(names) == wanted, 'ZIP member set differs')
                need(archive.read('expert-auth/CHECKPOINT_MANIFEST.json') == manifest_bytes, 'Embedded manifest differs')
                for row in manifest['files']:
                    body = archive.read('expert-auth/' + row['path'])
                    need(len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], 'Member bytes differ')
            sidecars = {p.name: sha(p) for p in (manifest_path, validation_path, path.with_suffix('.zip.sha256'))}
            report['rows'].append({'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
                                   'sha256': expected_sha, 'commit': manifest['commit'], 'crc_and_every_member_verified': True,
                                   'ancestor_of_current_head': True, 'sidecar_sha256': sidecars, 'retired': False})
        report['preflight_passed'] = True
        persist()
        target = (ROOT / report['rows'][0]['path']).resolve()
        need(target.parent == folder and target.name == 'expertauth-partial-checkpoint-8bc7ab687c25.zip' and sha(target) == PINS['8bc7ab687c25'], 'Final exact deletion boundary differs')
        target.unlink()
        report['rows'][0]['retired'] = report['deletion_performed'] = True
        persist()
        for row in report['rows']:
            for name, expected in row['sidecar_sha256'].items():
                need(sha(folder / name) == expected, 'Sidecar changed')
            if not row['retired']:
                need(sha(ROOT / row['path']) == row['sha256'], 'Retained recovery ZIP changed')
        need(not target.exists() and len(list(folder.glob('*.zip'))) == 2, 'Final retention set differs')
        report['passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        report['finished'] = datetime.now(timezone.utc).isoformat()
        persist()
    print(json.dumps({'passed': report['passed'], 'deleted_zip': report['deletion_performed'], 'retained_zip_count': len(list(folder.glob('*.zip'))), 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
