"""Retire an exact superseded JAR pair only after an installed upgrade/rollback proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile
from atomic_core_identity import current_core_image
from password_session_candidates import validate_pair, need

ROOT = Path(__file__).resolve().parents[1]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-build', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,35}', args.image_build), 'Invalid installed build name')
    output = ROOT / 'evidence/operations/hygiene' / ('password-session-retirement-' + args.image_build + '.json')
    need(not output.exists(), 'Preserve retirement evidence')
    image_path = ROOT / 'evidence/operations/atomic-core-image' / args.image_build / 'report.json'
    installed = read(image_path)
    need(installed['passed'] and installed['installed_qualification_passed'] and
         installed['candidate_image_id'] == current_core_image(), 'Installed current candidate required')
    for kind in ('core_test', 'node_test', 'refresh_grace_test', 'replacement'):
        ref = installed[kind]; path = ROOT / ref['path']
        need(sha(path) == ref['sha256'] and read(path)['passed'], 'Installed qualification changed')
    replacement = read(ROOT / installed['replacement']['path'])
    need(replacement['committed'] and replacement['old_image_retired'] == installed['previous_image'], 'Old image not retired after rollback qualification')
    build_path = ROOT / 'evidence/operations/password-session-build' / installed['session_build'] / 'report.json'
    build = read(build_path); current_folder = validate_pair(ROOT, build)
    previous = build['previous_build']; old_path = ROOT / previous['path']
    need(previous['mode'] == 'new-candidate' and sha(old_path) == previous['sha256'], 'Previous pair provenance differs')
    old = read(old_path); old_folder = validate_pair(ROOT, old)
    need(old_folder != current_folder and old['candidates'] == previous['candidates'], 'Retirement target is not superseded')
    for row in build['candidates']:
        location = ('lib/' if row['component'] == 'core' else 'plugin/') + Path(row['path']).name
        need(installed['installed_files'][location] == row['sha256'], 'Installed binary differs from retained pair')
    cids = subprocess.check_output(['docker', 'ps', '-aq', '--no-trunc'], timeout=30).decode().splitlines()
    mounts = []
    if cids:
        lines = subprocess.check_output(['docker', 'inspect', '--format', '{{json .Mounts}}', *cids], timeout=30).decode().splitlines()
        mounts = [m for line in lines for m in json.loads(line) if m.get('Type') == 'bind']
    target = old_folder.as_posix().lower()
    for mount in mounts:
        source = mount['Source'].replace('\\', '/').lower().rstrip('/')
        match = re.fullmatch(r'/(?:run/desktop/mnt/host|host_mnt)/([a-z])/(.*)', source)
        if match: source = match[1] + ':/' + match[2]
        need(not (source == target or target.startswith(source + '/') or source.startswith(target + '/')), 'Superseded pair may still be mounted')
    for row in old['candidates']:
        members = read(old_path.parent / (row['component'] + '-members.json'))
        with zipfile.ZipFile(ROOT / row['path']) as archive:
            need(archive.testzip() is None and len(archive.namelist()) == len(members) and
                 all(hashlib.sha256(archive.read(m['path'])).hexdigest() == m['sha256'] for m in members), 'Old JAR member provenance differs')
    report = {'kind': 'qualified-superseded-password-session-pair-retirement', 'passed': False,
        'image_build': {'path': image_path.relative_to(ROOT).as_posix(), 'sha256': sha(image_path)},
        'retired': old['candidates'], 'retained': build['candidates'], 'superseded_pair_unmounted': True,
        'source_and_historical_build_evidence_preserved': True, 'tool_sha256': sha(Path(__file__))}
    def persist(): output.write_bytes((json.dumps(report, indent=2) + '\n').encode())
    persist()
    # Exact validated files, no recursive deletion or unrelated cache cleanup.
    for row in old['candidates']: (ROOT / row['path']).unlink()
    old_folder.rmdir()
    report['passed'] = not old_folder.exists() and validate_pair(ROOT, build) == current_folder
    report['retired_bytes'] = sum(r['bytes'] for r in old['candidates']); persist()
    print(json.dumps({'passed': report['passed'], 'retired_bytes': report['retired_bytes']}))

if __name__ == '__main__': main()
