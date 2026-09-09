"""Check checkpoint evidence correspondence; does not execute authentication."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from install_bouncycastle import inputs as bc_inputs

ROOT = Path(__file__).resolve().parents[1]


def main():
    output = ROOT / 'evidence/operations/bouncycastle-installation/pause-correspondence.json'
    assert not output.exists(), 'Preserve prior evidence'
    def read(path): return json.loads((ROOT / path).read_text(encoding='utf-8'))
    def sha(path): return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    report = {'kind': 'firebase-pause-evidence-correspondence', 'passed': False,
              'complete': False, 'authentication_execution': False,
              'utc': datetime.now(timezone.utc).isoformat(), 'checks': [], 'errors': [],
              'tool_sha256': sha(Path(__file__))}
    def check(name, value):
        report['checks'].append({'check': name, 'passed': bool(value)})
        if not value: raise ValueError(name)
    try:
        build = read('evidence/operations/password-session-build/firebase-bc-02/report.json')
        lab = read('evidence/operations/atomic-reset/firebase-legacy-json-01/report.json')
        image = read('evidence/operations/atomic-core-image/firebase-01/report.json')
        for label, data in [('compiled source', build), ('current historical-peer lab', lab)]:
            check(label + ' passed', data['passed'])
            for path, digest in data['inputs'].items():
                check(label + ': ' + path, sha(path) == digest)
        check('installed image qualified', image['passed'] and image['installed_qualification_passed'])
        for key in ('native_startup_test', 'native_password_test', 'firebase_test',
                    'guarded_session_test', 'core_test', 'node_test', 'refresh_grace_test', 'replacement'):
            ref = image[key]
            check(key + ' bound and passed', sha(ref['path']) == ref['sha256'] and read(ref['path'])['passed'])
        changed = [p for p, h in image['source_inputs'].items() if sha(p) != h]
        check('only disclosed post-install harness changes', set(changed) == {
            'tools/build_atomic_core_runtime.py', 'tools/run_atomic_reset_lab.py',
            'tests/foundation/FirebaseScryptProbe.java'})
        for path, digest in image['source_inputs'].items():
            snapshot = 'evidence/operations/atomic-core-image/firebase-01/source-snapshots/' + path
            check('installed source snapshot: ' + path, sha(snapshot) == digest)
        preflight = read('evidence/operations/bouncycastle-installation/native-reference-preflight.stdout')
        check('current builder read-only preflight', preflight['passed'] and
              preflight['tool_sha256'] == sha('tools/build_atomic_core_runtime.py') and
              preflight['image'] == image['candidate_image_id'] and preflight['selected_build'] == 'firebase-bc-02')
        probe = read('evidence/operations/atomic-reset/firebase-legacy-json-01/firebase-scrypt-report.json')
        check('12 narrow candidate rows, no full pass', len(probe['rows']) == 12 and
              all(r['status'] == 'passed' for r in probe['rows']) and not probe['complete'])
        check('legacy Unicode migration visibly blocked', probe['legacy_json_migration']['status'] == 'blocked'
              and not probe['legacy_json_migration']['authentication_acceptance_pass']
              and not probe['full_migration_qualified'])
        bc_inputs()
        check('pinned BC binary/source/POM cache correspondence', True)
        check('owned historical lab resources restored', lab['resources_unchanged'] and lab['source_unchanged'] and
              len(lab['created_containers']) == len(lab['retired_containers']) == 6)
        check('superseded JAR pair retired', read('evidence/operations/hygiene/password-session-retirement-firebase-01.json')['passed'])
        report['post_install_source_changes'] = changed
        report['passed'] = True
    except Exception as exc:
        report['errors'].append(str(exc))
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
