"""Bind installed-native reports to exact source and retained command bytes.

Offline correspondence only: this never reruns or substitutes for authentication.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = 'evidence/operations/atomic-core-image/native-01'
PEER = 'evidence/foundation/refresh-grace/native-installed-peer-01'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def main():
    checks = []

    def check(name, passed):
        checks.append({'check': name, 'passed': bool(passed)})

    build = read(BUILD + '/report.json')
    peer = read(PEER + '/report.json')
    changed = {'tools/run_refresh_grace_lab.py', 'tests/foundation/NativePasswordProbe.java'}
    actual_changes = set()
    for name, digest in build['source_inputs'].items():
        current = ROOT / name
        if not current.is_file() or sha(current) != digest:
            actual_changes.add(name)
            snapshot = ROOT / BUILD / 'source-snapshots' / name
            check('build snapshot: ' + name, snapshot.is_file() and sha(snapshot) == digest)
        else:
            check('build input: ' + name, True)
    check('only separately qualified peer harness changed', actual_changes == changed)
    for name, digest in peer['inputs'].items():
        check('peer input: ' + name, (ROOT / name).is_file() and sha(ROOT / name) == digest)
    check('peer ran current changed harness', changed.issubset(peer['inputs']))
    check('installed peer used unchanged image', peer['images']['core'] == peer['images']['native_reference_core'] == build['candidate_image_id'])
    check('peer no overlays or resources', peer['passed'] and peer['inputs_unchanged'] and peer['source_unchanged']
          and peer['resources_unchanged'] and not peer['native_dependency_overlay'] and peer['native_peer_profile'] == 'installed-source'
          and len(peer['created_containers']) == len(peer['retired_containers']) == 5)
    for role in ('core-a', 'core-b'):
        check('actual installed native mapping: ' + role, any('/opt/expertauth/native/libargon2.so' in line for line in peer['native_process_mappings'][role]))
    native_rows = read(PEER + '/native-password-report.json')
    check('peer report bound', sha(ROOT / PEER / 'native-password-report.json') == peer['native_password_sha256'])
    check('peer eleven passed rows, not full migration', native_rows['passed'] and len(native_rows['rows']) == 11
          and all(row['status'] == 'passed' for row in native_rows['rows']) and not native_rows['full_migration_qualified'])
    for key in ('native_startup_test', 'native_password_test', 'guarded_session_test', 'core_test', 'node_test', 'refresh_grace_test', 'replacement'):
        ref = build[key]
        check('bound actual report: ' + key, sha(ROOT / ref['path']) == ref['sha256'] and read(ref['path'])['passed'])
    for command in build['commands']:
        retired_lookup = (command['argv'][:3] == ['docker', 'inspect', '--format']
                          and command['argv'][-1] in build['helpers_retired']
                          and command['exit_code'] == 1 and not command.get('timed_out'))
        if retired_lookup:
            diagnostic = (ROOT / BUILD / command['stderr']['path']).read_text().strip()
            check('retired helper inspection reports exact absence', diagnostic == 'Error: No such object: ' + command['argv'][-1])
        else:
            check('build command returned zero', command['exit_code'] == 0)
        for channel in ('stdout', 'stderr'):
            record = command.get(channel, {})
            if 'path' in record:
                path = ROOT / BUILD / record['path']
                check('retained command: ' + record['path'], path.stat().st_size == record['bytes'] and sha(path) == record['sha256'])
    installed = build['installed_files']
    original = build['original_installed_files']
    check('exact installed manifest count', len(installed) == 554)
    check('native-only bundle removed', 'lib/argon2-jvm-2.11.jar' not in installed and len([p for p in installed if p.endswith('.jar')]) == 86)
    for name in ('lib/argon2-jvm-nolibs-2.11.jar', 'lib/jna-5.8.0.jar'):
        check('unchanged Java dependency: ' + name, installed[name] == original[name])
    check('native candidate matches source build', installed['native/libargon2.so'] == build['native_argon2']['library']['sha256'])
    source_map = read('reuse/native-argon2-components.json')
    for row in source_map['files']:
        check('installed corresponding source: ' + row['source_path'], installed['licenses/expertauth/native-argon2/source/' + row['source_path']] == row['sha256'] == sha(ROOT / row['path']))
    bom = read(BUILD + '/adaptation-runtime.cdx.json')
    check('SBOM replacement', len(bom['components']) == 87 and not any(c.get('name') == 'argon2-jvm' for c in bom['components'])
          and len([c for c in bom['components'] if c.get('name') == 'phc-winner-argon2']) == 1)
    replacement = read(build['replacement']['path'])
    check('actual upgrade/rollback committed and retired old image', replacement['passed'] and replacement['committed']
          and replacement['old_image_retired'] == build['previous_image'] and replacement['installed_files_verified'] == 554)
    check('database/schema preserved', replacement['database_before'] == replacement['database_after']
          and replacement['schema_before_sha256'] == replacement['schema_after_sha256'] and not replacement['fixture_cleanup_pending'])
    report = {'kind': 'installed-native-source-evidence-correspondence', 'passed': all(r['passed'] for r in checks),
              'authentication_test_execution': False, 'complete': False, 'independent_review': False,
              'checks': checks, 'build_report_sha256': sha(ROOT / BUILD / 'report.json'),
              'peer_report_sha256': sha(ROOT / PEER / 'report.json'), 'verifier_sha256': sha(Path(__file__)),
              'changed_harness_qualified_separately': sorted(changed)}
    output = ROOT / 'evidence/operations/native-argon2-installation/correspondence-02.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2); stream.write('\n')
    reuse = {'kind': 'installed-native-argon2-file-specific-reuse', 'complete': False, 'distribution_approved': False,
             'upstream_native': source_map['files'], 'installed_image': build['candidate_image_id'],
             'installed_files': {p: v for p, v in installed.items() if p.startswith(('native/', 'licenses/expertauth/native-argon2/'))},
             'removed_native_bundle': build['native_argon2']['removed_native_bundle'],
             'unchanged_java_dependencies': [{'path': name, 'sha256': installed[name], 'license': license_name}
                 for name, license_name in [('lib/argon2-jvm-nolibs-2.11.jar', 'LGPL-3.0'), ('lib/jna-5.8.0.jar', 'Apache-2.0 OR LGPL-2.1-or-later')]],
             'original_integration_sources': [{'path': name, 'sha256': sha(ROOT / name), 'license': 'Apache-2.0'}
                 for name in ['tools/install_native_argon2.py', 'tools/qualify_native_startup.py', 'deploy/native-argon2-start.sh', 'deploy/NativeArgon2Check.java']],
             'license_sources': ['https://raw.githubusercontent.com/phxql/argon2-jvm/v2.11/LICENSE.txt',
                 'https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/LICENSE'],
             'limits': ['No native primitive or upstream wrapper code modified.', 'LGPL3 includes GPL3 terms; the wrapper is not described as GPL-only.',
                 'PHC public known-answer vector in the startup check uses the retained CC0 source grant.',
                 'Remaining native, wrapper, OS, source/relink, maintained-version and independent distribution review remain open.']}
    reuse_path = ROOT / 'reuse/installed-native-argon2.json'
    if reuse_path.exists():
        assert json.loads(reuse_path.read_text()) == reuse, 'Existing reuse mapping differs'
    else:
        with reuse_path.open('x', encoding='utf-8') as stream:
            json.dump(reuse, stream, indent=2); stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'failed': [r['check'] for r in checks if not r['passed']]}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
