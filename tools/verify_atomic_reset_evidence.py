"""Read-only source/binary/evidence correspondence; never authentication acceptance."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    checks = []
    def need(value, name):
        checks.append({'check': name, 'passed': bool(value)})
        if not value:
            raise ValueError(name)
    def read(path):
        return json.loads((ROOT / path).read_text())
    folders = ['evidence/operations/core-reset-build/compile-03', 'evidence/operations/atomic-reset/run-02',
               'evidence/operations/atomic-reset/node-03', 'evidence/operations/password-reset/atomic-node-03']
    build, core, parent, child = [read(p + '/report.json') for p in folders]
    report = {'kind': 'atomic-reset-evidence-correspondence', 'passed': False, 'authentication_complete': False,
              'independent_human_review': False, 'checks': checks, 'tool_sha256': sha(Path(__file__)), 'inputs': {}}
    try:
        for folder, result in zip(folders, [build, core, parent, child]):
            need(result['passed'] and not result['foundation_passed'], folder + ' bounded outcome')
            need(result.get('resources_unchanged', result.get('resources_restored')) is True, folder + ' resources restored')
            report['inputs'][folder + '/report.json'] = sha(ROOT / folder / 'report.json')
            for source, expected in result['inputs'].items():
                snapshot = ROOT / folder / 'source-snapshots' / source
                need(snapshot.is_file() and sha(snapshot) == expected, folder + ' snapshot ' + source)
                # Historical runner/reuse metadata differs; the actual security
                # code and every input to the final Node run must still match.
                if folder != folders[1] or source.endswith('.java'):
                    need(sha(ROOT / source) == expected, folder + ' current input ' + source)
        candidate = ROOT / build['candidate']['path']
        expected = build['candidate']['sha256']
        need(sha(candidate) == expected and candidate.stat().st_size == 1254808, 'one exact candidate JAR')
        need(core['compiled_jar_sha256'] == parent['compiled_jar_sha256'] == child['core_adaptation']['jar_sha256'] == expected,
             'all actual probes use the same adapted binary')
        need(parent['node_child']['sha256'] == sha(ROOT / folders[3] / 'report.json'), 'parent binds exact child report')
        members = read(folders[0] + '/jar-members.json')
        with zipfile.ZipFile(candidate) as archive:
            need(archive.testzip() is None and set(archive.namelist()) == {r['path'] for r in members}, 'candidate CRC and member set')
            need(all(hashlib.sha256(archive.read(r['path'])).hexdigest() == r['sha256'] for r in members), 'candidate every member hash')
        need(build['candidate']['unchanged_members'] == 557 and len(build['candidate']['changed_members']) == 2 and
             len(build['candidate']['added_members']) == 3, 'upstream preservation and adaptation footprint')
        core_probe = read(folders[1] + '/probe-report.json')
        need(sha(ROOT / folders[1] / 'probe-report.json') == core['probe_sha256'], 'Core report byte binding')
        need(len(core_probe['rows']) == 8 and all(r['status'] == 'passed' for r in core_probe['rows']), 'eight executed Core cases')
        probe, browser, tls = [read(folders[3] + '/' + name) for name in ['probe-results.json', 'browser-results.json', 'tls-results.json']]
        need(probe['passed'] and probe['skipped'] == 0 and probe['atomic_profile'] is True and
             len(probe['rows']) == 15 and all(r['status'] == 'passed' for r in probe['rows']), 'thirteen HTTP cases plus browser wrapper and fixture cleanup')
        need(len(browser['rows']) == 9 and all(r['status'] == 'passed' for r in browser['rows']), 'nine actual browser cases')
        need(tls['passed'] and len(tls['checks']) == 10, 'ten actual TLS checks')
        need(child['source_before'] == child['source_after'] and not parent['source_database_contacted'], 'persistent database uncontacted and lab source preserved')
        for name, result in [('Core', core), ('Node parent', parent), ('Node child', child)]:
            created = {r['id'] for r in result['created_containers']}
            need(len(created) == len(result['created_containers']) and created == {r['id'] for r in result['retired_containers']}, name + ' every exact container retired')
        reuse = read('engine-extensions/core-reset/reuse.json')
        baseline = {r['id'] for r in read('baseline/expert-auth-full-parity-plan-v1.0/registry/requirements.json')}
        need(set(reuse['mapped_requirements']) <= baseline and 'MIG-001' not in reuse['mapped_requirements'], 'requirement mapping preserves actual scope')
        for row in reuse['upstream_files']:
            repo_name = row['repository'].removeprefix('https://github.com/').replace('/', '__')
            source = ROOT / '.cache/reuse-audit/source' / repo_name / row['commit'] / row['source_path']
            need(sha(source) == row['sha256'] and row['license'] == 'Apache-2.0' and (ROOT / row['notice']).is_file(), 'file-specific source/license ' + row['source_path'])
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error) if isinstance(error, ValueError) else type(error).__name__
    output = ROOT / 'evidence/operations/atomic-reset/evidence-validation.json'
    if output.exists():
        raise ValueError('Preserve previous validation; choose a new evidence path for changed checks')
    output.write_bytes((json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps({'passed': report['passed'], 'checks': len(checks), 'error': report.get('error'), 'authentication_complete': False}))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
