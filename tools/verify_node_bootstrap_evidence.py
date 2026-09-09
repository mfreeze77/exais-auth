"""Check the bounded registry/bootstrap proof's actual source and command bytes.

Read-only except for a fresh report. These are evidence-integrity checks, not new
authentication tests or independent review. Historical Dockerfile drift is
explicitly limited to the subsequently tested public-directory permission fix.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'evidence/operations/node-bootstrap/fresh-registry-03'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    target = (ROOT / args.output).resolve()
    assert target.is_relative_to(ROOT / 'evidence') and not target.exists()
    report = {'passed': False, 'kind': 'recorded-bootstrap-evidence-integrity',
              'started': datetime.now(timezone.utc).isoformat(),
              'tool_sha256': sha(Path(__file__).read_bytes()), 'checks': [], 'errors': [],
              'authentication_complete': False, 'independent_human_review': False,
              'bound_files': {}, 'historical_dockerfile_difference': None}

    def need(name, value):
        report['checks'].append({'name': name, 'passed': bool(value)})
        if not value:
            raise ValueError(name)

    def bound(path):
        body = path.read_bytes()
        report['bound_files'][path.relative_to(ROOT).as_posix()] = {'bytes': len(body), 'sha256': sha(body)}
        return body

    try:
        host = json.loads(bound(RUN / 'report.json'))
        for name, expected in host['inputs'].items():
            binding = host['source_bindings'][name]
            body = (subprocess.check_output(['git', 'show', binding['git_commit'] + ':' + name], cwd=ROOT, timeout=15)
                    if 'git_commit' in binding else bound(ROOT / binding['path']))
            need('executed source binding ' + name, sha(body) == expected == binding['sha256'])
            current = bound(ROOT / name)
            if name == 'examples/node-react/Dockerfile':
                expected_current = body.replace(b'COPY --chmod=0644 public/index.html',
                                               b'RUN --network=none mkdir -m 0755 public\nCOPY --chmod=0644 public/index.html')
                need('only disclosed historical Dockerfile directory fix', current == expected_current)
                report['historical_dockerfile_difference'] = 'Added RUN --network=none mkdir -m 0755 public; current image separately qualified'
            else:
                need('current source unchanged ' + name, sha(current) == expected)
        for index, command in enumerate(host['commands'], 1):
            for stream in ('stdout', 'stderr'):
                row = command[stream]
                body = bound(RUN / row['path'])
                need(f'actual Docker command {index} {stream}', len(body) == row['bytes'] and sha(body) == row['sha256'])
        for stage, count in [('online', 3), ('offline', 8)]:
            probe = json.loads(bound(RUN / (stage + '-probe.json')))
            need(stage + ' actual cases', probe['passed'] and probe['skipped'] == 0 and len(probe['rows']) == count and
                 all(row['status'] == 'passed' for row in probe['rows']))
            need(stage + ' exact source pins', all(host['inputs'][name] == value for name, value in probe['source_sha256'].items()))
            need(stage + ' no wider acceptance claim', not probe['foundation_passed'] and not probe['fresh_stack_deployment_qualified'] and not probe['license_approval'])
        commands = json.loads(bound(RUN / 'offline-commands.json'))
        need('actual install then compile', len(commands) == 2 and commands[0]['argv'][2] == 'ci' and
             '--offline' in commands[0]['argv'] and '--ignore-scripts' in commands[0]['argv'] and commands[1]['argv'] == ['node', 'build.mjs'])
        for index, command in enumerate(commands):
            need('successful offline command ' + str(index), command['exit_code'] == 0 and command['signal'] is None and command['spawn_error_code'] is None)
            for stream in ('stdout', 'stderr'):
                need(f'offline command {index} {stream} bytes', sha(bound(RUN / f'offline-command-{index}.{stream}')) == command[stream + '_sha256'])
        audit = json.loads(bound(RUN / 'fresh-runtime-report.json'))
        previous = read(ROOT / 'evidence/operations/node-image-build/offline-build-02/candidate-runtime/runtime-report.json')
        need('complete installed dependency tree unchanged', audit['dependency_files'] == previous['dependency_files'] and audit['dependency_directories'] == previous['dependency_directories'])
        need('explicit normalized app modes and unchanged bytes', audit['app_files'] == [{**row, 'mode': 0o644} for row in previous['app_files']])
        need('all original package members correspond', audit['ok'] and audit['tar_correspondence']['verified'] and
             audit['tar_correspondence']['matched_files'] == 7629 and len(audit['packages']) == 143 and all(audit['tar_correspondence'][k] == 0 for k in
             ['missing_files', 'different_files', 'extra_installed_files', 'unsupported_entries', 'failed_archives']))
        need('offline phase disconnected and resources preserved', host['passed'] and host['offline_networks'] == {} and
             host['container_retired'] and host['resources_unchanged'] and host['resources_before'] == host['resources_after'] and host['inputs_unchanged'])
        for path in RUN.glob('*.json'):
            bound(path)
        report['passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    report['finished'] = datetime.now(timezone.utc).isoformat()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'errors': report['errors'], 'report': target.relative_to(ROOT).as_posix()}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
