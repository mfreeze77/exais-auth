"""Verify the recorded Node build bytes, sources and private command logs.

Read-only except for one fresh report. This checks evidence integrity, not new
authentication behavior or independent human review. Requires retained local
Git history, the generated bundle and the exact private reset command logs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(body):
    return hashlib.sha256(body).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--build-name', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.build_name), 'Invalid build name')
    build_directory = ROOT / 'evidence/operations/node-image-build' / args.build_name
    reset_directory = ROOT / 'evidence/operations/password-reset' / ('installed-' + args.build_name)
    private_directory = ROOT / '.runtime/password-reset' / ('installed-' + args.build_name)
    destination = (ROOT / args.output).resolve()
    need(destination.is_relative_to((ROOT / 'evidence').resolve()) and not destination.exists(), 'Fresh evidence output required')
    result = {'schema': 'expertauth-node-build-evidence-integrity-v1', 'passed': False,
              'started': datetime.now(timezone.utc).isoformat(), 'tool_sha256': sha(Path(__file__)),
              'authentication_complete': False, 'independent_human_review': False,
              'checks': [], 'errors': [], 'private_values_disclosed': False}

    def check(name, value, **detail):
        result['checks'].append({'name': name, 'passed': bool(value), **detail})
        need(value, name)

    try:
        build = read(build_directory / 'report.json')
        atomic = bool(build.get('password_session_build'))
        if atomic:
            reset_directory = ROOT/'evidence/operations/password-reset'/('atomic-installed-'+args.build_name)
            private_directory = ROOT/'.runtime/password-reset'/('atomic-installed-'+args.build_name)
        reset = read(reset_directory / 'report.json')
        result['reports'] = {p.relative_to(ROOT).as_posix(): sha(p) for p in [build_directory / 'report.json', reset_directory / 'report.json']}
        check('build binds exact reset child', build['reset_report']['path']==(reset_directory/'report.json').relative_to(ROOT).as_posix() and
              build['reset_report']['sha256']==sha(reset_directory/'report.json'))
        for name, expected in build['input_sha256'].items():
            check('current build input ' + name, sha(ROOT / name) == expected)
            binding = build['source_bindings'][name]
            if 'git_commit' in binding:
                body = subprocess.check_output(['git', 'show', binding['git_commit'] + ':' + name], cwd=ROOT, timeout=15)
                check('Git source binding ' + name, digest(body) == expected)
            elif 'path' in binding:
                check('captured source binding ' + name, sha(ROOT / binding['path']) == expected)
            else:
                check('generated bundle binding', name == 'examples/node-react/public/app.js' and binding['sha256'] == expected)
        for row in build['commands']:
            check('build command log ' + row['log'], sha(build_directory / row['log']) == row['sha256'])
        for stream in ('stdout', 'stderr'):
            row = build['reset_child'][stream]
            check('child output ' + stream, sha(build_directory / row['path']) == row['sha256'])
        for index, row in enumerate(reset['commands'], 1):
            for stream in ('stdout', 'stderr'):
                path = private_directory / f'command-{index:03d}.{stream}'
                check(f'private reset command {index} {stream}', sha(path) == row[stream]['sha256'] and path.stat().st_size == row[stream]['bytes'])
        check('reset inputs match current bytes', all(sha(ROOT / name) == value for name, value in reset['inputs'].items()))
        previous, candidate = (read(build_directory / kind / 'runtime-report.json') for kind in ('previous-runtime', 'candidate-runtime'))
        for key in ('dependency_files', 'dependency_directories'):
            check('unchanged installed ' + key, candidate[key] == previous[key])
        for report in (previous, candidate):
            for key in ('app_files', 'dependency_files'):
                actual = digest(json.dumps(report[key], ensure_ascii=False, separators=(',', ':')).encode())
                check('canonical runtime inventory hash ' + key, actual == report[key + '_sha256'])
        check('original archive correspondence', candidate['ok'] and candidate['tar_correspondence']['verified'] and
              candidate['tar_correspondence']['matched_files'] == 7629 and all(candidate['tar_correspondence'][k] == 0 for k in
              ('missing_files', 'different_files', 'extra_installed_files', 'unsupported_entries', 'failed_archives')),
              packages=len(candidate['packages']), matched_members=7629, separately_reported_mode_differences=candidate['tar_correspondence']['mode_differences'])
        check('installed app source and bundle', len(candidate['app_files']) == 8 and all(
              row['type'] == 'file' and sha(ROOT / 'examples/node-react' / row['path']) == row['sha256'] for row in candidate['app_files']))
        if build.get('installed_app_file_mode') is not None:
            check('deterministic application file permissions', build['installed_app_file_mode'] == '0644' and
                  all(row['mode'] == 0o644 for row in candidate['app_files']))
        transport = read(reset_directory / 'tls-results.json')
        check('actual recorded transport cases', transport['passed'] and len(transport['checks']) == 10 and
              all(row['passed'] is True for row in transport['checks']), checks=10)
        for filename in ('probe-results.json', 'browser-results.json'):
            report = read(reset_directory / filename)
            check('actual recorded cases ' + filename, bool(report['rows']) and all(row['status'] == 'passed' for row in report['rows']), rows=len(report['rows']))
        probe = read(reset_directory / 'probe-results.json')
        cleanup = probe['rows'][-1]
        check('exact original fixture set restored', cleanup['original_identity_set_restored'] and cleanup['source_identity_count'] == (0 if atomic else 52) and cleanup['owned_fixture_count'] == (22 if atomic else 11))
        check('normal installed-image run', reset['passed'] and reset['installed_image_tested'] and not reset['foundation_passed'] and not reset['full_PWD_006_qualified'])
        check('owned temporary container accounting', len(reset['created_containers']) == len(reset['retired_containers']) == (16 if atomic else 12) and len(build['temporary_containers_retired']) == 4 and
              {row['id'] for row in reset['created_containers']}=={row['id'] for row in reset['retired_containers']})
        if atomic:
            parent_directory=ROOT/'evidence/operations/atomic-reset'/('installed-'+args.build_name)
            parent=read(parent_directory/'report.json')
            result['reports'][(parent_directory/'report.json').relative_to(ROOT).as_posix()]=sha(parent_directory/'report.json')
            check('exact atomic parent-child chain',build['atomic_parent_report']['path']==(parent_directory/'report.json').relative_to(ROOT).as_posix() and
                  build['atomic_parent_report']['sha256']==sha(parent_directory/'report.json') and parent['node_child']['sha256']==sha(reset_directory/'report.json'))
            check('installed immutable Node image throughout',parent['installed_node_image']==reset['images']['node']==build['candidate_image_id'])
            check('atomic parent resources and original database preserved',parent['passed'] and not parent['source_database_contacted'] and parent['source_unchanged'] and
                  parent['resources_unchanged'] and parent['inputs_unchanged'] and len(parent['created_containers'])==3 and
                  {row['id'] for row in parent['created_containers']}=={row['id'] for row in parent['retired_containers']})
            for name,expected in parent['inputs'].items():
                check('current and captured atomic parent source '+name,sha(ROOT/name)==sha(parent_directory/'source-snapshots'/name)==expected)
            for index,row in enumerate(parent['commands'],1):
                for stream in ('stdout','stderr'):
                    path=ROOT/'.runtime/atomic-reset'/('installed-'+args.build_name)/f'command-{index:03d}.{stream}'
                    check(f'private atomic parent command {index} {stream}',sha(path)==row[stream]['sha256'] and path.stat().st_size==row[stream]['bytes'])
            session_build=read(ROOT/'evidence/operations/password-session-build'/build['password_session_build']/'report.json')
            artifacts={row['component']:row for row in session_build['candidates']}
            check('same qualified two-JAR candidate',parent['core_artifacts']==session_build['candidates'] and
                  all(sha(ROOT/row['path'])==row['sha256'] for row in artifacts.values()))
            original={Path(row['path']).name:row['sha256'] for row in read(ROOT/'evidence/build/oss-core/artifacts.json')}
            core_file='/opt/expertauth/lib/core-12.2.0.jar'
            plugin_file='/opt/expertauth/plugin/'+Path(artifacts['postgresql']['path']).name
            combinations={'expiry-core':{core_file:artifacts['core']['sha256'],plugin_file:artifacts['postgresql']['sha256']},
                          'unsupported-core':{core_file:original['core-12.2.0.jar'],plugin_file:original[Path(plugin_file).name]},
                          'missing-writer-core':{core_file:artifacts['core']['sha256'],plugin_file:original[Path(plugin_file).name]}}
            check('actual full, old and missing-writer deployment binaries',reset['deployment_core_files']==combinations)
            check('all atomic HTTP cases executed',probe['passed'] and probe['skipped']==0 and len(probe['rows'])==18 and all(row['status']=='passed' for row in probe['rows']))
            rejected=next(row for row in probe['rows'] if row['id']=='PASSWORD-SESSION-MISSING-WRITER-FAILS-CLOSED')
            check('missing writer actually rejects and recovers',rejected['status']=='passed' and
                  [rejected[key] for key in ('live_http','ready_http','signin_http','core_http')]==[200,503,500,503] and
                  all(rejected[key] for key in
                      ('no_auth_tokens_or_cookies','no_legacy_session_call','prior_session_preserved','no_failed_insert','healthy_writer_retry')))
            for role,code,status,count in [('good',200,'OK',38),('missing-writer',503,'PASSWORD_SESSION_REJECTED',1)]:
                wire=[json.loads(line) for line in (reset_directory/'wire'/(role+'.jsonl')).read_text().splitlines()]
                check('actual bounded wire observations '+role,len(wire)==count and all(set(row)=={'path','http','status','policy'} and
                      row['path']=='/expertauth/password/session' and row['http']==code and row['status']==status and
                      row['policy']==('EXPERTAUTH-PASSWORD-SESSION-1' if role=='good' else 'OTHER') for row in wire))
        check('build success with source/resource preservation', build['passed'] and build['image_promoted'] and build['private_scratch_removed'] and all(
              build[key] for key in ('resources_after_unchanged', 'source_after_unchanged', 'private_configuration_after_unchanged', 'inputs_after_unchanged', 'cache_after_unchanged')))
        check('foundation and licensing remain unqualified', not build['foundation_passed'] and not build['full_distribution_approved'] and not candidate['license_approval'] and not candidate['native_compiled_source_correspondence_verified'])
        result['passed'] = True
    except Exception as error:
        result['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    result['finished'] = datetime.now(timezone.utc).isoformat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': result['passed'], 'checks': len(result['checks']), 'errors': result['errors'], 'report': destination.relative_to(ROOT).as_posix()}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
