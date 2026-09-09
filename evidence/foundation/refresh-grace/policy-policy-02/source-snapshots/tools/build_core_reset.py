"""Compile an explicit Apache Core adaptation without images or dependency fetch.

One bounded offline compiler container, one retained candidate JAR. The original
audited sources, build, images and running services remain untouched. Compilation
and byte correspondence do not qualify the extension's runtime behavior.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE_REV = 'b2219c4aa019a501e4dfea76cf06ef802ca93fc0'
IMAGE = 'sha256:5ec6ccc3fd5dc7eff16afa48b3bf6abdd4d378077f2428cae3abf8a8bc2e30bf'
WEB = 'src/main/java/io/supertokens/webserver/Webserver.java'
JAVA = ['engine-extensions/core-reset/src/io/expertauth/core/' + name for name in
        ('AtomicPasswordReset.java', 'AtomicPasswordResetAPI.java')]


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.name), 'Invalid evidence name')
    output = ROOT / 'evidence/operations/core-reset-build' / args.name
    cache = (ROOT / '.cache/core-reset').resolve()
    private = (ROOT / '.runtime/core-reset-build' / args.name).resolve()
    need(not output.exists() and not private.exists() and not cache.exists(),
         'Preserve existing evidence/candidate; inspect its owner before another build')
    need(private.is_relative_to(ROOT / '.runtime/core-reset-build') and cache.parent == ROOT / '.cache', 'Workspace boundary differs')
    output.mkdir(parents=True); private.mkdir(parents=True); cache.mkdir(parents=True)
    run_id = uuid.uuid4().hex
    name = 'expertauth-core-reset-compile-' + run_id[:10]
    labels = {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': 'core-reset-compile', 'org.expertauth.build-run': run_id}
    sources = ['tools/build_core_reset.py', *JAVA]
    report = {'kind': 'core-reset-candidate-build', 'passed': False, 'runtime_qualified': False,
              'foundation_passed': False, 'full_distribution_approved': False,
              'started': datetime.now(timezone.utc).isoformat(), 'inputs': {p: sha(ROOT / p) for p in sources},
              'commands': [], 'errors': [], 'container_name': name, 'container_retired': False,
              'images_built': 0, 'dependency_downloads': 0, 'new_networks': 0, 'new_volumes': 0}
    for source in sources:
        target = output / 'source-snapshots' / source
        target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((ROOT / source).read_bytes())

    def persist():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def call(argv, timeout=35, required=True):
        row = {'argv': argv, 'exit_code': None, 'timed_out': False}; report['commands'].append(row)
        result = None
        try:
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
            row['exit_code'] = result.returncode
            raw = result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            row['timed_out'] = True; raw = (error.stdout or b'') + (error.stderr or b'')
        path = output / f'command-{len(report["commands"]):03d}.log'
        path.write_bytes(raw); row.update({'log': path.name, 'bytes': len(raw), 'sha256': sha(path)})
        persist()
        need(result is not None, 'Command timed out: ' + path.name)
        need(not required or result.returncode == 0, 'Command failed: ' + path.name)
        return result

    def inventory():
        return {key: sorted(set(call(['docker', *argv]).stdout.decode().splitlines())) for key, argv in {
            'containers': ['ps', '-aq', '--no-trunc'], 'images': ['image', 'ls', '-aq', '--no-trunc'],
            'networks': ['network', 'ls', '-q', '--no-trunc'], 'volumes': ['volume', 'ls', '-q']}.items()}

    before = cid = None
    try:
        before = report['resources_before'] = inventory()
        state = json.loads(call(['docker', 'image', 'inspect', IMAGE]).stdout)[0]
        need(state['Id'] == IMAGE and set(state['Config'].get('Volumes') or {}) == {'/home/gradle/.gradle'} and
             state['Config'].get('Labels', {}).get('org.expertauth.project') == 'expert-auth', 'Cached Core image differs')
        upstream = ROOT / '.cache/reuse-audit/source/supertokens__supertokens-core' / CORE_REV / WEB
        manifest = json.loads((ROOT / 'reuse/files/supertokens__supertokens-core.json').read_text())
        need(manifest['commit'] == CORE_REV, 'Core audit revision differs')
        expected = next(row['sha256'] for row in manifest['files'] if row['source_path'] == WEB)
        need(sha(upstream) == expected and b'Apache License, Version 2.0' in upstream.read_bytes(), 'Original Webserver source differs')
        original = upstream.read_bytes()
        insertion = b'        addAPI(new ResetPasswordAPI(main));'
        need(original.count(insertion) == 1 and b'WithinOtelSpan' not in original, 'Unexpected registration or annotated weaving boundary')
        patched = original.replace(insertion, insertion + b'\n        addAPI(new io.expertauth.core.AtomicPasswordResetAPI(main, true));\n        addAPI(new io.expertauth.core.AtomicPasswordResetAPI(main, false));')
        (private / 'Webserver.java').write_bytes(patched)
        (output / 'Webserver.java').write_bytes(patched)
        report['upstream'] = {'repository': 'supertokens/supertokens-core', 'commit': CORE_REV, 'path': WEB,
                              'sha256': expected, 'license': 'Apache-2.0', 'modified_source_sha256': sha(private / 'Webserver.java'),
                              'modification': 'Register two private APIs; existing routes, authorization and entitlement checks unchanged'}
        jar = ROOT / '.cache/engine-build/supertokens-core/build/libs/core-12.2.0.jar'
        artifacts = json.loads((ROOT / 'evidence/build/oss-core/artifacts.json').read_text())
        expected_jar = next(row['sha256'] for row in artifacts if row['path'] == 'supertokens-core/build/libs/core-12.2.0.jar')
        need(sha(jar) == expected_jar, 'Original source-built Core JAR differs')
        argv = ['docker', 'run', '--rm', '--pull=never', '--name', name, '--cidfile', str(private / 'container.cid'),
                '--network=none', '--read-only', '--memory=512m', '--cpus=2', '--pids-limit=128', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                '--tmpfs', '/home/gradle/.gradle:rw,nosuid,nodev,noexec,size=1m']
        for key, value in labels.items(): argv += ['--label', key + '=' + value]
        argv += ['--mount', f'type=bind,source={private},target=/out']
        for index, source in enumerate(JAVA):
            argv += ['--mount', f'type=bind,source={ROOT/source},target=/src/{Path(source).name},readonly']
        compile_command = ('java --version && javac --version && sha256sum /opt/expertauth/lib/core-12.2.0.jar && '
            'javap -p -classpath /opt/expertauth/lib/core-12.2.0.jar io.supertokens.webserver.Webserver && '
            "javac -proc:none --release 21 -encoding UTF-8 -cp '/opt/expertauth/lib/*:/opt/expertauth/plugin/*' "
            '-d /out/classes /out/Webserver.java /src/AtomicPasswordReset.java /src/AtomicPasswordResetAPI.java')
        argv += ['--entrypoint', 'sh', IMAGE, '-eu', '-c', compile_command]
        result = call(argv, timeout=100)
        need(expected_jar.encode() in result.stdout and b'ajc$' not in result.stdout, 'Actual compiler Core or Webserver weaving differs')
        compiled = {p.relative_to(private / 'classes').as_posix(): p.read_bytes() for p in (private / 'classes').rglob('*.class')}
        report['compiled_classes'] = {name: {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                                      for name, body in sorted(compiled.items())}
        persist()
        need(compiled and 'io/expertauth/core/AtomicPasswordReset.class' in compiled and 'io/supertokens/webserver/Webserver.class' in compiled,
             'Required compiled classes missing')
        need(all(key.startswith('io/expertauth/core/AtomicPasswordReset') or
                 re.fullmatch(r'io/supertokens/webserver/Webserver(?:\$TomcatReference)?\.class', key) for key in compiled), 'Unexpected compiled class')
        output_jar = cache / 'core-12.2.0-atomic-reset.jar'
        members = []
        with zipfile.ZipFile(jar) as old, zipfile.ZipFile(output_jar, 'x', compression=zipfile.ZIP_DEFLATED) as new:
            need(old.testzip() is None and len(old.namelist()) == len(set(old.namelist())), 'Original JAR invalid')
            for member in old.infolist():
                need(not member.filename.startswith(('io/supertokens/ee/', 'ee/')), 'Restricted member')
                previous = old.read(member)
                body = compiled.pop(member.filename, previous)
                new.writestr(member, body)
                members.append({'path': member.filename, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                                'original_sha256': hashlib.sha256(previous).hexdigest(), 'changed': body != previous})
            for name_in_jar, body in sorted(compiled.items()):
                need(name_in_jar.startswith('io/expertauth/core/'), 'Unexpected new upstream class')
                member = zipfile.ZipInfo(name_in_jar, date_time=(1980, 1, 1, 0, 0, 0)); member.external_attr = 0o100644 << 16
                member.compress_type = zipfile.ZIP_DEFLATED; new.writestr(member, body)
                members.append({'path': name_in_jar, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'added': True})
        with zipfile.ZipFile(output_jar) as candidate:
            need(candidate.testzip() is None and len(candidate.namelist()) == len(members), 'Candidate JAR invalid')
        (output / 'jar-members.json').write_text(json.dumps(members, indent=2) + '\n')
        report['candidate'] = {'path': output_jar.relative_to(ROOT).as_posix(), 'bytes': output_jar.stat().st_size,
                               'sha256': sha(output_jar), 'original_sha256': expected_jar,
                               'unchanged_members': sum(not row.get('changed') and not row.get('added') for row in members),
                               'changed_members': [row['path'] for row in members if row.get('changed')],
                               'added_members': [row['path'] for row in members if row.get('added')]}
        report['build_passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        try:
            if (private / 'container.cid').exists():
                cid = (private / 'container.cid').read_text().strip(); need(re.fullmatch('[0-9a-f]{64}', cid), 'Invalid cleanup ID')
                found = call(['docker', 'inspect', '--format', '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}', cid], required=False)
                if found.returncode == 0:
                    state = json.loads(found.stdout)
                    need(state['id'] == cid and state['name'] == '/' + name and state['image'] == IMAGE and
                         all((state['labels'] or {}).get(k) == v for k, v in labels.items()), 'Compiler ownership differs')
                    call(['docker', 'rm', '-f', cid], required=False)
                need(not call(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'id=' + cid]).stdout.strip(), 'Compiler container remains')
            need(not call(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip(), 'Named compiler remains')
            report['container_id'] = cid; report['container_retired'] = True
            # Only this fresh, exact workspace scratch directory is eligible.
            paths = list(private.rglob('*'))
            need(private.resolve().parent == (ROOT / '.runtime/core-reset-build').resolve() and
                 all(not p.is_symlink() and not getattr(p.lstat(), 'st_file_attributes', 0) & 0x400 and p.resolve().is_relative_to(private) for p in paths),
                 'Unsafe compile scratch cleanup boundary')
            for p in paths:
                if p.is_file(): p.unlink()
            for p in sorted((p for p in paths if p.is_dir()), key=lambda p: len(p.parts), reverse=True): p.rmdir()
            private.rmdir(); report['private_scratch_removed'] = True
            if not list(cache.iterdir()): cache.rmdir()
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, ValueError) else 'Cleanup failed: ' + type(error).__name__)
        try:
            report['resources_after'] = inventory()
            report['resources_unchanged'] = before == report['resources_after']
            report['inputs_unchanged'] = report['inputs'] == {p: sha(ROOT / p) for p in sources}
            need(report['resources_unchanged'] and report['inputs_unchanged'], 'Inputs or Docker resources changed')
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
        report['passed'] = not report['errors'] and report.get('build_passed') is True and report['container_retired']
        report['finished'] = datetime.now(timezone.utc).isoformat(); persist()
    print(json.dumps({'passed': report['passed'], 'runtime_qualified': False, 'errors': report['errors'],
                      'report': output.relative_to(ROOT).as_posix(), 'container_retired': report['container_retired']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
