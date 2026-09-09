"""Identify cached Argon2 wrapper/native release bytes; never infer native builds."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/reuse/native-correspondence'
PIN = 'a6a6ecd15c344983d5955cad6c8e7cb73dd1c1c1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def qualify():
    inputs = {}
    def read(path):
        raw = path.read_bytes()
        inputs[path.relative_to(ROOT).as_posix()] = sha(raw)
        return raw
    metadata = BASE / 'metadata/run-01'
    acquisition = json.loads(read(metadata / 'acquisition.json'))
    need(acquisition['passed'], 'Metadata acquisition failed')
    bound = {row['path']: row for row in acquisition['records']}
    for name in ['argon2/commit.json', 'argon2/tree.json']:
        need(sha(read(metadata / name)) == bound[name]['sha256'], 'Metadata bytes changed')
    commit = json.loads(read(metadata / 'argon2/commit.json'))
    tree = json.loads(read(metadata / 'argon2/tree.json'))
    need(commit['sha'] == PIN and commit['tree']['sha'] == tree['sha'] and tree['truncated'] is False,
         'Argon2 commit/tree mismatch')
    objects = {row['path']: row for row in tree['tree'] if row['type'] == 'blob'}
    rows = []
    def bind(path, raw, location):
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        expected = objects[path]
        need(len(raw) == expected['size'] and blob == expected['sha'], 'Release bytes differ: ' + path)
        row = {'source_path': path, 'local_source': location, 'bytes': len(raw), 'sha256': sha(raw),
               'git_blob_sha1': blob, 'matches_release_tree': True,
               'source_url': 'https://raw.githubusercontent.com/phxql/argon2-jvm/' + PIN + '/' + path}
        rows.append(row)
        return row
    dependencies = {row['coordinate']: row for row in json.loads(read(ROOT / 'reuse/runtime-dependencies.json'))['dependencies']}
    lock = {row['coordinate']: row for row in json.loads(read(ROOT / 'reuse/runtime-source-archives.lock.json'))['entries']}
    archives = []
    for coordinate in ['de.mkammerer:argon2-jvm:2.11', 'de.mkammerer:argon2-jvm-nolibs:2.11']:
        for kind, entry in [('runtime', dependencies[coordinate]['jar']), ('source', lock[coordinate])]:
            path = ROOT / entry.get('file', entry.get('path'))
            need(sha(read(path)) == entry['sha256'], 'Archive drift')
            archive_record = {'coordinate': coordinate, 'kind': kind, 'path': path.relative_to(ROOT).as_posix(),
                              'sha256': entry['sha256'], 'bindings': []}
            with zipfile.ZipFile(path) as archive:
                for member in archive.namelist():
                    native = member.endswith(('.so', '.dll', '.dylib'))
                    java = kind == 'source' and member.endswith('.java')
                    if not (native or java):
                        continue
                    source = ('argon2-jvm/src/main/resources/' if native else 'argon2-jvm-nolibs/src/main/java/') + member
                    row = bind(source, archive.read(member), {'archive': path.relative_to(ROOT).as_posix(), 'member': member})
                    row['kind'] = 'native-release-byte' if native else 'java-source-byte'
                    archive_record['bindings'].append(row)
            archives.append(archive_record)
    acquired = BASE / 'argon2/acquired'
    fetched = json.loads(read(acquired / 'acquisition.json'))
    need(fetched['passed'], 'Argon2 source fetch failed')
    for entry in fetched['records']:
        path = acquired / entry['path']
        raw = read(path)
        need(sha(raw) == entry['sha256'] and entry['expected_git_blob_sha1'] == objects[entry['path']]['sha'],
             'Fetched text identity drift')
        row = bind(entry['path'], raw, {'path': path.relative_to(ROOT).as_posix()})
        row['kind'] = 'build-notice-documentation-byte'
    inputs[Path(__file__).relative_to(ROOT).as_posix()] = sha(Path(__file__).read_bytes())
    return {'schema': 'expertauth-argon2-release-correspondence-v1', 'commit': PIN, 'tree': tree['sha'],
            'archives': archives, 'files': rows, 'input_sha256': inputs,
            'summary': {'runtime_native_members': sum(len(a['bindings']) for a in archives if a['kind'] == 'runtime'),
                        'source_native_members': sum(len([r for r in a['bindings'] if r['kind'] == 'native-release-byte']) for a in archives if a['kind'] == 'source'),
                        'java_source_members': len([r for r in rows if r['kind'] == 'java-source-byte']),
                        'acquired_text_files': len(fetched['records'])},
            'native_source_recipe_tag': '20190702', 'native_commit_resolved': False,
            'native_build_qualified': False, 'license_approved': False, 'authentication_complete': False,
            'remaining': ['Resolve PHC20190702 to immutable native commit and audit all applicable source/license bytes',
                          'Identify actual Darwin/Windows build sources and toolchains; Linux recipe alone is not their correspondence',
                          'Pin Ubuntu16.04 base and apt compiler/sysroot packages; establish source-to-binary and static runtime correspondence',
                          'Provide full incorporated GPL3 terms and demonstrate recipient source/library replacement obligations',
                          'Execute required native/platform tests and independent distribution/security review']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    need(output.is_relative_to((BASE / 'argon2').resolve()), 'Output outside Argon2 review')
    report = qualify()
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report['summary']))
