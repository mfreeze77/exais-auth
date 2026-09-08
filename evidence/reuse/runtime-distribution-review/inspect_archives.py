"""Read existing dependency/source archives; writes only this review evidence.

No downloads, archive extraction, native execution, containers, or runtime edits.
"""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
RUNTIME = ROOT / 'reuse/runtime-dependencies.json'
FETCH = ROOT / 'evidence/reuse/runtime-source-notices/fetch-20260908T222746Z.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(path):
    record = {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path.read_bytes()),
              'bytes': path.stat().st_size, 'native_members': [], 'notice_members': [],
              'build_members': [], 'native_source_members': [], 'java_source_count': 0,
              'class_count': 0, 'file_count': 0, 'witness_members': []}
    all_members = []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            name = entry.filename
            raw = archive.read(entry)
            item = {'member': name, 'bytes': len(raw), 'sha256': sha(raw)}
            all_members.append(item)
            record['file_count'] += 1
            record['java_source_count'] += name.endswith('.java')
            record['class_count'] += name.endswith('.class')
            if re.search(r'\.(so(?:\.\d+)*|dll|dylib|jnilib|a|lib|exe|o)$', name, re.I) or (raw[:4] == b'\x7fELF'):
                record['native_members'].append(item)
            if re.search(r'(^|/)([^/]*(license|notice|copying|copyright)[^/]*|about\.html)$', name, re.I):
                record['notice_members'].append(item)
            if re.search(r'(^|/)(pom\.xml|build\.(xml|gradle|gradle\.kts)|settings\.gradle.*|Makefile.*|CMakeLists\.txt|configure.*|gradlew.*|.*\.sh)$', name):
                record['build_members'].append(item)
            if re.search(r'\.(c|cc|cpp|cxx|h|hpp|s|S)$', name):
                record['native_source_members'].append(item)
            if name.endswith(('ListenableFuture.java', 'ListenableFuture.class', 'Argon2Library.java',
                              'Argon2.java', 'AsyncAppender.java', '/Appender.java', 'FieldSignatureImpl.java')):
                record['witness_members'].append(item)
    if 'listenablefuture' in path.name:
        record['all_members'] = all_members
    return record


def main():
    dependency_records = json.loads(RUNTIME.read_text())['dependencies']
    sources = {x['coordinate']: x for x in json.loads(FETCH.read_text())['sources']}
    records = []
    for dependency in dependency_records:
        binary = inspect(ROOT / dependency['jar']['file'])
        source = sources[dependency['coordinate']]
        record = {'coordinate': dependency['coordinate'], 'declared_licenses': dependency['license']['licenses'],
                  'binary': binary, 'binary_matches_audit': binary['sha256'] == dependency['jar']['sha256'],
                  'source_fetch_record': source}
        if source['status'] == 'available':
            record['source'] = inspect(ROOT / source['path'])
            record['source_matches_fetch'] = record['source']['sha256'] == source['sha256']
            source_native = {m['member']: m['sha256'] for m in record['source']['native_members']}
            record['identical_native_binary_and_source_members'] = sum(
                source_native.get(m['member']) == m['sha256'] for m in binary['native_members'])
        records.append(record)
    result = {'scope': 'Existing archive evidence only; no license approval or build/runtime qualification',
              'inputs': [{'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p.read_bytes())} for p in (RUNTIME, FETCH)],
              'summary': {'runtime_jars': len(records), 'source_jars': sum('source' in r for r in records),
                          'binary_hash_mismatches': sum(not r['binary_matches_audit'] for r in records),
                          'source_hash_mismatches': sum(r.get('source_matches_fetch') is False for r in records),
                          'native_bundle_coordinates': [r['coordinate'] for r in records if r['binary']['native_members']]},
              'artifacts': records}
    (OUT / 'archive-inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary'], indent=2))
    for r in records:
        if r['binary']['native_members'] or 'argon2' in r['coordinate'] or 'listenablefuture' in r['coordinate']:
            print(r['coordinate'], 'native=', len(r['binary']['native_members']),
                  'source_native=', len(r.get('source', {}).get('native_members', [])),
                  'C_sources=', len(r.get('source', {}).get('native_source_members', [])),
                  'build_members=', [x['member'] for x in r.get('source', {}).get('build_members', [])])


if __name__ == '__main__':
    main()
