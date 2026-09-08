"""Preserve exact pinned binary/source notice bytes in the OSS runtime image.

Acquired source archives remain in a bounded cache, with locked retrieval paths.
This does not assert complete corresponding-source or distribution approval.
"""
from __future__ import annotations
import json
from pathlib import Path, PurePosixPath
import re
import zipfile
from fetch_runtime_notice_sources import LOCK, ROOT, cache_path, ensure_sources, require, sha

NAME = re.compile(r'^(?:license|licence|notice|copying|copyright)(?:[._-].*)?$', re.I)
BINARY_SUFFIXES = {'.class', '.jar', '.exe', '.dll', '.so', '.dylib', '.jnilib', '.a'}


def safe_relative(relative):
    pure = PurePosixPath(relative)
    require(not pure.is_absolute() and '..' not in pure.parts and '\\' not in relative and
            ':' not in relative and relative == pure.as_posix(), 'Unsafe notice member path')
    return pure


def assemble(destination: Path):
    destination = destination.resolve()
    cache = (ROOT / '.cache').resolve()
    require(cache.is_relative_to(ROOT.resolve()) and destination.is_relative_to(cache) and destination != cache,
            'Generated notice context must stay inside the workspace cache')
    require(not destination.exists(), 'Use a new notice directory')
    # Validate every locked source before creating a partial output tree.
    ensure_sources(offline=True)
    sources = {row['coordinate']: row for row in json.loads(LOCK.read_bytes())['entries']}
    dependencies = json.loads((ROOT / 'reuse/runtime-dependencies.json').read_bytes())['dependencies']
    expected = {row['path']: row['sha256'] for row in json.loads((ROOT / 'evidence/build/oss-core/artifacts.json').read_bytes())}
    destination.mkdir(parents=True)
    outputs = []
    inputs = {}
    rows = []

    def input_bytes(path):
        raw = path.read_bytes()
        inputs[path.relative_to(ROOT).as_posix()] = sha(raw)
        return raw

    def write(relative, raw):
        pure = safe_relative(relative)
        path = destination.joinpath(*pure.parts)
        require(path.resolve().is_relative_to(destination), 'Notice output escaped')
        path.parent.mkdir(parents=True, exist_ok=True)
        require(not path.exists(), 'Duplicate notice output')
        path.write_bytes(raw)
        entry = {'path': relative, 'sha256': sha(raw), 'bytes': len(raw)}
        outputs.append(entry)
        return entry

    def preserve_archive(archive_path, prefix):
        notices = []
        with zipfile.ZipFile(archive_path) as archive:
            for item in sorted(archive.infolist(), key=lambda value: value.filename):
                pure = PurePosixPath(item.filename)
                if item.is_dir() or not NAME.match(pure.name) or pure.suffix.lower() in BINARY_SUFFIXES:
                    continue
                safe_relative(item.filename)
                require(item.file_size <= 4 * 1024 * 1024, 'Notice text exceeds bound')
                raw = archive.read(item)
                try:
                    raw.decode('utf-8-sig')
                except UnicodeError:
                    continue
                if b'\x00' in raw:
                    continue
                notices.append({**write(prefix + '/' + item.filename, raw), 'archive_member': item.filename})
            if 'META-INF/MANIFEST.MF' in archive.namelist():
                write(prefix + '/ARCHIVE-MANIFEST.MF', archive.read('META-INF/MANIFEST.MF'))
        return notices

    for dependency in dependencies:
        coordinate = dependency['coordinate']
        prefix = coordinate.replace(':', '/')
        jar = ROOT / dependency['jar']['file']
        digest = sha(input_bytes(jar))
        require(digest == dependency['jar']['sha256'] == dependency['build_record']['sha256'] ==
                expected[jar.relative_to(ROOT / '.cache/engine-build').as_posix()], 'Runtime artifact drift')
        notices = preserve_archive(jar, prefix + '/binary')
        source = sources[coordinate]
        source_notices = []
        if source['status'] == 'available':
            source_path = cache_path(source)
            require(sha(input_bytes(source_path)) == source['sha256'], 'Source archive drift')
            source_notices = preserve_archive(source_path, prefix + '/source')
        pom = dependency['license']['pom']
        group, artifact, version = coordinate.split(':')
        pom_path = ROOT / 'reuse/licenses/poms' / f'{group}.{artifact}-{version}.pom'
        raw_pom = input_bytes(pom_path)
        require(sha(raw_pom) == pom['sha256'], 'POM provenance drift')
        declarations = [write(prefix + '/maven-pom.xml', raw_pom)]
        inherited = dependency['license'].get('inherited')
        if inherited:
            pgroup, partifact, pversion = inherited['coordinate'].split(':')
            parent = ROOT / 'reuse/licenses/poms' / f'{pgroup}.{partifact}-{pversion}.pom'
            raw_parent = input_bytes(parent)
            require(sha(raw_parent) == inherited['pom']['sha256'], 'Inherited POM provenance drift')
            declarations.append(write(prefix + '/parent-maven-pom.xml', raw_parent))
        rows.append({'coordinate': coordinate, 'runtime_jar_sha256': digest, 'binary_notices': notices,
                     'source_notices': source_notices, 'source_archive': source, 'poms': declarations,
                     'declared_licenses': dependency['license']['licenses'],
                     'notice_text_present': bool(notices or source_notices),
                     'full_distribution_approved': False})
    projects = json.loads(input_bytes(ROOT / 'evidence/build/oss-core/command.json'))['sources']
    for name, commit in projects.items():
        path = ROOT / 'reuse/licenses' / f'supertokens__{name}' / commit / 'LICENSE.md'
        write(f'own-source/{name}/LICENSE.md', input_bytes(path))
    review = ROOT / 'evidence/reuse/runtime-distribution-review'
    supplemental = json.loads(input_bytes(review / 'supplemental-notices.json'))
    require(len(supplemental['bindings']) == 4 and len(supplemental['files']) == 5 and
            supplemental['license_approved'] is False, 'Unexpected supplemental notice qualification')
    runtime = {row['coordinate']: row for row in dependencies}
    fetch = json.loads(input_bytes(review / 'supplemental-fetch.json'))
    for entry in fetch['records']:
        path = (review / entry['path']).resolve()
        require(path.is_relative_to(review.resolve()) and sha(input_bytes(path)) == entry['sha256'],
                'Supplemental acquisition bytes changed')
    for binding in supplemental['bindings']:
        dependency = runtime[binding['coordinate']]
        require(dependency['jar']['sha256'] == binding['binary_jar_sha256'] and
                binding['matches_release_tree'] is True, 'Supplemental release binding drift')
        raw = (ROOT / dependency['jar']['file']).read_bytes()
        if 'jar_member' in binding:
            with zipfile.ZipFile(ROOT / dependency['jar']['file']) as archive:
                raw = archive.read(binding['jar_member'])
            require(sha(raw) == binding['member_sha256'], 'Supplemental native member drift')
        import hashlib
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == binding['git_blob_sha1'],
                'Supplemental release Git object mismatch')
    supplements = []
    for row in supplemental['files']:
        path = (ROOT / row['path']).resolve()
        require(path.is_relative_to(review.resolve()) and row['eligible_for_supplemental_notice_packaging'] is True,
                'Unreviewed supplemental notice')
        raw = input_bytes(path)
        require(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'Supplemental notice changed')
        if 'source_file' in row:
            source = input_bytes(ROOT / row['source_file'])
            bounds = row['exact_source_byte_range']
            require(sha(source) == row['source_sha256'] and
                    source[bounds['start_inclusive']:bounds['end_exclusive']] == raw, 'Source notice excerpt mismatch')
        packaged = write(row['coordinate'].replace(':', '/') + '/supplemental/' + path.name, raw)
        supplements.append({**row, 'packaged_file': packaged})
    for name in ['THIRD_PARTY_NOTICES.md', 'reuse/oss-core-runtime.cdx.json', 'reuse/runtime-source-archives.lock.json', 'docs/runtime-image-notices.md']:
        write(Path(name).name, input_bytes(ROOT / name))
    input_bytes(Path(__file__))
    input_bytes(ROOT / 'tools/fetch_runtime_notice_sources.py')
    input_bytes(ROOT / 'reuse/runtime-dependencies.json')
    input_bytes(ROOT / 'evidence/build/oss-core/artifacts.json')
    report = {'schema': 'runtime-notice-preservation-v2', 'dependencies': rows,
              'runtime_dependency_count': len(rows),
              'binary_notice_text_count': sum(len(row['binary_notices']) for row in rows),
              'source_notice_text_count': sum(len(row['source_notices']) for row in rows),
              'supplemental_notices': supplements,
              'no_embedded_notice_text': [row['coordinate'] for row in rows if not row['notice_text_present']],
              'full_distribution_approved': False,
              'remaining': ['Full applicable license and copyright texts for components without embedded notices',
                            'Native component provenance, notices and applicable corresponding-source/relink obligations',
                            'Container OS licenses and independent distribution review'],
              'source_archives_embedded_in_image': False,
              'input_sha256': inputs, 'files': sorted(outputs, key=lambda row: row['path'])}
    # The manifest is outside its own file inventory to avoid self-reference.
    (destination / 'manifest.json').write_bytes((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    report = assemble(args.output)
    print(json.dumps({'dependencies': report['runtime_dependency_count'],
                      'binary_notice_texts': report['binary_notice_text_count'],
                      'source_notice_texts': report['source_notice_text_count'],
                      'without_embedded_text': len(report['no_embedded_notice_text']),
                      'files': len(report['files']), 'full_distribution_approved': False}))
