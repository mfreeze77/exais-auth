"""Verify cached scrypt source bytes and inventory native correspondence gaps.

Local files only: no network, Docker, compilation or authentication claims.
All writes stay in this evidence directory; original sources remain unchanged.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import zipfile

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
REVIEW = ROOT / 'evidence/reuse/runtime-distribution-review'
COMMIT = '0675236370458e819ee21e4427c5f7f3f9485d33'
PREFIX = 'https://raw.githubusercontent.com/wg/scrypt/' + COMMIT + '/'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def location(path):
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def role(name):
    if name.startswith('src/main/c/'):
        return 'native-c'
    if name.startswith('src/main/include/'):
        return 'native-header'
    if name.startswith('src/main/java/'):
        return 'java-jni-loader' if '/jni/' in name else 'java-crypto-codec'
    if name.startswith('src/test/java/'):
        return 'test-source'
    return 'build-or-project-notice'


def notices(name, data):
    text = data.decode('utf-8')
    if data.startswith(b'/*'):
        end = data.find(b'*/') + 2
    elif data.startswith(b'// Copyright'):
        end = data.find(b'\n')
    else:
        end = 0
    block = data[:end]
    if b'Redistribution and use in source and binary forms' in block:
        expression = 'BSD-3-Clause' if b'3.' in block else 'BSD-2-Clause'
        basis = 'Explicit file permission and disclaimer block'
        terms = ['Retain copyright, conditions and disclaimer in source distributions.',
                 'Reproduce copyright, conditions and disclaimer in binary documentation/materials.']
        if expression == 'BSD-3-Clause':
            terms.append('Do not use named copyright-holder/contributor names to endorse derived products without permission.')
    else:
        expression = 'Apache-2.0'
        basis = 'Repository LICENSE and matching Maven POM declaration; no separate file grant or overriding terms found'
        terms = ['Preserve the repository Apache-2.0 license and applicable attribution notices.',
                 'Mark modified files and retain applicable NOTICE material when distributing derivatives.']
    return {'license_expression_observed': expression, 'basis': basis,
            'copyright_lines': [line.strip(' /*') for line in text.splitlines() if 'Copyright' in line][:5],
            'inline_notice_byte_range': {'start_inclusive': 0, 'end_exclusive': end} if end else None,
            'inline_notice_sha256': sha(block) if end else None,
            'distribution_terms_summary': terms, 'independent_license_approval': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquired-directory', type=Path, default=OUT / 'acquired')
    parser.add_argument('--commit-metadata', type=Path)
    parser.add_argument('--output', default='source-manifest.json')
    args = parser.parse_args()
    need(Path(args.output).name == args.output and args.output.endswith('.json'), 'Output must be a JSON basename')
    destination = OUT / args.output
    need(not destination.exists(), 'Preserve previous manifest; choose a new output basename')
    inputs = {}

    def read(path):
        data = path.read_bytes()
        inputs[location(path)] = sha(data)
        return data

    metadata = json.loads(read(REVIEW / 'upstream/scrypt-tree.json'))
    tag = json.loads(read(REVIEW / 'upstream/scrypt-tag.json'))
    need(not metadata['truncated'] and len(metadata['tree']) == 71, 'Pinned tree coverage differs')
    need(tag['object']['type'] == 'commit' and tag['object']['sha'] == COMMIT, 'Tag binding differs')
    tree = metadata['tree']
    entries = {entry['path']: entry for entry in tree}
    reconstructed = {}
    for parent in [''] + [entry['path'] for entry in tree if entry['type'] == 'tree']:
        children = [entry for entry in tree if entry['path'].rpartition('/')[0] == parent]
        children.sort(key=lambda entry: (entry['path'].split('/')[-1] + ('/' if entry['type'] == 'tree' else '')).encode())
        content = b''.join(entry['mode'].lstrip('0').encode() + b' ' + entry['path'].split('/')[-1].encode() +
                           b'\0' + bytes.fromhex(entry['sha']) for entry in children)
        value = hashlib.sha1(b'tree ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        if parent:
            need(value == entries[parent]['sha'], 'Subtree hash differs: ' + parent)
        reconstructed[parent] = value
    commit_binding = {'status': 'missing-commit-object', 'reconstructed_root_tree_sha1': reconstructed[''],
                      'note': 'The cached trees endpoint top-level sha echoes the requested commit; it is not the reconstructed root tree hash.'}
    if args.commit_metadata:
        commit = json.loads(read(args.commit_metadata))
        need(commit['sha'] == COMMIT and commit['tree']['sha'] == reconstructed[''], 'Commit/root-tree binding differs')
        commit_binding['status'] = 'verified-commit-tree-binding'
    inventory = json.loads(read(REVIEW / 'archive-inventory.json'))
    artifact = next(row for row in inventory['artifacts'] if row['coordinate'] == 'com.lambdaworks:scrypt:1.4.0')
    archives = {}
    for kind in ('binary', 'source'):
        data = read(ROOT / artifact[kind]['path'])
        need(sha(data) == artifact[kind]['sha256'], 'Cached archive hash differs: ' + kind)
        archives[kind] = {'path': artifact[kind]['path'], 'sha256': sha(data), 'bytes': len(data)}
    blobs = [entry for entry in tree if entry['type'] == 'blob']
    wanted = [entry for entry in blobs if entry['path'] in {'LICENSE', 'Makefile', 'README', 'pom.xml'} or
              entry['path'].startswith(('src/main/c/', 'src/main/include/', 'src/main/java/', 'src/test/java/'))]
    need(len(wanted) == 32, 'Source/build/test denominator differs')
    files = []
    system_headers = set()
    local_headers = set()
    source_data = {}
    with zipfile.ZipFile(ROOT / artifact['source']['path']) as jar:
        for entry in wanted:
            name = entry['path']
            cached = REVIEW / 'upstream' / ('scrypt__' + name.replace('/', '__'))
            acquired = args.acquired_directory / name
            record = {'path': name, 'role': role(name), 'source_url': PREFIX + name,
                      'expected_bytes': entry['size'], 'expected_git_blob_sha1': entry['sha']}
            data = None
            if cached.is_file():
                data = read(cached)
                record['local_source'] = {'path': location(cached)}
            elif name.startswith('src/main/java/') and name.removeprefix('src/main/java/') in jar.namelist():
                member = name.removeprefix('src/main/java/')
                data = jar.read(member)
                record['local_source'] = {'archive_path': artifact['source']['path'], 'archive_sha256': artifact['source']['sha256'], 'member': member}
            elif acquired.is_file():
                data = read(acquired)
                record['local_source'] = {'path': location(acquired)}
            if data is None:
                record.update({'status': 'missing-source-bytes', 'git_blob_and_size_verified': False,
                               'notice': {'status': 'unreviewed-unacquired-file', 'license_expression_observed': None}})
            else:
                need(len(data) == entry['size'] and git_blob(data) == entry['sha'], 'Source Git blob/size differs: ' + name)
                record.update({'status': 'verified-source-bytes', 'bytes': len(data), 'sha256': sha(data),
                               'git_blob_sha1': git_blob(data), 'git_blob_and_size_verified': True, 'notice': notices(name, data)})
                source_data[name] = data
                if name.endswith(('.c', '.h')):
                    includes = re.findall(r'^\s*#\s*include\s+([<"])([^>"]+)[>"]', data.decode(), re.M)
                    record['includes'] = [{'header': header, 'scope': 'system-toolchain' if opener == '<' else 'project'} for opener, header in includes]
                    system_headers.update(header for opener, header in includes if opener == '<')
                    local_headers.update(header for opener, header in includes if opener == '"')
            files.append(record)
    binaries = []
    with zipfile.ZipFile(ROOT / artifact['binary']['path']) as jar, zipfile.ZipFile(ROOT / artifact['source']['path']) as source_jar:
        for member in artifact['binary']['native_members']:
            path = 'src/main/resources/' + member['member']
            expected = entries[path]
            data = jar.read(member['member'])
            need(sha(data) == member['sha256'] and len(data) == expected['size'] and git_blob(data) == expected['sha'], 'Native member/tree binding differs')
            need(source_jar.read(member['member']) == data, 'Source JAR native member differs')
            binaries.append({'jar_member': member['member'], 'upstream_path': path, 'bytes': len(data), 'sha256': sha(data),
                             'git_blob_sha1': git_blob(data), 'release_tree_and_both_jars_byte_match': True,
                             'built_from_reviewed_sources_proven': False, 'toolchain_and_link_map_available': False,
                             'static_runtime_and_system_library_correspondence': 'unverified'})
    missing = [row['path'] for row in files if not row['git_blob_and_size_verified']]
    native_files = [row for row in files if row['role'] in {'native-c', 'native-header'}]
    excluded = [{'path': row['path'], 'git_blob_sha1': row['sha'], 'bytes': row['size'],
                 'reason': 'Already inventoried runtime native; no acquisition' if row['path'].startswith('src/main/resources/') else
                           'Upstream Android native is outside the three-member runtime JAR inventory; binary acquisition prohibited in this lane' if row['path'].startswith('src/android/') else
                           'Binary/signature test fixture not acquired; complete upstream test execution remains blocked' if row['path'].startswith('src/test/resources/') else
                           'Git ignore metadata is not a native/JNI source or build input'}
                for row in blobs if row['path'] not in {entry['path'] for entry in wanted}]
    result = {'schema': 'expertauth-scrypt-native-source-correspondence-v1', 'coordinate': 'com.lambdaworks:scrypt:1.4.0',
              'repository': 'https://github.com/wg/scrypt', 'release_tag': '1.4.0', 'commit': COMMIT,
              'scope': 'File acquisition, notice observations and release-tree byte correspondence; no native build or legal/security approval',
              'native_corresponding_source_complete': False, 'native_rebuild_verified': False, 'license_approved': False,
              'foundation_passed': False, 'independent_security_review_passed': False,
              'tree': {'entries': len(tree), 'blobs': len(blobs), 'subtrees_verified': len(reconstructed) - 1,
                       'commit_binding': commit_binding}, 'archives': archives, 'files': files,
              'summary': {'source_build_test_files': len(files), 'verified_files': len(files) - len(missing),
                          'missing_files': missing, 'roles': dict(Counter(row['role'] for row in files)),
                          'repository_native_c_and_headers_present_and_verified': all(row['git_blob_and_size_verified'] for row in native_files)},
              'source_include_closure': {'project_headers': sorted(local_headers), 'system_headers_requiring_toolchain_provenance': sorted(system_headers),
                                        'all_project_header_paths_in_manifest': all('src/main/include/' + header in source_data for header in local_headers)},
              'runtime_native_bindings': binaries, 'excluded_blob_inventory': excluded,
              'build_observations': {
                  'source': 'Makefile', 'c_flags': '-std=c99 -Wall -O2 -DHAVE_CONFIG_H -I src/main/include',
                  'source_selection': 'All four C files are considered; default SSE2=yes filters out crypto_scrypt-nosse.c; SSE2= filters out crypto_scrypt-sse.c.',
                  'native_output': 'target/libscrypt.so or target/libscrypt.dylib; Makefile does not copy it into Maven resource directories.',
                  'platforms': [
                      {'platform': 'linux-x86_64', 'upstream_mode': '-shared -fPIC; JNI headers from JAVA_HOME/include and include/linux', 'qualification': 'blocked-missing-toolchain-link-map-and-rebuild'},
                      {'platform': 'freebsd-x86_64', 'upstream_mode': '-shared -fPIC; JNI headers from JAVA_HOME/include and include/freebsd', 'qualification': 'blocked-missing-toolchain-link-map-and-rebuild'},
                      {'platform': 'darwin-x86_64', 'upstream_mode': '-dynamiclib -undefined dynamic_lookup -single_module; legacy JAVA_HOME/Headers path', 'qualification': 'blocked-missing-macos-sdk-toolchain-and-rebuild'},
                      {'platform': 'android-arm', 'upstream_mode': 'arm-linux-androideabi-gcc; NDK_ROOT/platforms/android-9/arch-arm; -lc; --fix-cortex-a8; SSE2 disabled', 'qualification': 'outside-runtime-jar-and-unverified-upstream-native-platform'}],
                  'compiler_version_pinned': False, 'jdk_vendor_version_and_jni_headers_pinned': False, 'system_headers_and_libc_versions_pinned': False,
                  'static_runtime_inclusion': 'Unknown. A shared-library link command does not establish absence or provenance of statically incorporated compiler/runtime code.',
                  'maven': {'java_source_target': '1.6', 'test_dependency': 'junit:junit:4.8.2',
                            'plugins': {'maven-compiler-plugin': '2.3.2', 'maven-resources-plugin': '2.5', 'maven-jarsigner-plugin': '1.2', 'maven-surefire-plugin': '2.10', 'maven-gpg-plugin': '1.1'},
                            'native_compilation_wired_into_pom': False, 'signing_credentials_and_reproducible_release_process_available': False}},
              'jni_boundary': {'native_entry': 'scrypt_jni.c JNI_OnLoad registers SCrypt.scryptN ([B[BIIII)[B using JNI_VERSION_1_6',
                               'java_selection': 'SCrypt.scrypt selects scryptN only if LibraryLoader reports success; otherwise it uses scryptJ.',
                               'loader_property': 'com.lambdaworks.jni.loader accepts nil/jar/sys; no configuration change was made.',
                               'platform_detector': 'x86/x86_64 plus darwin/freebsd/linux; runtime JAR contains only x86_64 libraries.',
                               'native_execution_proven_by_this_manifest': False},
              'blockers': ['All three runtime natives lack a reproduced source-to-binary build, compiler/JDK/platform SDK pins, link maps and transitive/static runtime provenance.',
                           'Native shared-library build output is not wired into Maven resource packaging; checked-in native bytes are packaged instead.',
                           'Complete upstream tests need five binary/signature fixtures that this source-only lane did not fetch, plus pinned test toolchain dependencies.',
                           'Independent license/security review and per-platform native execution remain unperformed.'],
              'inputs_sha256': inputs, 'tool_sha256': sha(Path(__file__).read_bytes())}
    if missing:
        result['blockers'].append('Unacquired source bytes: ' + ', '.join(missing))
    if commit_binding['status'] != 'verified-commit-tree-binding':
        result['blockers'].append('Commit object binding the reconstructed root tree has not been acquired.')
    destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'manifest': location(destination), 'sha256': sha(destination.read_bytes()), 'verified_files': len(files)-len(missing),
                      'source_files': len(files), 'native_binary_bindings': len(binaries), 'native_rebuild_verified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
