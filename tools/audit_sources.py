#!/usr/bin/env python3
"""Pinned, network-evidenced upstream audit; never installs or executes upstream code.

Run inside the pinned Python container when host Winsock is unavailable. Network
responses stay in .cache/reuse-audit. Only metadata, permitted license notices,
and path/hash manifests are written to release directories. Enterprise source
is not read from source archives, extracted, or distributed.
"""
from __future__ import annotations
import argparse, concurrent.futures, datetime, hashlib, io, json, re, tarfile, zipfile, os, sys, time, traceback
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache' / 'reuse-audit'
OUT = ROOT / 'reuse'
EVIDENCE = ROOT / 'evidence' / 'reuse'
BASELINE = ROOT / 'baseline' / 'expert-auth-full-parity-plan-v1.0'
for directory in (CACHE, OUT, EVIDENCE):
    directory.mkdir(parents=True, exist_ok=True)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def fetch(url, json_data=True, post=None):
    key = sha((url + (json.dumps(post, sort_keys=True) if post else '')).encode())
    path, meta = CACHE / (key + '.body'), CACHE / (key + '.json')
    if not path.exists():
        request = Request(url, headers={'User-Agent': 'ExpertAuth-Source-Audit/1.0', 'Accept': 'application/json' if json_data else '*/*'},
                          data=json.dumps(post).encode() if post else None)
        if post:
            request.add_header('Content-Type', 'application/json')
        with urlopen(request, timeout=90) as response:
            data = response.read()
            provenance = {'url': url, 'final_url': response.url, 'http_status': response.status,
                          'fetched_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          'sha256': sha(data), 'bytes': len(data), 'request_method': 'POST' if post else 'GET'}
        path.write_bytes(data)
        write(meta, provenance)
    data = path.read_bytes()
    provenance = json.loads(meta.read_text())
    if sha(data) != provenance['sha256']:
        raise ValueError(f'Cached response integrity mismatch: {url}')
    return (json.loads(data) if json_data else data), provenance

def github(repo, endpoint):
    return fetch((f'https://api.github.com/repos/{repo}/' + endpoint).rstrip('/'))[0]

def source_file(repo, commit, path):
    if path.startswith('ee/') and path != 'ee/LICENSE.md':
        raise ValueError('Enterprise source is excluded')
    data, metadata = fetch(f'https://raw.githubusercontent.com/{repo}/{commit}/{path}', False)
    return {'source_path': path, 'sha256': sha(data), 'bytes': len(data), 'provenance': metadata}, data

def engine_probe():
    result = []
    for repo in ('keycloak/keycloak', 'supertokens/supertokens-core'):
        release = github(repo, 'releases/latest')
        tag = release['tag_name']
        commit = github(repo, 'commits/' + tag)['sha']
        paths = ['LICENSE.txt', 'pom.xml'] if repo.startswith('keycloak/') else ['LICENSE.md', 'ee/LICENSE.md', 'build.gradle', 'settings.gradle', 'gradle.properties', '.gitmodules']
        entry = {'repository': repo, 'release': tag, 'commit': commit, 'published_at': release['published_at'],
                 'release_url': release['html_url'], 'release_notes': release.get('body'),
                 'assets': [{k: asset.get(k) for k in ('name', 'digest', 'size', 'browser_download_url')} for asset in release['assets']], 'files': []}
        for path in paths:
            try:
                record, data = source_file(repo, commit, path)
                entry['files'].append(record)
                target = CACHE / 'probe' / repo.replace('/', '__') / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            except HTTPError as exc:
                entry['files'].append({'source_path': path, 'http_error': exc.code})
        result.append(entry)
        print(json.dumps({k: entry[k] for k in ('repository', 'release', 'commit', 'published_at')}), flush=True)
    write(OUT / 'engine-candidates.json', result)

SDK_REPOS = {
    'SDKP-01': ('supertokens/supertokens-node', 'supertokens-node'),
    'SDKP-02': ('supertokens/supertokens-python', None),
    'SDKP-03': ('supertokens/supertokens-golang', None),
    'SDKP-04': ('supertokens/supertokens-web-js', 'supertokens-web-js'),
    'SDKP-05': ('supertokens/supertokens-auth-react', 'supertokens-auth-react'),
    'SDKP-06': ('supertokens/supertokens-react-native', 'supertokens-react-native'),
    'SDKP-07': ('supertokens/supertokens-ios', None),
    'SDKP-08': ('supertokens/supertokens-android', None),
}

def license_id(content):
    text = content.decode('utf-8', errors='replace')
    if 'Apache License' in text and 'Version 2.0' in text:
        return 'Apache-2.0'
    if 'Permission is hereby granted, free of charge' in text:
        return 'MIT'
    if 'GNU LESSER GENERAL PUBLIC LICENSE' in text:
        return 'LGPL-version-review-required'
    if 'GNU GENERAL PUBLIC LICENSE' in text:
        return 'GPL-version-review-required'
    if 'Redistribution and use in source and binary forms' in text:
        return 'BSD-clause-review-required'
    return 'LicenseRef-Unreviewed'

def audit_archive(repo, commit, url=None, extract=False, manifest_name=None):
    url = url or f'https://codeload.github.com/{repo}/tar.gz/{commit}'
    data, provenance = fetch(url, False)
    archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
    files, licenses, excluded, notices, content_map = [], {}, [], [], {}
    for member in archive:
        parts = Path(member.name).parts
        if len(parts) < 2 or not member.isfile():
            continue
        path = '/'.join(parts[1:])
        if '..' in parts or member.name.startswith('/'):
            raise ValueError('Unsafe archive path')
        if path.startswith('ee/'):
            excluded.append({'source_path': path, 'decision': 'exclude', 'license': 'LicenseRef-SuperTokens-Enterprise',
                             'content_inspected': False, 'sha256': None, 'reason': 'Restricted enterprise directory; bytes not read or extracted'})
            continue
        body = archive.extractfile(member).read()
        content_map[path] = body
        name = Path(path).name.lower()
        if name in ('license', 'license.md', 'license.txt', 'license-mit', 'license-apache', 'copying', 'copying.txt'):
            licenses[path] = {'license': license_id(body), 'sha256': sha(body)}
        if name.startswith(('license', 'notice', 'copying')):
            notices.append({'source_path': path, 'sha256': sha(body)})
        if extract:
            target = CACHE / 'source' / repo.replace('/', '__') / commit / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists() or sha(target.read_bytes()) != sha(body):
                temporary = target.with_name(target.name + '.audit-tmp')
                temporary.write_bytes(body)
                temporary.replace(target)
        files.append({'source_path': path, 'sha256': sha(body), 'bytes': len(body)})
    declarations = dict(licenses)
    if not licenses and 'README.md' in content_map:
        readme = content_map['README.md'].decode('utf-8', errors='replace')
        declaration = 'This project is licensed under the Apache License 2.0'
        if declaration in readme:
            declarations['README.md'] = {'license': 'Apache-2.0', 'sha256': sha(content_map['README.md']),
                                          'evidence_type': 'Explicit README declaration; referenced LICENSE file missing'}
    for path, body in content_map.items():
        if Path(path).name == 'package.json':
            try:
                metadata = json.loads(body)
                if isinstance(metadata.get('license'), str):
                    declarations[path] = {'license': metadata['license'], 'sha256': sha(body),
                                           'evidence_type': 'Package license declaration'}
            except (ValueError, UnicodeError):
                pass
    for entry in files:
        parent = Path(entry['source_path']).parent
        candidates = []
        for license_path, evidence in declarations.items():
            license_parent = Path(license_path).parent
            if parent == license_parent or license_parent in parent.parents:
                candidates.append((len(license_parent.parts), license_path, evidence))
        candidates.sort(reverse=True)
        if candidates:
            _, license_path, evidence = candidates[0]
            entry.update({'license': evidence['license'], 'license_source_path': license_path,
                          'license_determination': 'Nearest enclosing license; file-header and dependency exceptions require review'})
        else:
            entry.update({'license': 'LicenseRef-Unknown', 'license_source_path': None, 'license_determination': 'No enclosing license found'})
        header = content_map[entry['source_path']][:6000].decode('utf-8', errors='replace')
        spdx = re.search(r'SPDX-License-Identifier:\s*([^\r\n*]+)', header)
        if spdx:
            entry['license'] = spdx.group(1).strip()
            entry['license_determination'] = 'File SPDX header'
        entry['copyright_lines'] = [line.strip()[:300] for line in header.splitlines() if 'copyright' in line.lower()][:6]
        entry.update({'repository': 'https://github.com/' + repo, 'commit': commit, 'decision': 'reference only',
                      'destination': None, 'modifications': [], 'validation': 'Source bytes hashed; not built or functionally qualified',
                      'mapped_requirements': ['BAS-002', 'BAS-004'], 'implementation_qualification': False,
                      'security_sensitivity': 'Authentication dependency; critical',
                      'upstream_tracking_owner': 'ExpertAuth maintainer', 'update_strategy': 'Pin; re-audit license, advisories, contracts, and tests on update'})
        if Path(entry['source_path']).suffix.lower() in ('.jar', '.so', '.dll', '.exe', '.dylib'):
            entry['binary_boundary'] = 'Prebuilt binary; root source license does not establish nested dependency provenance or license closure'
            entry['runtime_approval'] = False
    result = {'repository': repo, 'commit': commit, 'archive': provenance, 'files': files,
              'license_files': licenses, 'license_declarations': declarations, 'notice_files': notices, 'excluded_files': excluded,
              'reuse_approval': 'reference only; dependency closure and component-specific tests pending'}
    write(OUT / 'files' / ((manifest_name or repo.replace('/', '__') + '__' + commit) + '.json'), result)
    for path in licenses:
        target = OUT / 'licenses' / repo.replace('/', '__') / commit / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content_map[path])
    return result, content_map

def core_source():
    candidates = json.loads((OUT / 'engine-candidates.json').read_text())
    candidate = next(item for item in candidates if item['repository'] == 'supertokens/supertokens-core')
    report, _ = audit_archive(candidate['repository'], candidate['commit'], extract=True)
    print(json.dumps({'repository': candidate['repository'], 'permitted_files_hashed': len(report['files']),
                      'restricted_paths_excluded_without_reading': len(report['excluded_files'])}), flush=True)

def audit_profile(profile):
    item = dict(profile)
    item.update({'qualification': 'unverified', 'decision': 'reference only', 'errors': []})
    npm_name = profile.get('upstream_package')
    if profile['id'] in SDK_REPOS:
        repo, npm_name = SDK_REPOS[profile['id']]
    else:
        repo = 'supertokens/supertokens-plugins'
    item['repository'] = repo
    if npm_name:
        metadata, provenance = fetch('https://registry.npmjs.org/' + npm_name.replace('/', '%2f') + '/latest')
        item['npm'] = {'name': npm_name, 'version': metadata['version'], 'license': metadata.get('license'),
                       'git_head': metadata.get('gitHead'), 'repository': metadata.get('repository'),
                       'dependencies': metadata.get('dependencies', {}), 'peer_dependencies': metadata.get('peerDependencies', {}),
                       'dist': metadata.get('dist'), 'metadata_evidence': provenance}
        item['candidate_version'] = metadata['version']
        item['candidate_commit'] = metadata.get('gitHead')
        tarball, tarball_provenance = fetch(metadata['dist']['tarball'], False)
        integrity = metadata['dist'].get('integrity')
        if integrity and integrity.startswith('sha512-'):
            import base64
            expected = base64.b64decode(integrity.split('-', 1)[1])
            if hashlib.sha512(tarball).digest() != expected:
                raise ValueError('npm integrity mismatch: ' + npm_name)
        item['npm']['tarball_evidence'] = tarball_provenance
        # Inventory the exact published package, including build outputs and package notices.
        package_report, package_files = audit_archive(repo, metadata.get('gitHead') or 'unresolved', metadata['dist']['tarball'], manifest_name=profile['id'] + '-published-package')
        write(OUT / 'package-files' / (profile['id'] + '.json'), package_report)
        item['package_license_files'] = package_report['license_files']
        item['package_manifest'] = 'reuse/package-files/' + profile['id'] + '.json'
        query = {'package': {'name': npm_name, 'ecosystem': 'npm'}, 'version': metadata['version']}
        try:
            vulnerabilities, evidence = fetch('https://api.osv.dev/v1/query', post=query)
            item['advisories'] = {'method': 'OSV exact direct package query; not transitive audit', 'evidence': evidence,
                                  'vulnerabilities': vulnerabilities.get('vulns', [])}
        except Exception as exc:
            item['advisories'] = {'status': 'blocked', 'error': str(exc)}
    else:
        try:
            release = github(repo, 'releases/latest')
            tag = release['tag_name']
            item['release_published_at'] = release.get('published_at')
        except HTTPError as exc:
            if exc.code != 404:
                raise
            tags = github(repo, 'tags?per_page=1')
            tag = tags[0]['name']
            item['release_metadata_limitation'] = 'No GitHub latest release; first upstream tag used as candidate only'
        item['candidate_version'] = tag
        item['candidate_commit'] = github(repo, 'commits/' + tag)['sha']
        report, _ = audit_archive(repo, item['candidate_commit'], extract=False)
        item['source_license_files'] = report['license_files']
        item['source_manifest'] = 'reuse/files/' + repo.replace('/', '__') + '__' + item['candidate_commit'] + '.json'
        query = {'commit': item['candidate_commit']}
        try:
            vulnerabilities, evidence = fetch('https://api.osv.dev/v1/query', post=query)
            item['advisories'] = {'method': 'OSV commit query; coverage is ecosystem dependent and is not a transitive audit',
                                  'evidence': evidence, 'vulnerabilities': vulnerabilities.get('vulns', [])}
        except Exception as exc:
            item['advisories'] = {'status': 'blocked', 'error': str(exc)}
    item['blockers'] = ['Full transitive dependency license/advisory closure not qualified', 'No ExpertAuth behavior/build test evidence for this profile']
    return item

def profiles():
    baseline = json.loads((BASELINE / 'registry' / 'sdk-and-plugins.json').read_text())
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(audit_profile, profile): profile for profile in baseline['sdks'] + baseline['plugins']}
        for future in concurrent.futures.as_completed(futures):
            profile = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {**profile, 'qualification': 'blocked', 'error': str(exc)}
            results.append(result)
            print(json.dumps({'id': result['id'], 'version': result.get('candidate_version'), 'error': result.get('error')}), flush=True)
    results.sort(key=lambda item: item['id'])
    write(OUT / 'profiles.json', {'sdks': [item for item in results if item['id'].startswith('SDK')],
                                'plugins': [item for item in results if item['id'].startswith('PLG')],
                                'integrations': [{**item, 'qualification': 'unverified', 'blocker': 'No tested runtime/version combination'} for item in baseline['integrations']],
                                'coverage': {'sdk_profiles': 8, 'plugin_profiles': 14, 'integration_profiles': 10},
                                'selection_status': 'Candidates only. Pins do not imply compatibility or production acceptance.'})

def source_profiles():
    profiles_path = OUT / 'profiles.json'
    profiles = json.loads(profiles_path.read_text())
    examined = {}
    for item in profiles['sdks'] + profiles['plugins']:
        if not item.get('npm') or not item.get('candidate_commit'):
            continue
        key = (item['repository'], item['candidate_commit'])
        if key not in examined:
            try:
                examined[key] = audit_archive(*key)
            except Exception as exc:
                item['source_audit_error'] = str(exc)
                continue
        report, files = examined[key]
        item['source_manifest'] = 'reuse/files/' + key[0].replace('/', '__') + '__' + key[1] + '.json'
        item['source_license_files'] = report['license_files']
        matched = []
        for path, body in files.items():
            if Path(path).name != 'package.json':
                continue
            try:
                package = json.loads(body)
            except (ValueError, UnicodeError):
                continue
            if package.get('name') == item['npm']['name'] and package.get('version') == item['candidate_version']:
                matched.append({'source_path': path, 'sha256': sha(body), 'version': package.get('version'),
                                'license': package.get('license'), 'directory': str(Path(path).parent)})
        item['source_package_declarations'] = matched
        item['source_license_declarations'] = report['license_declarations']
        if 'README.md' in report['license_declarations']:
            item['license_declaration_evidence'] = report['license_declarations']['README.md']
            item['license_audit'] = 'Apache-2.0 declared in pinned README; missing license text and transitive closure remain review gaps'
        if not item['package_license_files']:
            item['notice_gap'] = 'Published npm archive omits license text. Retain pinned repository license and package provenance before redistribution.'
        print(json.dumps({'id': item['id'], 'source_packages': matched}), flush=True)
    write(profiles_path, profiles)

def auxiliary():
    results = []
    for repo in ('supertokens/supertokens-plugin-interface', 'supertokens/supertokens-postgresql-plugin', 'supertokens/supertokens-root'):
        try:
            release = github(repo, 'releases/latest')
            tag = release['tag_name']
        except HTTPError as exc:
            if exc.code != 404:
                raise
            info = github(repo, '')
            tag = info['default_branch']
        commit = github(repo, 'commits/' + tag)['sha']
        report, files = audit_archive(repo, commit, extract=True)
        record = {'repository': repo, 'candidate_release_or_ref': tag, 'commit': commit,
                  'license_files': report['license_files'], 'archive': report['archive'],
                  'source_manifest': 'reuse/files/' + repo.replace('/', '__') + '__' + commit + '.json',
                  'compatibility': 'Build and runtime qualification required'}
        if 'pluginInterfaceSupported.json' in files:
            record['plugin_interface_supported'] = json.loads(files['pluginInterfaceSupported.json'])
        results.append(record)
        print(json.dumps(record), flush=True)
    write(OUT / 'core-build-dependencies.json', results)

def jar_metadata(path):
    data = path.read_bytes()
    result = {'file': path.relative_to(ROOT).as_posix(), 'sha256': sha(data), 'bytes': len(data), 'notices': [], 'maven_properties': []}
    with zipfile.ZipFile(io.BytesIO(data)) as jar:
        for name in jar.namelist():
            if name.endswith('/'):
                continue
            if any(word in name.lower() for word in ('license', 'notice')) or name.upper() == 'META-INF/MANIFEST.MF':
                body = jar.read(name)
                result['notices'].append({'source_path': name, 'sha256': sha(body), 'bytes': len(body),
                                          'detected_license': license_id(body)})
                destination = OUT / 'licenses' / 'jars' / (path.name + '-' + sha(data)[:12]) / name
                if '..' in Path(name).parts or name.startswith('/'):
                    raise ValueError('Unsafe JAR metadata path')
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
                if name.upper() == 'META-INF/MANIFEST.MF':
                    result['manifest'] = body.decode('utf-8', errors='replace')
            if name.endswith('pom.properties'):
                result['maven_properties'].append({'source_path': name, 'content': jar.read(name).decode('utf-8', errors='replace')})
    return result

def bundled_jars():
    directory = CACHE / 'source' / 'supertokens__supertokens-core' / 'b2219c4aa019a501e4dfea76cf06ef802ca93fc0' / 'src' / 'main' / 'resources'
    result = [jar_metadata(path) for path in directory.glob('*.jar')]
    for item in result:
        item['decision'] = 'reference only; omit from source build pending byte-for-byte upstream provenance and nested dependency advisory closure'
    write(OUT / 'bundled-telemetry-jars.json', result)
    print(json.dumps({'bundled_telemetry_jars': len(result), 'runtime_approval': False}), flush=True)

def pom_license(group, name, version, seen=None):
    seen = set() if seen is None else seen
    key = (group, name, version)
    if key in seen or len(seen) >= 12:
        return {'error': 'POM inheritance cycle or depth limit'}
    seen.add(key)
    relative = group.replace('.', '/') + '/' + name + '/' + version + '/' + name + '-' + version + '.pom'
    failures = []
    for origin in ('https://repo.maven.apache.org/maven2/', 'https://build.shibboleth.net/nexus/content/repositories/releases/'):
        try:
            data, provenance = fetch(origin + relative, False)
            break
        except HTTPError as exc:
            failures.append({'url': origin + relative, 'status': exc.code})
    else:
        return {'errors': failures, 'licenses': []}
    document = ET.fromstring(data)
    # Valid Maven POMs exist both with and without an XML namespace (e.g. BC).
    for element in document.iter():
        element.tag = element.tag.rsplit('}', 1)[-1]
    def get(node, tag):
        child = node.find(tag)
        return child.text.strip() if child is not None and child.text else None
    licenses = [{get(child, 'name'): get(child, 'url')} for child in document.findall('licenses/license')]
    record = {'pom': provenance, 'licenses': licenses, 'coordinate': ':'.join(key)}
    target = OUT / 'licenses' / 'poms' / (group + '.' + name + '-' + version + '.pom')
    target.write_bytes(data)
    if not licenses:
        parent = document.find('parent')
        if parent is not None:
            parent_key = [get(parent, part) for part in ('groupId', 'artifactId', 'version')]
            if all(parent_key):
                record['inherited'] = pom_license(*parent_key, seen)
                record['licenses'] = record['inherited'].get('licenses', [])
    return record

def dependency_closure(input_path):
    source = Path(input_path)
    if not source.is_absolute():
        source = ROOT / source
    raw = source.read_bytes()
    parsed = json.loads(raw)
    dependencies = []
    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            if all(key in value for key in ('group', 'name', 'version')):
                dependencies.append(value)
            else:
                for child in value.values():
                    visit(child)
    visit(parsed)
    unique = {':'.join(str(item[key]) for key in ('group', 'name', 'version')): item for item in dependencies}
    (OUT / 'licenses' / 'poms').mkdir(parents=True, exist_ok=True)
    def inspect(item):
        coordinate = ':'.join(str(item[key]) for key in ('group', 'name', 'version'))
        result = {'coordinate': coordinate, 'build_record': item, 'license': pom_license(item['group'], item['name'], item['version']),
                  'decision': 'depend candidate; unmodified upstream Maven artifact', 'modifications': [],
                  'requirements': ['BAS-002', 'BAS-004'], 'mapped_requirement_note': 'Provenance and exclusion association; does not verify whole requirement'}
        query = {'package': {'ecosystem': 'Maven', 'name': item['group'] + ':' + item['name']}, 'version': item['version']}
        try:
            vulnerabilities, evidence = fetch('https://api.osv.dev/v1/query', post=query)
            result['advisories'] = {'evidence': evidence, 'vulnerabilities': vulnerabilities.get('vulns', [])}
        except Exception as exc:
            result['advisories'] = {'error': str(exc)}
        name = Path(item.get('filename', item.get('file', ''))).name or item['name'] + '-' + item['version'] + '.jar'
        jars = list((ROOT / '.cache' / 'engine-build').rglob(name))
        if jars:
            result['jar'] = jar_metadata(jars[0])
            expected_hash = item.get('sha256')
            result['build_hash_matches'] = None if expected_hash is None else expected_hash == result['jar']['sha256']
        else:
            result['artifact_blocker'] = 'JAR not found under .cache/engine-build'
        result['license_review'] = 'unreviewed' if not result['license'].get('licenses') else 'declared license captured; distribution obligations require review'
        return result
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(inspect, unique.values()):
            results.append(result)
            print(json.dumps({'coordinate': result['coordinate'], 'licenses': result['license'].get('licenses'),
                              'vulnerabilities': len(result.get('advisories', {}).get('vulnerabilities', []))}), flush=True)
    results.sort(key=lambda item: item['coordinate'])
    write(OUT / 'runtime-dependencies.json', {'input': str(source.relative_to(ROOT)), 'input_sha256': sha(raw),
                                            'dependencies': results, 'runtime_approval': False,
                                            'limitations': ['Maven POM declarations and JAR notices are evidence, not a legal opinion',
                                                            'OSV query coverage does not prove absence of vulnerabilities',
                                                            'Image OS/build-tool dependencies are outside this Maven closure']})

def validate_audit():
    baseline = json.loads((BASELINE / 'registry' / 'sdk-and-plugins.json').read_text())
    profiles = json.loads((OUT / 'profiles.json').read_text())
    checks = []
    for group, count in (('sdks', 8), ('plugins', 14), ('integrations', 10)):
        original_ids = [item['id'] for item in baseline[group]]
        retained_ids = [item['id'] for item in profiles[group]]
        passed = set(original_ids) == set(retained_ids) and len(retained_ids) == len(set(retained_ids)) == count
        checks.append({'test': 'reuse-profile-retention-' + group, 'passed': passed, 'count': len(retained_ids)})
    for profile in profiles['sdks'] + profiles['plugins']:
        passed = bool(re.fullmatch('[0-9a-f]{40}', profile.get('candidate_commit', ''))) and bool(profile.get('candidate_version'))
        checks.append({'test': 'immutable-candidate-' + profile['id'], 'passed': passed})
        if profile.get('source_manifest'):
            manifest = ROOT / profile['source_manifest']
            checks.append({'test': 'source-manifest-' + profile['id'], 'passed': manifest.is_file()})
        if profile.get('package_manifest'):
            manifest = ROOT / profile['package_manifest']
            checks.append({'test': 'package-manifest-' + profile['id'], 'passed': manifest.is_file()})
    core = json.loads((OUT / 'files' / 'supertokens__supertokens-core__b2219c4aa019a501e4dfea76cf06ef802ca93fc0.json').read_text())
    checks.append({'test': 'core-no-ee-content-in-manifest', 'passed': all(not item['source_path'].startswith('ee/') for item in core['files'])})
    checks.append({'test': 'core-restricted-paths-not-inspected', 'passed': len(core['excluded_files']) == 23 and all(not item['content_inspected'] and item['sha256'] is None for item in core['excluded_files'])})
    checks.append({'test': 'no-profile-functional-success-claims', 'passed': all(item['qualification'] != 'verified' for group in ('sdks', 'plugins', 'integrations') for item in profiles[group])})
    result = {'kind': 'Source audit consistency only; not authentication implementation tests', 'checks': checks,
              'passed': sum(item['passed'] for item in checks), 'failed': sum(not item['passed'] for item in checks),
              'script_sha256': sha(Path(__file__).read_bytes()),
              'inputs': {path.relative_to(ROOT).as_posix(): sha(path.read_bytes()) for path in (OUT / 'profiles.json', BASELINE / 'registry' / 'sdk-and-plugins.json')}}
    write(EVIDENCE / 'audit-validation.json', result)
    print(json.dumps({key: result[key] for key in ('kind', 'passed', 'failed')}), flush=True)
    if result['failed']:
        raise RuntimeError('Source audit consistency failed')

def bind_build():
    build_path = ROOT / 'evidence' / 'build' / 'oss-core' / 'command.json'
    build = json.loads(build_path.read_text())
    if build.get('exit_code') != 0:
        raise ValueError('Cannot bind failed build as source compilation evidence')
    indexed = {}
    rows = []
    for entry in build['source_files']:
        key = (entry['repository'], entry['commit'])
        if key not in indexed:
            candidate = OUT / 'files' / (key[0].replace('/', '__') + '__' + key[1] + '.json')
            manifest = json.loads(candidate.read_text())
            indexed[key] = {item['source_path']: item for item in manifest['files']}
        source = indexed[key][entry['path']]
        if source['sha256'] != entry['sha256']:
            raise ValueError('Build source hash differs from audited archive: ' + entry['path'])
        rows.append({**source, 'decision': 'depend',
                     'dependency_boundary': 'Source-built engine candidate used only for local foundation proof',
                     'destination': '.cache/engine-build/' + entry['repository'].split('/')[-1] + '/' + entry['path'],
                     'build_declaration': 'tools/build_oss_core.py', 'mapped_requirements': ['BAS-002', 'BAS-004', 'BAS-005'],
                     'validation': 'Hash matched to successful source build input; no runtime parity or security qualification implied',
                     'evidence': 'evidence/build/oss-core/command.json'})
    dependencies_path = OUT / 'runtime-dependencies.json'
    dependency_report = json.loads(dependencies_path.read_text())
    artifacts = dependency_report['dependencies']
    if any(not item.get('build_hash_matches') or not item['license'].get('licenses') for item in artifacts):
        raise ValueError('Unresolved runtime artifact hash/license declaration')
    result = {'source_build_evidence': build_path.relative_to(ROOT).as_posix(), 'source_build_evidence_sha256': sha(build_path.read_bytes()),
              'runtime_dependency_evidence': dependencies_path.relative_to(ROOT).as_posix(), 'runtime_dependency_evidence_sha256': sha(dependencies_path.read_bytes()),
              'source_files': rows, 'local_proof_license_boundary': 'Eligible for local testing under captured OSS license terms; no restricted EE runtime dependency found',
              'release_approved': False, 'release_blockers': ['LGPL/EPL complete source, notices, replacement/relink and distribution obligations require final review',
                                                           'Native library nested source provenance not fully qualified',
                                                           'OS image and build tooling dependency boundaries require separate audit',
                                                           'Independent security review and full parity tests remain outstanding']}
    write(OUT / 'actual-build-files.json', result)
    components = []
    for item in artifacts:
        dependency = item['build_record']
        purl = 'pkg:maven/' + dependency['group'] + '/' + dependency['name'] + '@' + dependency['version']
        components.append({'type': 'library', 'bom-ref': purl, 'purl': purl, 'group': dependency['group'],
                           'name': dependency['name'], 'version': dependency['version'],
                           'hashes': [{'alg': 'SHA-256', 'content': item['jar']['sha256']}],
                           'licenses': [{'license': {'name': name, 'url': url}} for license in item['license']['licenses'] for name, url in license.items()],
                           'properties': [{'name': 'expertauth:source-evidence', 'value': 'reuse/runtime-dependencies.json'},
                                          {'name': 'expertauth:distribution-approval', 'value': 'pending'}]})
    write(OUT / 'oss-core-runtime.cdx.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                                           'metadata': {'component': {'type': 'application', 'name': 'expertauth-oss-core-foundation-proof', 'version': 'partial-12.2.0'},
                                                        'properties': [{'name': 'expertauth:scope', 'value': '84 Maven runtime dependencies only; excludes OS, build tooling, SDKs, and omitted telemetry resources'}]},
                                           'components': components})
    validation = {'kind': 'Actual source build to source audit binding; not runtime qualification', 'source_files_bound': len(rows),
                  'runtime_dependencies_bound': len(components), 'declared_licenses_captured': len(components),
                  'hash_mismatches': 0, 'build_exit_code': build['exit_code'], 'release_approved': False,
                  'input_sha256': {'build': sha(build_path.read_bytes()), 'runtime_dependencies': sha(dependencies_path.read_bytes())}}
    write(EVIDENCE / 'build-binding.json', validation)
    print(json.dumps(validation), flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine-probe', action='store_true')
    parser.add_argument('--core-source', action='store_true')
    parser.add_argument('--profiles', action='store_true')
    parser.add_argument('--source-profiles', action='store_true')
    parser.add_argument('--auxiliary', action='store_true')
    parser.add_argument('--bundled-jars', action='store_true')
    parser.add_argument('--dependencies')
    parser.add_argument('--validate', action='store_true')
    parser.add_argument('--bind-build', action='store_true')
    args = parser.parse_args()
    if args.engine_probe:
        engine_probe()
    if args.core_source:
        core_source()
    if args.profiles:
        profiles()
    if args.source_profiles:
        source_profiles()
    if args.auxiliary:
        auxiliary()
    if args.bundled_jars:
        bundled_jars()
    if args.dependencies:
        dependency_closure(args.dependencies)
    if args.validate:
        validate_audit()
    if args.bind_build:
        bind_build()

if __name__ == '__main__':
    class Tee:
        def __init__(self, original):
            self.original, self.parts = original, []
        def write(self, text):
            self.parts.append(text)
            return self.original.write(text)
        def flush(self):
            self.original.flush()
    started = datetime.datetime.now(datetime.timezone.utc)
    stdout, stderr = Tee(sys.stdout), Tee(sys.stderr)
    sys.stdout, sys.stderr = stdout, stderr
    exit_status = 0
    try:
        main()
    except Exception:
        exit_status = 1
        traceback.print_exc()
    finally:
        write(EVIDENCE / 'runs' / (started.strftime('%Y%m%dT%H%M%S%fZ') + '.json'), {
            'command_argv': sys.argv, 'started_at': started.isoformat(),
            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'python': sys.version, 'script_sha256': sha(Path(__file__).read_bytes()),
            'stdout': ''.join(stdout.parts), 'stderr': ''.join(stderr.parts), 'exit_status': exit_status})
    raise SystemExit(exit_status)
