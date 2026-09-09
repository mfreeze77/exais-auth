"""Verify actual notice-package bytes and scope against the prior installed manifest."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile
from assemble_runtime_licenses import assemble
from fetch_runtime_notice_sources import ROOT, require, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to((ROOT / 'evidence/reuse/native-correspondence/notice-packaging').resolve())
            and not output.exists(), 'Use new bounded notice evidence directory')
    previous_path = ROOT / 'evidence/runtime/oss-core-notices/preserved-notices-01/notice-manifest.json'
    previous = json.loads(previous_path.read_bytes())
    output.mkdir(parents=True)
    cache = (ROOT / '.cache').resolve()
    with tempfile.TemporaryDirectory(prefix='notice-revision-', dir=cache) as temporary:
        scratch = Path(temporary).resolve()
        require(scratch.parent == cache, 'Notice scratch cleanup boundary')
        destination = scratch / 'licenses'
        current = assemble(destination)
        for row in current['files']:
            raw = (destination / row['path']).read_bytes()
            require((len(raw), sha(raw)) == (row['bytes'], row['sha256']), 'Generated notice bytes differ')
        old = {row['path']: row['sha256'] for row in previous['files']}
        new = {row['path']: row['sha256'] for row in current['files']}
        added = sorted(new.keys() - old.keys())
        changed = sorted(path for path in old.keys() & new.keys() if old[path] != new[path])
        expected = ['com/lambdaworks/scrypt/1.4.0/supplemental/' + name + '.NOTICE'
                    for name in ['crypto_scrypt.h', 'sha256.h', 'sysendian.h']]
        expected += ['net.java.dev.jna/jna/5.8.0/binary/META-INF/' + name for name in ['AL2.0', 'LGPL2.1']]
        # Coordinate directories use dots within the Maven group, not slashes.
        expected = [name.replace('com/lambdaworks/', 'com.lambdaworks/') for name in expected]
        require(added == sorted(expected) and not old.keys() - new.keys(), 'Unexpected notice addition/removal')
        require(set(changed).issubset({'docs/runtime-image-notices.md', 'runtime-image-notices.md', 'THIRD_PARTY_NOTICES.md'}),
                'Existing third-party notice changed')
        require({row['coordinate']: row['runtime_jar_sha256'] for row in previous['dependencies']} ==
                {row['coordinate']: row['runtime_jar_sha256'] for row in current['dependencies']}, 'Runtime JAR identity changed')
        (output / 'notice-manifest.json').write_bytes((destination / 'manifest.json').read_bytes())
        report = {'schema': 'expertauth-notice-revision-v1', 'passed': True,
                  'previous_manifest': {'path': previous_path.relative_to(ROOT).as_posix(), 'sha256': sha(previous_path.read_bytes())},
                  'current_manifest_sha256': sha((destination / 'manifest.json').read_bytes()),
                  'tool_sha256': sha(Path(__file__).read_bytes()), 'input_sha256': current['input_sha256'],
                  'added': added, 'changed': changed, 'files_verified': len(current['files']),
                  'archive_notice_texts': current['binary_notice_text_count'] + current['source_notice_text_count'],
                  'source_header_notices': len(current['source_header_notices']), 'runtime_dependencies_unchanged': 84,
                  'docker_resources_created': 0, 'image_contents_verified': False,
                  'native_build_qualified': False, 'license_approved': False, 'authentication_complete': False}
    report['scratch_removed'] = not scratch.exists()
    require(report['scratch_removed'], 'Notice scratch remains')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ['passed', 'files_verified', 'archive_notice_texts',
                                                  'source_header_notices', 'scratch_removed', 'image_contents_verified']}))


if __name__ == '__main__':
    main()
