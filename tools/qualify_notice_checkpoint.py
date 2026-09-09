"""Test an extracted source ZIP against the installed image using verified cache hardlinks.

No image build or service start. Source/dependency caches are read-only inputs;
the isolated extraction and generated notice context are retired afterward.
The adjacent artifact report is outside the ZIP to avoid self-reference.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
from package_checkpoint import safe

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def resources():
    commands = {
        'containers': ['ps', '-a', '--no-trunc', '--filter', 'name=expertauth',
                       '--format', '{{.ID}} {{.Names}} {{.Image}}'],
        'images': ['image', 'ls', '--no-trunc', '--filter', 'reference=expertauth*',
                   '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'],
        'networks': ['network', 'ls', '--filter', 'name=expertauth', '--format', '{{.ID}} {{.Name}}'],
        'volumes': ['volume', 'ls', '--filter', 'name=expertauth', '--format', '{{.Name}}'],
    }
    return {kind: sorted(subprocess.run(['docker', *argv], capture_output=True, text=True,
                                       check=True, timeout=30).stdout.splitlines())
            for kind, argv in commands.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    archive = args.archive.resolve()
    need(archive.parent == (ROOT / 'artifacts').resolve(), 'Only local checkpoint artifacts are accepted')
    need(sha(archive.read_bytes()) == args.sha256, 'Source ZIP identity mismatch')
    output = archive.with_suffix('.runtime-validation.json')
    need(not output.exists(), 'Preserve prior extracted-runtime evidence')
    report = {'schema': 'expertauth-extracted-notice-image-verification-v1',
              'started': datetime.now(timezone.utc).isoformat(), 'archive': archive.name,
              'zip_sha256': args.sha256, 'tool_sha256': sha(Path(__file__).read_bytes()),
              'passed': False, 'build_executed': False, 'services_started': False,
              'authentication_complete': False, 'native_build_qualified': False,
              'full_distribution_approved': False, 'errors': []}
    cache = (ROOT / '.cache').resolve()
    copied_sources = []
    temporary = None
    try:
        report['resources_before'] = resources()
        with tempfile.TemporaryDirectory(prefix='extracted-notice-', dir=cache) as directory:
            temporary = Path(directory).resolve()
            need(temporary.parent == cache and cache.is_relative_to(ROOT.resolve()), 'Extraction cleanup boundary')
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
                need(len(names) == len(set(names)) and bundle.testzip() is None, 'Invalid source archive')
                manifest = json.loads(bundle.read('expert-auth/CHECKPOINT_MANIFEST.json'))
                entries = {row['path']: row for row in manifest['files']}
                need(len(entries) == len(manifest['files']) and len(names) == len(entries) + 1, 'ZIP inventory differs')
                for name in names:
                    safe(name)
                    need(name.startswith('expert-auth/'), 'Unexpected checkpoint root')
                    raw = bundle.read(name)
                    if name != 'expert-auth/CHECKPOINT_MANIFEST.json':
                        expected = entries[name.removeprefix('expert-auth/')]
                        need(len(raw) == expected['bytes'] and sha(raw) == expected['sha256'], 'Checkpoint member changed')
                    destination = temporary / name
                    need(destination.resolve().is_relative_to(temporary), 'Archive member escaped extraction')
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(raw)
            extracted = temporary / 'expert-auth'
            report['source_commit'] = manifest['commit']
            report['zip_files_verified'] = len(names)
            # These two inventories cover the 87 built runtime JARs and 83 source
            # siblings consumed by the extracted notice/image verifier.
            runtime = json.loads((extracted / 'evidence/build/oss-core/artifacts.json').read_bytes())
            sources = json.loads((extracted / 'reuse/runtime-source-archives.lock.json').read_bytes())['entries']
            requested = [('.cache/engine-build/' + row['path'], row['sha256']) for row in runtime]
            requested += [(row['path'], row['sha256']) for row in sources if row['status'] == 'available']
            need(len(requested) == len(set(p for p, _ in requested)) == 170, 'Cache input inventory differs')
            for relative, digest in requested:
                source = (ROOT / relative).resolve()
                need(source.is_relative_to(cache) and source.is_file() and sha(source.read_bytes()) == digest,
                     'Canonical cache source changed or escaped')
                destination = extracted / relative
                need(destination.resolve().is_relative_to(extracted / '.cache'), 'Extracted cache path escaped')
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.link(source, destination)
                copied_sources.append((source, digest))
            report['cache_files_reused_as_hardlinks'] = len(copied_sources)
            report['cache_bytes_reused_without_copy'] = sum(p.stat().st_size for p, _ in copied_sources)
            command = [sys.executable, '-B', 'tools/build_oss_runtime.py', '--verify-existing',
                       '--evidence-name', 'fresh-source-checkpoint']
            # The inner helper bounds each Docker command and owns its finally
            # cleanup. Do not kill that parent while it may own a live child.
            result = subprocess.run(command, cwd=extracted, capture_output=True)
            report['command'] = command
            report['exit_code'] = result.returncode
            report['stdout'] = result.stdout.decode('utf-8', errors='replace')
            report['stderr'] = result.stderr.decode('utf-8', errors='replace')
            evidence = extracted / 'evidence/runtime/oss-core-notices/fresh-source-checkpoint'
            if (evidence / 'report.json').exists():
                inner = json.loads((evidence / 'report.json').read_bytes())
                report['image_verification'] = inner
                report['retained_command_logs'] = []
                for row in inner['commands']:
                    raw = (evidence / row['log']).read_bytes()
                    need(sha(raw) == row['sha256'], 'Extracted command log identity differs')
                    report['retained_command_logs'].append({'log': row['log'], 'sha256': row['sha256'],
                                                             'text': raw.decode('utf-8', errors='replace')})
                report['notice_manifest'] = json.loads((evidence / 'notice-manifest.json').read_bytes())
                need(inner['status'] == 'IMAGE_CONTENTS_VERIFIED' and inner['build_executed'] is False and
                     inner['services_started'] is False and inner['image_tag_promoted'] is False and
                     inner['inspection_container_removed'] and inner['scratch_removed'] and
                     inner['installed_file_count'] == 479, 'Extracted image verification incomplete')
                need(all(sha((extracted / path).read_bytes()) == digest for path, digest in inner['source_sha256'].items()),
                     'Extracted verifier inputs changed')
            else:
                raise ValueError('Extracted image report missing')
            need(result.returncode == 0, 'Extracted verifier command failed')
            need(all(sha(source.read_bytes()) == digest for source, digest in copied_sources), 'Canonical cache changed')
            report['canonical_cache_hashes_unchanged'] = True
            # The temporary root contains hardlinks, never directory junctions.
            need(not any(p.is_symlink() for p in temporary.rglob('*')), 'Unexpected link in extraction')
            report['passed'] = True
    except Exception as error:
        report['passed'] = False
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    try:
        report['resources_after'] = resources()
        need(report['resources_after'] == report.get('resources_before'), 'Task resource inventory changed')
        report['canonical_cache_hashes_unchanged'] = all(sha(source.read_bytes()) == digest
                                                       for source, digest in copied_sources)
        need(report['canonical_cache_hashes_unchanged'], 'Canonical cache changed')
    except Exception as error:
        report['passed'] = False
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    report['extraction_removed'] = temporary is None or not temporary.exists()
    report['finished'] = datetime.now(timezone.utc).isoformat()
    report['passed'] = report['passed'] and report['extraction_removed']
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'report': str(output), 'passed': report['passed'], 'errors': report['errors'],
                      'extraction_removed': report['extraction_removed'], 'build_executed': False,
                      'files_verified': report.get('image_verification', {}).get('installed_file_count')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
