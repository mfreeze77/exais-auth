"""Qualify representative applications from an exact PARTIAL source ZIP.

Uses only freshly extracted application/probe code, exact locks and pinned base
images. Reuses the explicitly named existing private Core/database; this is not
a fresh full-stack restore, full parity acceptance, or production approval.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import uuid
import zipfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
NODE = 'node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436'
PYTHON = 'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'
BROWSER = 'mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e'
MANIFEST = 'expert-auth/CHECKPOINT_MANIFEST.json'
FORBIDDEN = {'.git', '.runtime', '.cache', 'node_modules', 'artifacts'}
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'{prefix}{i}' for prefix in ('COM', 'LPT') for i in range(1, 10))}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '\\' not in name and ':' not in name and '\x00' not in name,
            'Unsafe archive path')
    require(name == str(path) and all(part not in ('.', '..', '') for part in path.parts), 'Noncanonical archive path')
    require(path.parts[0] == 'expert-auth' and len(path.parts) > 1, 'Unexpected archive root')
    for part in path.parts:
        require(part.casefold() not in FORBIDDEN and part == part.rstrip(' .'), 'Forbidden archive directory or Windows alias')
        require(part.split('.')[0].upper() not in RESERVED, 'Windows reserved archive path')
        require(not any(ord(char) < 32 for char in part), 'Control character in archive path')
    require(path.name == '.env.example' or not (path.name.casefold() == '.env' or path.name.casefold().startswith('.env.')), 'Environment file in checkpoint')
    return path


def inspect_archive(archive):
    infos = archive.infolist()
    require(0 < len(infos) <= 20_000, 'Archive member count exceeds bound')
    require(sum(info.file_size for info in infos) <= 512 * 1024 * 1024, 'Archive expansion exceeds bound')
    names = set()
    for info in infos:
        safe_name(info.filename)
        folded = info.filename.casefold()
        require(folded not in names, 'Duplicate or case-colliding archive member')
        names.add(folded)
        require(not info.is_dir() and not info.flag_bits & 1, 'Directory or encrypted member is unsupported')
        kind = stat.S_IFMT(info.external_attr >> 16)
        require(kind in (0, stat.S_IFREG), 'Symlink or special archive member')
        require(info.file_size <= 128 * 1024 * 1024, 'Archive member exceeds bound')
        require(info.file_size <= max(1, info.compress_size) * 250, 'Suspicious archive expansion ratio')
    require(MANIFEST.casefold() in names, 'Checkpoint manifest missing')
    manifest = json.loads(archive.read(MANIFEST))
    require(manifest.get('kind') == 'PARTIAL_SOURCE_CHECKPOINT' and manifest.get('complete') is False,
            'Expected explicitly partial checkpoint manifest')
    require(re.fullmatch(r'[0-9a-f]{40}', manifest.get('commit', '')) is not None, 'Invalid source commit')
    expected = {}
    require(isinstance(manifest.get('files'), list), 'Manifest file inventory missing')
    for row in manifest['files']:
        require(isinstance(row, dict) and isinstance(row.get('path'), str), 'Malformed manifest row')
        name = 'expert-auth/' + row['path']
        safe_name(name)
        require(name != MANIFEST and name not in expected, 'Duplicate or self-referencing manifest row')
        require(type(row.get('bytes')) is int and row['bytes'] >= 0, 'Invalid manifest byte count')
        require(re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')) is not None, 'Invalid manifest file hash')
        expected[name] = row
    require(set(info.filename for info in infos) == set(expected) | {MANIFEST}, 'Manifest/archive membership differs')
    for info in infos:
        if info.filename == MANIFEST:
            continue
        expected_row = expected[info.filename]
        require(info.file_size == expected_row['bytes'], 'Manifest byte count differs')
        require(sha(archive.read(info)) == expected_row['sha256'], 'Manifest content hash differs')
    require(archive.testzip() is None, 'ZIP CRC validation failed')
    return manifest


def extract_verified(zip_path, checksum, directory):
    require(re.fullmatch(r'[0-9a-f]{64}', checksum) is not None, 'Expected SHA-256 must be explicit lowercase hex')
    require(sha(zip_path.read_bytes()) == checksum, 'Checkpoint ZIP SHA-256 mismatch')
    require(not directory.exists(), 'Never overwrite a previous extraction')
    directory.mkdir(parents=True)
    with zipfile.ZipFile(zip_path) as archive:
        manifest = inspect_archive(archive)
        for info in archive.infolist():
            target = directory.joinpath(*PurePosixPath(info.filename).parts)
            require(target.resolve().is_relative_to(directory.resolve()), 'Extraction escaped target')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output:
                output.write(archive.read(info))
    return directory / 'expert-auth', manifest


def retire_scratch(directory, report):
    """Remove only this generated extraction after preserving private diagnostics."""
    cache = (ROOT / '.cache/extracted-checkpoints').resolve()
    directory = directory.resolve()
    require(cache.is_relative_to(ROOT.resolve()) and directory.parent == cache and directory != cache,
            'Scratch retirement outside exact extraction boundary')
    if not directory.exists():
        return
    backup = (ROOT / '.runtime/retired-proof-logs' / directory.name).resolve()
    require((ROOT / '.runtime').resolve().is_relative_to(ROOT.resolve()) and
            backup.is_relative_to((ROOT / '.runtime').resolve()) and not backup.exists(), 'Private backup path conflict')
    backup.mkdir(parents=True)
    retained = []
    for source in (directory / 'raw-command-logs', directory / 'source/expert-auth/.runtime/extracted-proof/evidence'):
        if source.exists():
            shutil.copytree(source, backup / source.name)
            for original in source.rglob('*'):
                if original.is_file():
                    copied = backup / source.name / original.relative_to(source)
                    require(sha(original.read_bytes()) == sha(copied.read_bytes()), 'Private diagnostics backup differs')
                    retained.append({'path': copied.relative_to(backup).as_posix(), 'sha256': sha(copied.read_bytes())})
    (backup / 'manifest.json').write_text(json.dumps({'files': retained}, indent=2) + '\n')
    for command in report['commands']:
        old = Path(command['private_raw_log'])
        command['private_raw_log'] = str((backup / 'raw-command-logs' / old.name).relative_to(ROOT))
    report['private_diagnostics_retained'] = str(backup.relative_to(ROOT))
    # Both source and target were resolved/checked above. No repository or data
    # volume is removed, and extracted source remains reproducible from the ZIP.
    shutil.rmtree(directory)
    report['scratch_removed'] = str(directory.relative_to(ROOT))


class ArchiveGateTests(unittest.TestCase):
    def archive(self, mutation=None):
        files = {'expert-auth/README.md': b'synthetic archive integrity fixture'}
        manifest = {'kind': 'PARTIAL_SOURCE_CHECKPOINT', 'complete': False, 'commit': '1' * 40,
                    'files': [{'path': 'README.md', 'bytes': len(files['expert-auth/README.md']),
                               'sha256': sha(files['expert-auth/README.md'])}]}
        if mutation:
            mutation(files, manifest)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as target:
            for name, body in files.items():
                item = zipfile.ZipInfo(name)
                item.external_attr = (stat.S_IFLNK if name.endswith('link') else stat.S_IFREG) << 16
                target.writestr(item, body)
            target.writestr(MANIFEST, json.dumps(manifest))
        buffer.seek(0)
        return zipfile.ZipFile(buffer)

    def denied(self, mutation):
        with self.archive(mutation) as archive, self.assertRaises((ValueError, KeyError)):
            inspect_archive(archive)

    def test_valid_synthetic_integrity_only(self):
        with self.archive() as archive:
            self.assertFalse(inspect_archive(archive)['complete'])

    def test_changed_file_hash(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/README.md': b'changed'}))

    def test_missing_manifest_member(self):
        self.denied(lambda files, manifest: files.clear())

    def test_unlisted_member(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/extra': b'x'}))

    def test_path_traversal(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/../../outside': b'x'}))

    def test_windows_drive(self):
        self.denied(lambda files, manifest: files.update({'C:/outside': b'x'}))

    def test_symlink(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/link': b'../../outside'}))

    def test_case_collision(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/readme.md': b'x'}))

    def test_environment_secret(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/.env': b'fixture'}))

    def test_windows_reserved_name(self):
        self.denied(lambda files, manifest: files.update({'expert-auth/NUL.txt': b'x'}))

    def test_scratch_retirement_cannot_remove_repository(self):
        for target in (ROOT, ROOT / 'evidence', ROOT / '.cache/extracted-checkpoints'):
            with self.assertRaises(ValueError):
                retire_scratch(target, {'commands': []})

    def test_scratch_retirement_preserves_actual_diagnostics(self):
        cache = ROOT / '.cache/extracted-checkpoints'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='hygiene-self-test-', dir=cache) as temporary:
            scratch = Path(temporary)
            raw = scratch / 'raw-command-logs/01.log'
            raw.parent.mkdir()
            raw.write_bytes(b'actual filesystem preservation fixture')
            evidence = scratch / 'source/expert-auth/.runtime/extracted-proof/evidence'
            evidence.mkdir(parents=True)
            (evidence / 'diagnostic.json').write_bytes(b'{"fixture": true}')
            report = {'commands': [{'private_raw_log': str(raw.relative_to(ROOT))}]}
            retire_scratch(scratch, report)
            backup = (ROOT / report['private_diagnostics_retained']).resolve()
            try:
                self.assertFalse(scratch.exists())
                self.assertEqual((ROOT / report['commands'][0]['private_raw_log']).read_bytes(),
                                 b'actual filesystem preservation fixture')
                self.assertEqual(len(json.loads((backup / 'manifest.json').read_text())['files']), 2)
                self.assertEqual((backup / 'evidence/diagnostic.json').read_bytes(), b'{"fixture": true}')
            finally:
                require(backup.parent == (ROOT / '.runtime/retired-proof-logs').resolve() and
                        backup.name.startswith('hygiene-self-test-'), 'Test backup cleanup boundary')
                shutil.rmtree(backup)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--core-env', type=Path, default=ROOT / '.runtime/oss-core/runtime.env')
    parser.add_argument('--core-container', default='expertauth-oss-core-a')
    parser.add_argument('--network', default='expertauth-oss-proof')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--no-cache', action='store_true', help='Explicit clean dependency-layer rebuild for a declared reproducibility check')
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveGateTests))
        return 0 if result.wasSuccessful() and result.testsRun == 12 else 1
    require(args.zip is not None and args.sha256 is not None, 'Supply --zip and independently supplied --sha256')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    name = 'expertauth-extracted-' + stamp.lower()
    extraction = ROOT / '.cache/extracted-checkpoints' / stamp
    evidence = ROOT / 'evidence/extracted-checkpoint' / stamp
    evidence.mkdir(parents=True, exist_ok=False)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'source_zip': str(args.zip.resolve()),
              'expected_zip_sha256': args.sha256, 'wrapper_sha256': sha(Path(__file__).read_bytes()),
              'status': 'BLOCKED', 'complete': False, 'foundation_passed': False, 'full_stack_restore': False,
              'commands': [], 'source_changed_during_tests': None, 'test_results': {},
              'limits': ['Uses existing owned Core and PostgreSQL; no fresh full-stack deployment, data restore or migration qualification',
                         'Representative Node/React and Python password/session profiles only',
                         'No original requirement/API/SDK family closure or independent security review',
                         'Synthetic users remain in the isolated existing Core database']}
    private_logs = extraction / 'raw-command-logs'
    private_logs.mkdir(parents=True, exist_ok=False)
    # Reserve only a private logs sibling; the actual extraction destination remains new.
    extraction = extraction / 'source'
    key = ''
    started_containers = []
    temporary_images = []

    def redact(value):
        if key:
            value = value.replace(key, '[REDACTED_CORE_KEY]')
        value = re.sub(r'(?:Synthetic|Browser)-[0-9a-f-]{36}-(?:a9|9a)!(?:wrong)?', '[REDACTED_PASSWORD]', value)
        value = re.sub(r'P9![0-9a-f]{32}', '[REDACTED_PASSWORD]', value)
        # Raw logs stay in ignored private cache. Release logs suppress long opaque credentials too.
        return re.sub(r'[A-Za-z0-9_+/=.-]{64,}', '[REDACTED_LONG_VALUE]', value)

    def run(argv, *, cwd=None, required=True, timeout=240):
        if argv[:3] == ['docker', 'run', '--rm']:
            # --rm alone does not remove a still-running container if the Docker
            # client times out. Record a unique name for the outer finally too.
            job = name + '-job-' + str(len(report['commands']) + 1)
            argv = argv[:3] + ['--name', job] + argv[3:]
            started_containers.append(job)
        begin = time.monotonic()
        process = subprocess.run(argv, cwd=cwd or ROOT, capture_output=True, timeout=timeout)
        raw = process.stdout + process.stderr
        number = len(report['commands']) + 1
        raw_path = private_logs / f'{number:02d}.log'
        raw_path.write_bytes(raw)
        log = evidence / f'command-{number:02d}.log'
        log.write_text(redact(raw.decode('utf8', errors='replace')), encoding='utf8')
        report['commands'].append({'argv': argv, 'cwd': str(cwd or ROOT), 'exit_code': process.returncode,
                                   'elapsed_seconds': round(time.monotonic() - begin, 3),
                                   'redacted_log': log.name, 'raw_output_sha256': sha(raw),
                                   'redacted_output_sha256': sha(log.read_bytes()),
                                   'private_raw_log': str(raw_path.relative_to(ROOT))})
        if required:
            require(process.returncode == 0, f'Command {number} failed with exit {process.returncode}')
        return process

    try:
        repo, manifest = extract_verified(args.zip.resolve(), args.sha256, extraction)
        report.update({'source_commit': manifest['commit'], 'verified_manifest_files': len(manifest['files']),
                       'manifest_sha256': sha((repo / 'CHECKPOINT_MANIFEST.json').read_bytes()),
                       'extracted_repository': str(repo.relative_to(ROOT)), 'zip_integrity_passed': True})
        # Select only nonsensitive Docker fields. Never capture full inspect environments.
        core = json.loads(run(['docker', 'inspect', args.core_container, '--format',
                              '{"image":"{{.Image}}","running":{{.State.Running}}}']).stdout)
        network = json.loads(run(['docker', 'network', 'inspect', args.network, '--format',
                                 '{"internal":{{.Internal}}}']).stdout)
        require(core['running'] and network['internal'], 'Existing Core must run on an internal network')
        report['reused_dependency'] = {'container': args.core_container, 'image': core['image'],
                                       'network': args.network, 'network_internal': True,
                                       'database': 'Existing isolated PostgreSQL state; not recreated/restored by this qualification'}
        for line in args.core_env.read_text().splitlines():
            if line.startswith('EXPERTAUTH_CORE_API_KEY='):
                key = line.partition('=')[2]
        require(len(key) >= 20 and '\n' not in key, 'Owned Core API key prerequisite missing')
        runtime = repo / '.runtime/extracted-proof'
        runtime.mkdir(parents=True)
        env_path = runtime / 'core-key.env'
        env_path.write_text('EXPERTAUTH_CORE_API_KEY=' + key + '\n')
        raw_evidence = runtime / 'evidence'
        raw_evidence.mkdir()
        node_image, python_image = name + '-node:proof', name + '-python:proof'
        # Fresh extracted contexts remain the only input. Cache reuse is valid for
        # identical content; force a clean build only for an explicit check.
        temporary_images = [node_image, python_image]
        build_flags = ['--no-cache'] if args.no_cache else []
        for image, context in [(node_image, 'examples/node-react'), (python_image, 'examples/python')]:
            run(['docker', 'build', *build_flags, '--label', 'org.expertauth.project=expert-auth', '-t', image, str(repo / context)], timeout=360)
        report['built_images'] = {}
        for label, tag in [('node_react', node_image), ('python', python_image)]:
            report['built_images'][label] = {'tag': tag, 'image': run(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}']).stdout.decode().strip()}
        node_name, python_name = name + '-node', name + '-python'
        node_origin, python_origin = f'http://{node_name}.example.test:3000', f'http://{python_name}.example.test:8300'
        for container, image, environment in [
            (node_name, node_image, ['EXPERTAUTH_LOCAL_PROBE=true', 'EXPERTAUTH_PUBLIC_ORIGIN=' + node_origin, 'EXPERTAUTH_CORE_URL=http://core-a:3567']),
            (python_name, python_image, ['PYTHON_API_DOMAIN=' + python_origin, 'WEBSITE_DOMAIN=' + python_origin])]:
            argv = ['docker', 'run', '-d', '--label', 'org.expertauth.project=expert-auth', '--name', container, '--network', args.network, '--env-file', str(env_path),
                    '--network-alias', container + '.example.test',
                    '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m']
            for entry in environment:
                argv += ['-e', entry]
            started_containers.append(container)
            run(argv + [image])
        for container, command in [
            (node_name, ['node', '-e', "fetch('http://localhost:3000/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]),
            (python_name, ['python', '-c', "import urllib.request;urllib.request.urlopen('http://localhost:8300/ready',timeout=4)"])]:
            for attempt in range(15):
                if run(['docker', 'exec', container, *command], required=False).returncode == 0:
                    break
                state = run(['docker', 'inspect', container, '--format', '{{.State.Running}}'], required=False)
                if state.stdout.decode().strip() != 'true':
                    run(['docker', 'logs', container], required=False)
                    raise ValueError('Extracted candidate exited before readiness; captured sanitized logs')
                time.sleep(1)
            else:
                raise ValueError('Extracted candidate readiness failed')
        mount = ['--mount', f'type=bind,source={repo},target=/source,readonly']
        evidence_mount = ['--mount', f'type=bind,source={raw_evidence},target=/proof-evidence']
        node_result = run(['docker', 'run', '--rm', '--label', 'org.expertauth.project=expert-auth', '--network', args.network, '--env-file', str(env_path),
                           '-e', 'EXPERTAUTH_TEST_URL=' + node_origin, *mount, node_image, 'node', '--test',
                           '/source/examples/node-react/test/live.test.js'], required=False)
        tap = node_result.stdout.decode('utf8', errors='replace')
        node_checks = re.findall(r'^ok \d+ - (.+)$', tap, flags=re.MULTILINE)
        node_pass = node_result.returncode == 0 and len(node_checks) == 12 and '# pass 12' in tap and '# skipped 0' in tap
        report['test_results']['node_http'] = {'passed': node_pass, 'expected': 12, 'executed_pass_ids': node_checks,
                                              'exit_code': node_result.returncode}
        python_result = run(['docker', 'run', '--rm', '--label', 'org.expertauth.project=expert-auth', '--network', args.network, *mount, *evidence_mount,
                             '-w', '/source', python_image, 'python', 'tests/clients/python_probe.py', '--url', python_origin,
                             '--origin', python_origin, '--evidence-dir', '/proof-evidence/python'], required=False)
        python_report = json.loads((raw_evidence / 'python/probe-report.json').read_text())
        python_pass = python_result.returncode == 0 and python_report['executed'] == python_report['passed'] == 19 and python_report['skipped'] == 0
        report['test_results']['python_http'] = {'passed': python_pass, 'expected': 19, 'executed': python_report['executed'],
                                                'passed_count': python_report['passed'], 'exit_code': python_result.returncode}
        # Browser harness and package-lock are from this extraction; no host node_modules are mounted.
        run(['docker', 'run', '--rm', '--label', 'org.expertauth.project=expert-auth', '--mount', f'type=bind,source={repo / "tests/browser"},target=/browser',
             '-w', '/browser', NODE, 'npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'])
        browser_result = run(['docker', 'run', '--rm', '--label', 'org.expertauth.project=expert-auth', '--network', args.network, *mount, *evidence_mount,
                              '-w', '/source/tests/browser', '-e', 'TEST_ORIGIN=' + node_origin,
                              '-e', 'EVIDENCE_DIR=/proof-evidence/browser', BROWSER, 'node', 'oss-password.mjs'], required=False)
        browser_report = json.loads((raw_evidence / 'browser/results.json').read_text())
        browser_pass = browser_result.returncode == 0 and browser_report['pass'] == 4 and browser_report['fail'] == browser_report['skipped'] == 0
        report['test_results']['node_chromium'] = {'passed': browser_pass, 'expected': 4, 'passed_count': browser_report['pass'],
                                                 'exit_code': browser_result.returncode}
        copied = []
        for path in raw_evidence.rglob('*'):
            if not path.is_file():
                continue
            relative = path.relative_to(raw_evidence)
            target = evidence / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix.lower() in ('.json', '.txt'):
                target.write_text(redact(path.read_text()), encoding='utf8')
            elif path.suffix.lower() == '.png' and browser_pass:
                shutil.copyfile(path, target)
            else:
                continue # Unreviewed failure screenshots remain private, never represented as passed.
            copied.append({'path': str(relative), 'sha256': sha(target.read_bytes())})
        report['test_artifacts'] = copied
        mismatches = [row['path'] for row in manifest['files'] if sha((repo / row['path']).read_bytes()) != row['sha256']]
        report['source_changed_during_tests'] = bool(mismatches)
        report['changed_archive_files'] = mismatches
        report['executed_input_sha256'] = {path: sha((repo / path).read_bytes()) for path in (
            'examples/node-react/Dockerfile', 'examples/node-react/package-lock.json', 'examples/node-react/server.js',
            'examples/node-react/client.jsx', 'examples/node-react/test/live.test.js', 'examples/python/Dockerfile',
            'examples/python/requirements.lock', 'examples/python/app.py', 'tests/clients/python_probe.py',
            'tests/browser/oss-password.mjs', 'tests/browser/package-lock.json')}
        report['status'] = 'QUALIFIED_REPRESENTATIVE_CHECKPOINT' if node_pass and python_pass and browser_pass and not mismatches else 'FAILED'
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'detail': redact(str(error))}
        report['status'] = 'FAILED'
    finally:
        for container in started_containers:
            try:
                present = run(['docker', 'ps', '-aq', '--filter', 'name=^/' + container + '$'])
                if not present.stdout.strip():
                    continue
                run(['docker', 'stop', '--timeout', '5', container], required=False)
                result = run(['docker', 'rm', container], required=False)
                if result.returncode:
                    report.setdefault('cleanup_errors', []).append({'container': container, 'action': 'remove'})
            except Exception as error:
                report.setdefault('cleanup_errors', []).append({'container': container, 'type': type(error).__name__})
        for image in temporary_images:
            try:
                exists = run(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], required=False)
                if exists.returncode == 0:
                    result = run(['docker', 'image', 'rm', image], required=False)
                    if result.returncode:
                        report.setdefault('cleanup_errors', []).append({'image': image, 'action': 'remove-tag'})
            except Exception as error:
                report.setdefault('cleanup_errors', []).append({'image': image, 'type': type(error).__name__})
        try:
            retire_scratch(extraction.parent, report)
        except Exception as error:
            report.setdefault('cleanup_errors', []).append({'scratch': str(extraction.parent), 'type': type(error).__name__})
        report['cleanup_passed'] = not bool(report.get('cleanup_errors'))
        if not report['cleanup_passed'] and report['status'] == 'QUALIFIED_REPRESENTATIVE_CHECKPOINT':
            report['status'] = 'FAILED_CLEANUP'
        report['completed_at'] = datetime.now(timezone.utc).isoformat()
        report['source_zip_unchanged'] = sha(args.zip.read_bytes()) == args.sha256
        if not report['source_zip_unchanged']:
            report['status'] = 'FAILED'
        serialized = json.dumps(report, indent=2) + '\n'
        (evidence / 'report.json').write_bytes(serialized.encode('utf-8'))
        (evidence.parent / 'latest.json').write_text(json.dumps({'report': str((evidence / 'report.json').relative_to(ROOT)),
                                                               'sha256': sha(serialized.encode()), 'status': report['status']}, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(evidence.relative_to(ROOT) / 'report.json'),
                      'complete': False, 'full_stack_restore': False, 'test_results': report['test_results']}))
    return 0 if report['status'] == 'QUALIFIED_REPRESENTATIVE_CHECKPOINT' else 1


if __name__ == '__main__':
    raise SystemExit(main())
