"""Verify the installed Python example against its 49 locked wheel artifacts.

Run in the candidate image with /repo inputs and wheel cache mounted read-only,
and a writable /evidence directory. This script neither installs nor downloads.
It reports artifact correspondence, not license approval or runtime acceptance.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import sysconfig
import zipfile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = Path('/evidence/distribution.json')
SDK_COMMIT = 'b498da1a6d09ca84ca204ac881df76900df19175'
SDK_MANIFEST = 'reuse/files/supertokens__supertokens-python.json'
BASE_DISTRIBUTIONS = {'pip', 'setuptools'}
INPUTS = ['tools/verify_python_distribution.py', 'tools/fetch_python_wheels.py',
          'examples/python/requirements.lock',
          'examples/python/dependency-resolution.json', SDK_MANIFEST]
NOTICE_NAME = re.compile(r'^(?:licen[cs]e|copying|notice|copyright|authors)(?:$|[._-])', re.I)


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inventory_sha(rows):
    """Canonical inventories use sorted JSON arrays, UTF-8, and no whitespace."""
    return sha(json.dumps(sorted(rows), ensure_ascii=True, separators=(',', ':')).encode('utf-8'))


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def relative_path(name):
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and '\\' not in name and '\x00' not in name
         and all(part not in ('', '.', '..') for part in name.split('/'))
         and ':' not in name, 'Unsafe relative path: ' + repr(name))
    return path


def installed_path(site, name, directory=False):
    """Do not follow package symlinks when comparing immutable file bytes."""
    parts = relative_path(name).parts
    target = site
    for part in parts:
        target = target / part
        need(not target.is_symlink(), 'Installed symlink is outside correspondence policy: ' + name)
    need(target.resolve().is_relative_to(site), 'Installed path escaped site-packages: ' + name)
    need(target.is_dir() if directory else target.is_file(), 'Installed member absent or wrong type: ' + name)
    if not directory:
        need(stat.S_ISREG(target.stat().st_mode), 'Installed member is not regular: ' + name)
    return target


def preserve(report):
    """Replace only this report, retaining a useful partial record between stages."""
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix('.json.tmp')
    with temporary.open('w', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(OUTPUT)


def error_text(error):
    return type(error).__name__ + ': ' + str(error)


def verify_distribution(row, distribution, cache, helper, result, owners):
    target = cache / row['filename']
    need(not target.is_symlink() and target.is_file(), 'Locked wheel missing or linked')
    need(target.stat().st_size <= helper.MAX_WHEEL, 'Locked wheel exceeds size bound')
    raw = target.read_bytes()
    helper.verify_wheel(raw, row)
    result['wheel_bytes'] = len(raw)
    result['wheel_sha256_verified'] = True
    site = Path(distribution.locate_file('')).resolve()
    roots = {Path(sysconfig.get_path(key)).resolve() for key in ('purelib', 'platlib')}
    need(site in roots, 'Distribution is outside the interpreter installation roots: ' + str(site))
    result['installation_root'] = str(site)
    result['installed_version'] = distribution.version
    need(distribution.version == row['version'], 'Installed version differs from lock')
    inventory = []
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        members = wheel.infolist()
        names = [member.filename for member in members]
        need(len(names) == len({name.casefold() for name in names}), 'Case-folded wheel member collision')
        files = {member.filename: member for member in members if not member.is_dir()}
        result['wheel_member_count'] = len(members)
        result['wheel_file_count'] = len(files)
        result['wheel_directory_count'] = len(members) - len(files)
        result['unchanged_members_verified'] = 0
        metadata_name = next(name for name in files if name.endswith('.dist-info/METADATA'))
        info = metadata_name.rsplit('/', 1)[0]
        record_name = info + '/RECORD'
        need(record_name in files, 'Wheel has no corresponding RECORD')
        parsed = BytesParser().parsebytes(wheel.read(metadata_name))
        result['metadata_version'] = parsed.get('Metadata-Version')
        declarations = parsed.get_all('License-File', [])
        result['declared_license_files'] = declarations
        result['notices'] = []
        wheel_metadata = BytesParser().parsebytes(wheel.read(info + '/WHEEL'))
        need(wheel_metadata.get('Root-Is-Purelib') in ('true', 'false'), 'Invalid Root-Is-Purelib metadata')
        result['root_is_purelib'] = wheel_metadata['Root-Is-Purelib'] == 'true'
        data_members = [name for name in names if PurePosixPath(name).parts[0].endswith('.data')]
        result['data_layout_members'] = data_members
        need(not data_members, 'Unsupported .data relocation; no relocated members are silently skipped')
        declared_members = {}
        for declaration in declarations:
            relative_path(declaration)
            candidates = [name for name in (info + '/licenses/' + declaration, info + '/' + declaration)
                          if name in files]
            need(len(candidates) == 1, 'Declared License-File absent or ambiguous: ' + declaration)
            declared_members.setdefault(candidates[0], []).append(declaration)
        notice_members = set(declared_members) | {
            name for name in files if NOTICE_NAME.match(PurePosixPath(name).name)
        }
        for member in sorted(members, key=lambda item: item.filename):
            name = member.filename.rstrip('/') if member.is_dir() else member.filename
            relative_path(name)
            mode = (member.external_attr >> 16) & 0xFFFF
            need(not stat.S_ISLNK(mode), 'Wheel contains a symlink: ' + name)
            need(stat.S_IFMT(mode) in (0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG),
                 'Wheel contains a special member: ' + name)
            if member.is_dir():
                installed_path(site, name, directory=True)
                continue
            destination = installed_path(site, name)
            owner_key = str(destination)
            need(owner_key not in owners, 'Two locked distributions own the same installed file: ' + name)
            owners[owner_key] = row['name']
            wheel_bytes = wheel.read(member)
            wheel_digest = sha(wheel_bytes)
            if name == record_name:
                need(destination.stat().st_size <= helper.MAX_WHEEL, 'Installed RECORD exceeds read bound')
                result['record_exception'] = {
                    'wheel_member': name, 'wheel_sha256': wheel_digest,
                    'installed_sha256': sha(destination.read_bytes()),
                    'reason': 'pip rewrites RECORD during installation; its bytes are not compared',
                }
                continue
            need(destination.stat().st_size == member.file_size, 'Installed size differs: ' + name)
            installed_digest = sha(destination.read_bytes())
            need(installed_digest == wheel_digest, 'Installed bytes differ from locked wheel: ' + name)
            inventory.append([name, name, member.file_size, wheel_digest])
            result['unchanged_members_verified'] += 1
            if name in notice_members:
                result['notices'].append({
                    'wheel_member': name, 'installed_path': str(destination),
                    'bytes': member.file_size, 'sha256': wheel_digest,
                    'installed_sha256': installed_digest,
                    'declared_as': declared_members.get(name, []),
                    'discovered_by_filename': bool(NOTICE_NAME.match(PurePosixPath(name).name)),
                })
        need(result['unchanged_members_verified'] == len(files) - 1, 'Incomplete unchanged member comparison')
        need(set(notice_members) == {item['wheel_member'] for item in result['notices']},
             'Incomplete notice correspondence')
        result['unchanged_member_inventory_sha256'] = inventory_sha(inventory)
        result['notice_count'] = len(result['notices'])
        result['passed'] = True


def verify_sdk(distributions, report):
    result = report['sdk_source']
    source = json.loads((ROOT / SDK_MANIFEST).read_bytes())
    need(source['commit'] == SDK_COMMIT, 'SDK immutable source commit differs')
    expected = {}
    for entry in source['files']:
        name = entry['source_path']
        if name.startswith('supertokens_python/') and name.endswith('.py'):
            relative_path(name)
            need(name not in expected and entry['commit'] == SDK_COMMIT, 'SDK source entry duplicate or unpinned')
            need(re.fullmatch(r'[0-9a-f]{64}', entry['sha256']) is not None, 'Invalid SDK source hash')
            expected[name] = entry
    result['expected_python_files'] = len(expected)
    need(len(expected) == 418, 'Immutable SDK source Python inventory is not 418 files')
    candidates = distributions.get('supertokens-python', [])
    need(len(candidates) == 1, 'SDK installed distribution missing or ambiguous')
    site = Path(candidates[0].locate_file('')).resolve()
    package = installed_path(site, 'supertokens_python', directory=True)
    actual = {}
    for folder, directories, files in os.walk(package, followlinks=False):
        for name in directories:
            need(not (Path(folder) / name).is_symlink(), 'SDK contains a linked directory')
        for name in files:
            if name.endswith('.py'):
                target = Path(folder) / name
                relative = target.relative_to(site).as_posix()
                target = installed_path(site, relative)
                actual[relative] = {'bytes': target.stat().st_size, 'sha256': sha(target.read_bytes())}
    result['actual_python_files'] = len(actual)
    result['missing'] = sorted(set(expected) - set(actual))
    result['extra'] = sorted(set(actual) - set(expected))
    result['mismatches'] = [name for name in sorted(set(expected) & set(actual))
                            if any(actual[name][key] != expected[name][key] for key in ('bytes', 'sha256'))]
    result['actual_inventory_sha256'] = inventory_sha(
        [[name, row['bytes'], row['sha256']] for name, row in actual.items()])
    need(not result['missing'] and not result['extra'] and not result['mismatches'],
         'SDK installed Python files differ from immutable source inventory')
    result['verified_python_files'] = len(actual)
    result['passed'] = True


def pip_check(report):
    command = [sys.executable, '-m', 'pip', 'check']
    overrides = {'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
                 'PIP_CONFIG_FILE': os.devnull, 'PYTHONDONTWRITEBYTECODE': '1'}
    result = report['pip_check']
    result.update({'command': command, 'environment_overrides': overrides, 'timeout_seconds': 60})
    try:
        completed = subprocess.run(command, env={**os.environ, **overrides},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        result.update({'returncode': completed.returncode,
                       'stdout': completed.stdout.decode('utf-8', errors='backslashreplace'),
                       'stderr': completed.stderr.decode('utf-8', errors='backslashreplace'),
                       'stdout_base64': base64.b64encode(completed.stdout).decode('ascii'),
                       'stderr_base64': base64.b64encode(completed.stderr).decode('ascii'),
                       'stdout_sha256': sha(completed.stdout), 'stderr_sha256': sha(completed.stderr),
                       'passed': completed.returncode == 0})
        need(result['passed'], 'Offline pip check failed')
    except subprocess.TimeoutExpired as error:
        result.update({'timed_out': True,
                       'stdout': (error.stdout or b'').decode('utf-8', errors='backslashreplace'),
                       'stderr': (error.stderr or b'').decode('utf-8', errors='backslashreplace'),
                       'stdout_base64': base64.b64encode(error.stdout or b'').decode('ascii'),
                       'stderr_base64': base64.b64encode(error.stderr or b'').decode('ascii')})
        raise


def main():
    if OUTPUT.exists() or OUTPUT.with_suffix('.json.tmp').exists():
        print('Refusing to overwrite existing distribution evidence; use a fresh /evidence mount.', file=sys.stderr)
        return 1
    report = {
        'schema': 'expertauth-python-installed-distribution-v1',
        'started': datetime.now(timezone.utc).isoformat(), 'status': 'RUNNING', 'passed': False,
        'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
        'input_sha256': {}, 'errors': [], 'distributions': [], 'base_distributions_outside_scope': [],
        'sdk_source': {'commit': SDK_COMMIT, 'manifest': SDK_MANIFEST, 'passed': False},
        'pip_check': {'passed': False}, 'full_distribution_approved': False,
        'inventory_encoding': 'SHA-256 of UTF-8 JSON sorted arrays; ensure_ascii=true; separators=comma,colon',
        'member_inventory_fields': ['wheel_member', 'installed_relative_path', 'bytes', 'sha256'],
        'sdk_inventory_fields': ['source_path', 'bytes', 'sha256'],
        'limitations': [
            'Only wheel-provided RECORD is excluded from wheel file byte comparison because pip rewrites it.',
            'Any wheel .data relocation fails closed; no relocated layout is qualified by this verifier.',
            'Installer-generated files absent from wheels are outside wheel-member comparison; '
            'the installed SDK Python file set is independently checked exactly.',
            'Base-provided pip/setuptools, the Python interpreter and OS distribution closure are separate.',
            'Source correspondence for native extensions and their bundled components remains separate.',
            'Notice correspondence is not legal approval, a fresh advisory audit or independent security review.',
            'This is artifact verification; functional, live-provider and native-platform acceptance remain separate.',
        ],
    }
    preserve(report)
    distributions = {}
    try:
        # Importing the sibling acquisition helper has no network or install side effects.
        import fetch_python_wheels as helper
        for name in INPUTS:
            report['input_sha256'][name] = sha((ROOT / name).read_bytes())
        rows = helper.locked_wheels()
        report['locked_distribution_count'] = len(rows)
        cache = ROOT / '.cache/python-wheels'
        expected_cache = {row['filename'] for row in rows}
        need(cache.is_dir() and not cache.is_symlink(), 'Wheel cache missing or linked')
        cached = list(cache.iterdir())
        need({item.name for item in cached} == expected_cache, 'Cache must contain exactly the 49 locked wheels')
        need(all(item.is_file() and not item.is_symlink() for item in cached), 'Cache contains non-files or links')
        report['cache_bytes'] = sum(item.stat().st_size for item in cached)
        need(report['cache_bytes'] <= helper.MAX_CACHE, 'Wheel cache exceeds bounded size')
        for distribution in importlib.metadata.distributions():
            name = distribution.metadata.get('Name')
            need(name, 'Installed distribution has no Name metadata')
            distributions.setdefault(normalized(name), []).append(distribution)
        locked_names = {normalized(row['name']) for row in rows}
        extras = sorted(set(distributions) - locked_names - BASE_DISTRIBUTIONS)
        report['unexpected_installed_distributions'] = extras
        for name in sorted(set(distributions) & BASE_DISTRIBUTIONS):
            report['base_distributions_outside_scope'].extend(
                {'name': name, 'version': distribution.version} for distribution in distributions[name])
        if extras:
            report['errors'].append('Unexpected installed distributions: ' + ', '.join(extras))
        report['installed_distribution_count_including_base'] = sum(map(len, distributions.values()))
        owners = {}
        for row in rows:
            result = {**row, 'passed': False, 'errors': []}
            report['distributions'].append(result)
            try:
                candidates = distributions.get(normalized(row['name']), [])
                need(len(candidates) == 1, 'Locked installed distribution missing or ambiguous: ' + row['name'])
                verify_distribution(row, candidates[0], cache, helper, result, owners)
            except Exception as error:
                result['errors'].append(error_text(error))
                report['errors'].append(row['name'] + ': ' + error_text(error))
            preserve(report)
    except Exception as error:
        report['errors'].append(error_text(error))
    try:
        verify_sdk(distributions, report)
    except Exception as error:
        report['sdk_source']['error'] = error_text(error)
        report['errors'].append('SDK: ' + error_text(error))
    preserve(report)
    try:
        pip_check(report)
    except Exception as error:
        report['pip_check']['error'] = error_text(error)
        report['errors'].append('pip check: ' + error_text(error))
    try:
        need(len(report['input_sha256']) == len(INPUTS), 'Incomplete input hash inventory')
        need(all(sha((ROOT / name).read_bytes()) == digest
                 for name, digest in report['input_sha256'].items()), 'Verifier inputs changed during verification')
    except Exception as error:
        report['errors'].append(error_text(error))
    report['verified_distribution_count'] = sum(item['passed'] for item in report['distributions'])
    report['passed'] = (not report['errors'] and report['verified_distribution_count'] == 49
                        and report['sdk_source']['passed'] and report['pip_check']['passed'])
    report['status'] = 'PASS' if report['passed'] else 'PARTIAL'
    report['finished'] = datetime.now(timezone.utc).isoformat()
    preserve(report)
    print(json.dumps({'passed': report['passed'], 'verified_distribution_count': report['verified_distribution_count'],
                      'sdk_python_files': report['sdk_source'].get('verified_python_files', 0),
                      'errors': report['errors'], 'evidence': str(OUTPUT)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
