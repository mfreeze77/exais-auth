"""Bind the original Node install to license declarations and advisory evidence.

Read-only application inspection; output restricted to reuse/evidence paths.
Run with python -B inside the audit container for network access.
"""
from pathlib import Path
import collections
import concurrent.futures
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_sources as audit

def sha(body):
    return hashlib.sha256(body).hexdigest()

lock_path = ROOT / 'evidence/reuse/node-original-lock.json'
lock_bytes = lock_path.read_bytes()
lock = json.loads(lock_bytes)
application = ROOT / 'examples/node-react'
rows = []
installed_files = []
for location, package in lock['packages'].items():
    if not location:
        continue
    directory = application / location
    own_manifest = directory / 'package.json'
    installed = json.loads(own_manifest.read_text()) if own_manifest.exists() else None
    row = {'lock_path': location, 'version': package['version'], 'registry_tarball': package.get('resolved'),
           'tarball_integrity': package.get('integrity'), 'declared_license': package.get('license'),
           'dev': package.get('dev', False), 'optional': package.get('optional', False),
           'cpu': package.get('cpu'), 'os': package.get('os'), 'installed': installed is not None,
           'install_scripts': package.get('hasInstallScript', False), 'license_files': [],
           'decision': 'depend candidate; immutable npm artifact identity from lock', 'modifications': [],
           'mapped_requirements': ['BAS-002', 'BAS-004'],
           'qualification': 'License metadata and installed file inventory only; full file-header and distribution obligations not approved'}
    if installed is not None:
        row['name'] = installed['name']
        row['installed_version_matches_lock'] = installed['version'] == package['version']
        row['installed_license_declaration'] = installed.get('license')
        row['installed_package_sha256'] = sha(own_manifest.read_bytes())
        row['installed_repository'] = installed.get('repository')
        for path in sorted(directory.rglob('*')):
            # Nested packages receive their own lock records; do not double count.
            relative = path.relative_to(directory)
            if 'node_modules' in relative.parts or not path.is_file():
                continue
            record = {'package': row['name'], 'version': package['version'],
                      'path': path.relative_to(application).as_posix(), 'sha256': sha(path.read_bytes()),
                      'package_declared_license': package.get('license'), 'tarball_integrity': package.get('integrity')}
            installed_files.append(record)
            if path.name.lower().startswith(('license', 'notice', 'copying')):
                row['license_files'].append({'path': record['path'], 'sha256': record['sha256']})
        row['file_license_limitation'] = 'Enclosing package declaration recorded; bundled/generated third-party exceptions are not automatically covered'
    else:
        row['name'] = location.rsplit('node_modules/', 1)[-1]
        row['absence_reason'] = 'Not installed in observed Linux profile; optional platform packages are still retained in the lock'
    rows.append(row)

nodemailer, provenance = audit.fetch('https://registry.npmjs.org/nodemailer/9.1.1')
candidate = {key: nodemailer.get(key) for key in ('name', 'version', 'license', 'engines', 'gitHead', 'repository', 'dist')}
candidate['metadata_evidence'] = provenance
audit_result = json.loads((ROOT / 'evidence/reuse/node-npm-audit.json').read_text())
qualification = json.loads((ROOT / 'evidence/reuse/nodemailer-9.1.1-qualification.json').read_text())
if sha(lock_bytes) != qualification['original_lock_sha256']:
    raise ValueError('Original Node lock snapshot differs from isolated qualification input')

report = {'state': 'partial; original graph has a high-severity transitive advisory, isolated fix qualified only for bounded cases',
          'input_lock': 'evidence/reuse/node-original-lock.json', 'input_lock_sha256': sha(lock_bytes),
          'application_package_files_modified_by_audit': False,
          'counts': {'lock_packages': len(rows), 'installed_packages': sum(row['installed'] for row in rows),
                     'missing_license_declarations': sum(not row['declared_license'] for row in rows),
                     'installed_version_mismatches': sum(row.get('installed_version_matches_lock') is False for row in rows),
                     'installed_files_hashed': len(installed_files)},
          'license_declaration_counts': dict(collections.Counter(row['declared_license'] for row in rows)),
          'packages': rows, 'installed_files': installed_files,
          'original_advisory': {'id': 'GHSA-p6gq-j5cr-w38f', 'cve': 'CVE-2026-82659',
                                'affected_dependency': 'nodemailer@8.0.11', 'npm_reported_high_records': 2,
                                'underlying_distinct_advisories': 1, 'affected_range': '<=9.0.0', 'minimum_patched_version': '9.0.1',
                                'evidence': 'evidence/reuse/node-npm-audit.json',
                                'evidence_sha256': sha((ROOT / 'evidence/reuse/node-npm-audit.json').read_bytes()),
                                'automatic_fix_rejected': 'npm proposes SuperTokens Node downgrade to9.2.3, incompatible with required current contracts'},
          'reachability': {'server_source_sha256': sha((application / 'server.js').read_bytes()),
                           'observed': 'Example custom email-delivery service throws; upstream SMTP methods construct text/html messages without a raw field',
                           'conclusion': 'No exercised message-level raw sink in current local prototype; original package remains affected and release-blocked'},
          'candidate_fix': {'override': {'supertokens-node': {'nodemailer': '9.1.1'}}, 'package': candidate,
                            'classification': 'Explicit adapted dependency graph outside upstream declared ^8.0.2; not asserted upstream-supported',
                            'qualified_tests': qualification['tests'], 'local_smtp_messages': qualification['local_smtp_messages'],
                            'npm_audit_after_override': qualification['npm']['audit']['result']['metadata']['vulnerabilities'],
                            'evidence': 'evidence/reuse/nodemailer-9.1.1-qualification.json',
                            'limitations': qualification['limitations']},
          'primary_sources': ['https://github.com/nodemailer/nodemailer/security/advisories/GHSA-p6gq-j5cr-w38f',
                              'https://github.com/nodemailer/nodemailer/releases/tag/v9.0.0',
                              'https://github.com/nodemailer/nodemailer/releases/tag/v9.0.1',
                              'https://github.com/nodemailer/nodemailer/releases/tag/v9.1.1',
                              'https://github.com/nodemailer/nodemailer/releases/tag/v10.0.0'],
          'recommendation': 'Apply only the scoped9.1.1 override as a declared adaptation, regenerate lock, rerun npm audit and complete Node/React authentication regressions; keep provider/TLS qualification blocked',
          'release_approved': False}
audit.write(ROOT / 'reuse/node-example-dependencies.json', report)
print(json.dumps(report['counts']))
