"""File-specific notice and content inventory for the test-only PyOTP wheel."""
import hashlib
import json
import pathlib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
wheel = HERE / '.runtime/wheels/pyotp-2.10.0-py3-none-any.whl'
assert hashlib.sha256(wheel.read_bytes()).hexdigest() == '1df2f6a1bcc3bb0716172a5215ddc2f8c7c7fd26a13df9927d52e1746934836c'
with zipfile.ZipFile(wheel) as archive:
    license_name = 'pyotp-2.10.0.dist-info/licenses/LICENSE'
    license_text = archive.read(license_name).decode()
    assert 'Permission is hereby granted, free of charge' in license_text
    (HERE / 'PYOTP_LICENSE.txt').write_text(license_text)
    report = {'name': 'PyOTP', 'version': '2.10.0', 'license': 'MIT', 'repository': 'https://github.com/pyauth/pyotp',
              'immutable_revision': 'PyOTP 2.10.0 exact wheel SHA-256', 'source_boundary': 'Unmodified maintained package, test-only fixture TOTP generation',
              'destination': 'examples/keycloak-clients/.runtime/testdeps via hash-locked requirements-test.txt',
              'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(), 'modifications': [],
              'requirement_mapping': 'Candidate positive/negative MFA fixture proof only; no requirement closure',
              'files': [{'path': name, 'sha256': hashlib.sha256(archive.read(name)).hexdigest()}
                        for name in archive.namelist() if not name.endswith('/')]}
(ROOT / 'evidence/foundation/keycloak-clients/python-reuse-files.json').write_text(json.dumps(report, indent=2) + '\n')
print('PyOTP 2.10.0 wheel and complete MIT grant validated; no auth completion claim')
