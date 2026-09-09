"""Exercise real source-capture request rejection; no auth or native-platform claims."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'evidence/reuse/native-correspondence'
sys.path.insert(0, str(ROOT / 'tools'))
from capture_native_sources import validate_source_request


class NativeSourceCaptureTests(unittest.TestCase):
    def test_all_actual_source_requests_meet_strict_identity_policy(self):
        counts = {}
        for component in ['scrypt', 'jna', 'sqlite', 'argon2']:
            request = json.loads((BASE / component / 'acquisition-request.json').read_bytes())
            counts[component] = len(validate_source_request(request))
        self.assertEqual(counts, {'scrypt': 13, 'jna': 47, 'sqlite': 26, 'argon2': 31})

    def test_malformed_requests_fail_in_real_cli_before_acquisition(self):
        template = json.loads((BASE / 'scrypt/acquisition-request.json').read_bytes())['files'][0]
        rows = []
        for value in [None, '', '0' * 39]:
            row = copy.deepcopy(template)
            row['expected_git_blob_sha1'] = value
            rows.append(row)
        for value in [None, True, 0, 8 * 1024 * 1024 + 1]:
            row = copy.deepcopy(template)
            row['expected_bytes'] = value
            rows.append(row)
        for path in ['acquisition.json', 'container.json', 'Acquisition.json', '../outside.h',
                     'acquisition.json/note.h', 'container.json/note.h']:
            row = copy.deepcopy(template)
            row['path'] = path
            rows.append(row)
        row = copy.deepcopy(template)
        row['url'] = row['url'].rsplit('/', 1)[0] + '/libscrypt.so'
        rows.append(row)
        row = copy.deepcopy(row)
        row['path'] = '/'.join(row['url'].split('/')[6:])
        rows.append(row)
        with tempfile.TemporaryDirectory(prefix='invalid-source-test-', dir=BASE) as temporary:
            temporary = Path(temporary).resolve()
            self.assertEqual(temporary.parent, BASE.resolve())
            for index, row in enumerate(rows):
                with self.subTest(case=index):
                    request = temporary / f'request-{index}.json'
                    request.write_text(json.dumps({'files': [row]}), encoding='utf-8')
                    output = temporary / f'output-{index}'
                    result = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/capture_native_sources.py'),
                                             '--request', str(request), '--output', str(output)],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    report = json.loads((output / 'acquisition.json').read_bytes())
                    self.assertFalse(report['passed'])
                    self.assertEqual(report['records'], [])
                    self.assertEqual(report['total_bytes'], 0)
                    self.assertTrue(report['errors'][0].startswith('ValueError:'), report['errors'])
                    self.assertEqual({p.name for p in output.iterdir()}, {'acquisition.json'})
        self.assertFalse(temporary.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
