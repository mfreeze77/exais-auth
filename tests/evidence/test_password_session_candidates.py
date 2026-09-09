"""Actual filesystem guard tests; these are tooling checks, not engine acceptance."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from password_session_candidates import NAMES, new_candidate, validate_pair

class CandidateBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='candidate-guards-', dir=ROOT / '.runtime')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / '.cache/password-session'
        self.folder.mkdir(parents=True)
        self.report = {'passed': True, 'candidates': []}
        for component, name in NAMES.items():
            path = self.folder / name
            path.write_bytes(component.encode())
            self.report['candidates'].append({'component': component, 'path': path.relative_to(self.root).as_posix(),
                'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

    def test_one_new_pair_preserves_previous_bytes(self):
        before = {p: p.read_bytes() for p in self.folder.iterdir()}
        target = new_candidate(self.root, 'policy-01', self.report)
        self.assertEqual(target, self.root / '.cache/password-session-policy-01')
        self.assertFalse(target.exists())
        self.assertEqual(before, {p: p.read_bytes() for p in self.folder.iterdir()})

    def test_third_pair_refused(self):
        (self.root / '.cache/password-session-other').mkdir()
        with self.assertRaisesRegex(ValueError, 'previously superseded'):
            new_candidate(self.root, 'policy-01', self.report)

    def test_unknown_member_refused(self):
        (self.folder / 'user-file').write_bytes(b'preserve')
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            validate_pair(self.root, self.report)

    def test_tampered_same_size_file_refused(self):
        (self.folder / NAMES['core']).write_bytes(b'xxxx')
        with self.assertRaisesRegex(ValueError, 'differs'):
            validate_pair(self.root, self.report)

    def test_outside_cache_path_refused(self):
        self.report['candidates'][0]['path'] = '../outside/core-12.2.0.jar'
        with self.assertRaisesRegex(ValueError, 'outside'):
            validate_pair(self.root, self.report)

    def test_existing_candidate_refused(self):
        (self.root / '.cache/password-session-policy-01').mkdir()
        with self.assertRaisesRegex(ValueError, 'Preserve'):
            new_candidate(self.root, 'policy-01', self.report)

    def test_unpassed_build_refused(self):
        self.report['passed'] = False
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            validate_pair(self.root, self.report)

    def test_duplicate_component_refused(self):
        self.report['candidates'][1]['component'] = 'core'
        with self.assertRaisesRegex(ValueError, 'Exact'):
            validate_pair(self.root, self.report)

if __name__ == '__main__':
    unittest.main()
