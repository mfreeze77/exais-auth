"""Actual pinned-archive/notice packaging checks; not auth acceptance tests."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from assemble_runtime_licenses import assemble, safe_relative
from fetch_runtime_notice_sources import LOCK, approved_url, cache_path, ensure_sources, sha, validate_lock, verify_bytes


class RuntimeDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = json.loads(LOCK.read_bytes())
        cls.entries = validate_lock(cls.lock)
        cls.small = min((row for row in cls.entries if row['status'] == 'available'), key=lambda row: row['bytes'])

    def test_all_locked_cached_sources_verify_without_download(self):
        results = ensure_sources(offline=True)
        self.assertEqual(sum(row['status'] == 'verified' for row in results), 83)
        self.assertFalse(any(row['downloaded'] for row in results))

    def test_corrupted_actual_source_archive_is_rejected(self):
        raw = cache_path(self.small).read_bytes()
        verify_bytes(raw, self.small)
        changed = bytes([raw[0] ^ 1]) + raw[1:]
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            verify_bytes(changed, self.small)

    def test_duplicate_or_deleted_coordinate_is_rejected(self):
        for change in ('duplicate', 'delete'):
            lock = copy.deepcopy(self.lock)
            if change == 'duplicate':
                lock['entries'][0] = lock['entries'][1]
            else:
                lock['entries'].pop()
            with self.assertRaisesRegex(ValueError, 'coordinate'):
                validate_lock(lock)

    def test_unreviewed_source_replacement_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock['entries'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'reviewed acquisition'):
            validate_lock(lock)

    def test_inventory_drift_is_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock['runtime_inventory_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'inventory drift'):
            validate_lock(lock)

    def test_source_origin_and_cache_boundaries(self):
        for url in ('http://repo.maven.apache.org/maven2/x', 'https://repo.maven.apache.org.evil.test/maven2/x',
                    'https://repo.maven.apache.org/private/x', 'file:///tmp/source.jar'):
            with self.assertRaises(ValueError):
                approved_url(url)
        for path in ('../outside.jar', '.runtime/source.jar', '.cache/runtime-source-jars/../../outside.jar'):
            with self.assertRaises(ValueError):
                cache_path({'path': path})
        for member in ('../outside', '/absolute', 'C:/outside', 'a\\outside'):
            with self.assertRaises(ValueError):
                safe_relative(member)

    def test_missing_guava_source_is_a_metadata_only_binary_observation(self):
        missing = [row for row in self.entries if row['status'] == 'unavailable']
        self.assertEqual(len(missing), 1)
        row = missing[0]
        self.assertEqual(row['coordinate'], 'com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava')
        dependencies = json.loads((ROOT / 'reuse/runtime-dependencies.json').read_bytes())['dependencies']
        binary = next(dep for dep in dependencies if dep['coordinate'] == row['coordinate'])
        with zipfile.ZipFile(ROOT / binary['jar']['file']) as archive:
            self.assertTrue(archive.namelist())
            self.assertTrue(all(name.startswith('META-INF/') for name in archive.namelist()))
            self.assertFalse(any(name.endswith('.class') for name in archive.namelist()))

    def test_real_notice_tree_preserves_archive_bytes_and_reproduces(self):
        cache = ROOT / '.cache'
        with tempfile.TemporaryDirectory(prefix='notice-test-', dir=cache) as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(root.parent, cache.resolve())
            output = root / 'first'
            report = assemble(output)
            self.assertEqual(report['runtime_dependency_count'], 84)
            self.assertFalse(report['full_distribution_approved'])
            for row in report['files']:
                raw = (output / row['path']).read_bytes()
                self.assertEqual((len(raw), sha(raw)), (row['bytes'], row['sha256']))
            dependencies = {dep['coordinate']: dep for dep in json.loads((ROOT / 'reuse/runtime-dependencies.json').read_bytes())['dependencies']}
            checked = 0
            for row in report['dependencies']:
                for key, archive_path in [('binary_notices', ROOT / dependencies[row['coordinate']]['jar']['file'])] + (
                        [('source_notices', cache_path(row['source_archive']))] if row['source_archive']['status'] == 'available' else []):
                    with zipfile.ZipFile(archive_path) as archive:
                        for notice in row[key]:
                            self.assertEqual((output / notice['path']).read_bytes(), archive.read(notice['archive_member']))
                            checked += 1
            # The initial discovery's88 candidates included Bouncy Castle's
            # compiled LICENSE.class. It is not a notice text; its source and
            # actual text notices are preserved and checked above.
            self.assertEqual(checked, 89)
            # Real JNA ships the complete alternatives under short filenames.
            # Keep exact upstream text, not just its788-byte LICENSE pointer.
            jna = next(row for row in report['dependencies'] if row['coordinate'] == 'net.java.dev.jna:jna:5.8.0')
            expected_jna = {'META-INF/AL2.0': (10174, '0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594'),
                            'META-INF/LGPL2.1': (24389, 'eea173a556abac0370461e57e12aab266894ea6be3874c2be05fd87871f75449')}
            packaged = {row['archive_member']: row for row in jna['binary_notices']}
            for member, identity in expected_jna.items():
                self.assertIn(member, packaged)
                self.assertEqual((packaged[member]['bytes'], packaged[member]['sha256']), identity)
            self.assertFalse(any(row['path'].endswith('.class') for row in report['files']))
            self.assertEqual(len(report['supplemental_notices']), 5)
            self.assertEqual(len(report['source_header_notices']), 3)
            for row in report['source_header_notices']:
                notice = (output / row['packaged_file']['path']).read_bytes()
                self.assertEqual(notice, (ROOT / row['source_file']).read_bytes()[:row['notice_byte_range']['end_exclusive']])
                self.assertEqual(sha(notice), row['notice_sha256'])
            for row in report['supplemental_notices']:
                self.assertEqual((output / row['packaged_file']['path']).read_bytes(), (ROOT / row['path']).read_bytes())
            second = root / 'second'
            assemble(second)
            self.assertEqual((output / 'manifest.json').read_bytes(), (second / 'manifest.json').read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
