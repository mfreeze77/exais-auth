"""Real-Fernet recovery format tests; no engine/provider acceptance claims.

Run in the pinned Python image: python -B -m unittest discover
    -s /repo/tests/operations -p test_recovery_bundle.py -v
"""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from cryptography.fernet import Fernet


SPEC = importlib.util.spec_from_file_location('recovery_bundle', Path(__file__).resolve().parents[2] / 'tools/recovery_bundle.py')
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class RecoveryBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='expertauth-recovery-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)
        self.contents = {'database.pgdump': b'PGDMP\x00\xff\x00test-database\n',
                         'core-config.yaml': b'postgresql_connection_uri: postgresql://private-secret\n',
                         'runtime.env': b'API_KEY=private-runtime-secret\n'}
        for name, raw in self.contents.items():
            (self.source / name).write_bytes(raw)
        self.key = self.root / 'key'
        bundle.generate_key(self.key)
        self.archive = self.root / 'backup.fernet'
        self.destination = self.root / 'restored'

    def make_archive(self):
        return bundle.pack(self.source, self.key, self.archive)

    def inventory(self):
        return {'schema': bundle.SCHEMA, 'total_bytes': sum(map(len, self.contents.values())),
                'files': [{'name': name, 'bytes': len(self.contents[name]),
                           'sha256': hashlib.sha256(self.contents[name]).hexdigest()} for name in bundle.FILES]}

    def authenticated_archive(self, header=None, header_raw=None, suffix=b'', payload=None):
        if header_raw is None:
            header_raw = json.dumps(header if header is not None else self.inventory(), separators=(',', ':')).encode()
        if payload is None:
            payload = b''.join(self.contents[name] for name in bundle.FILES)
        plain = struct.pack('>I', len(header_raw)) + header_raw + payload + suffix
        self.archive.write_bytes(Fernet(self.key.read_bytes()).encrypt(plain))

    def assert_rejected_without_output(self):
        before = self.archive.read_bytes()
        with self.assertRaises(bundle.BundleError):
            bundle.unpack(self.archive, self.key, self.destination)
        self.assertEqual(before, self.archive.read_bytes())
        self.assertFalse(self.destination.exists())
        self.assertEqual([], list(self.root.glob('.expertauth-recovery-*')))

    def test_round_trip_exact_bytes_and_inventory(self):
        packed = self.make_archive()
        restored = bundle.unpack(self.archive, self.key, self.destination)
        self.assertEqual(set(bundle.FILES), {path.name for path in self.destination.iterdir()})
        for name, raw in self.contents.items():
            self.assertEqual(raw, (self.destination / name).read_bytes())
        self.assertEqual(packed['files'], restored['files'])
        self.assertEqual(packed['inventory_sha256'], restored['inventory_sha256'])
        self.assertEqual(packed['archive_sha256'], restored['archive_sha256'])
        self.assertEqual('PACKED', packed['status'])
        self.assertEqual('UNPACKED', restored['status'])
        self.assertNotIn(b'private-runtime-secret', self.archive.read_bytes())

    def test_existing_empty_destination(self):
        self.make_archive()
        self.destination.mkdir()
        bundle.unpack(self.archive, self.key, self.destination)
        self.assertEqual(self.contents['runtime.env'], (self.destination / 'runtime.env').read_bytes())

    def test_zero_byte_files(self):
        for path in self.source.iterdir():
            path.write_bytes(b'')
        self.make_archive()
        bundle.unpack(self.archive, self.key, self.destination)
        self.assertTrue(all(path.read_bytes() == b'' for path in self.destination.iterdir()))

    def test_wrong_key(self):
        self.make_archive()
        self.key.write_bytes(Fernet.generate_key())
        self.assert_rejected_without_output()

    def test_tampered_token(self):
        self.make_archive()
        raw = bytearray(self.archive.read_bytes())
        raw[len(raw) // 2] = ord('A') if raw[len(raw) // 2] != ord('A') else ord('B')
        self.archive.write_bytes(raw)
        self.assert_rejected_without_output()

    def test_truncated_token(self):
        self.make_archive()
        self.archive.write_bytes(self.archive.read_bytes()[:-12])
        self.assert_rejected_without_output()

    def test_noncanonical_token(self):
        self.make_archive()
        self.archive.write_bytes(self.archive.read_bytes() + b'\n')
        self.assert_rejected_without_output()

    def test_unknown_schema(self):
        header = self.inventory()
        header['schema'] = 'unknown-schema'
        self.authenticated_archive(header)
        self.assert_rejected_without_output()

    def test_unknown_top_level_field(self):
        header = self.inventory()
        header['extra'] = True
        self.authenticated_archive(header)
        self.assert_rejected_without_output()

    def test_unknown_inventory_field(self):
        header = self.inventory()
        header['files'][0]['extra'] = True
        self.authenticated_archive(header)
        self.assert_rejected_without_output()

    def test_duplicate_top_level_json_key(self):
        raw = json.dumps(self.inventory(), separators=(',', ':')).encode()
        raw = b'{"schema":"unknown",' + raw[1:]
        self.authenticated_archive(header_raw=raw)
        self.assert_rejected_without_output()

    def test_duplicate_nested_json_key(self):
        raw = json.dumps(self.inventory(), separators=(',', ':')).encode()
        raw = raw.replace(b'"name":"database.pgdump"', b'"name":"bad","name":"database.pgdump"', 1)
        self.authenticated_archive(header_raw=raw)
        self.assert_rejected_without_output()

    def test_path_variants(self):
        for name in ('../database.pgdump', './database.pgdump', '/database.pgdump',
                     'directory/database.pgdump', 'directory\\database.pgdump', 'DATABASE.pgdump'):
            with self.subTest(name=name):
                header = self.inventory()
                header['files'][0]['name'] = name
                self.authenticated_archive(header)
                self.assert_rejected_without_output()

    def test_duplicate_missing_and_extra_members(self):
        for variant in ('duplicate', 'missing', 'extra'):
            with self.subTest(variant=variant):
                header = self.inventory()
                if variant == 'duplicate':
                    header['files'][1] = header['files'][0].copy()
                elif variant == 'missing':
                    header['files'].pop()
                else:
                    header['files'].append(header['files'][0].copy())
                self.authenticated_archive(header)
                self.assert_rejected_without_output()

    def test_wrong_hash_on_final_member_leaves_no_partial_files(self):
        header = self.inventory()
        header['files'][-1]['sha256'] = '0' * 64
        self.authenticated_archive(header)
        self.assert_rejected_without_output()

    def test_invalid_lengths_and_total(self):
        for value in (-1, True, 1.0, '1', bundle.MAX_PLAINTEXT + 1):
            with self.subTest(value=value):
                header = self.inventory()
                header['files'][0]['bytes'] = value
                self.authenticated_archive(header)
                self.assert_rejected_without_output()
        header = self.inventory()
        header['total_bytes'] += 1
        self.authenticated_archive(header)
        self.assert_rejected_without_output()

    def test_trailing_and_truncated_authenticated_payload(self):
        self.authenticated_archive(suffix=b'extra')
        self.assert_rejected_without_output()
        self.authenticated_archive(payload=b'truncated')
        self.assert_rejected_without_output()

    def test_malformed_json_and_header_size(self):
        for raw in (b'{', b'\xff', b'[]', b'{"a":NaN}'):
            with self.subTest(raw=raw):
                self.authenticated_archive(header_raw=raw)
                self.assert_rejected_without_output()
        self.archive.write_bytes(Fernet(self.key.read_bytes()).encrypt(struct.pack('>I', bundle.MAX_HEADER + 1) + b'{}'))
        self.assert_rejected_without_output()

    def test_key_overwrite_protection(self):
        before = self.key.read_bytes()
        with self.assertRaises(bundle.BundleError):
            bundle.generate_key(self.key)
        self.assertEqual(before, self.key.read_bytes())

    def test_archive_overwrite_protection(self):
        self.make_archive()
        before = self.archive.read_bytes()
        with self.assertRaises(bundle.BundleError):
            self.make_archive()
        self.assertEqual(before, self.archive.read_bytes())

    def test_nonempty_destination_protection(self):
        self.make_archive()
        self.destination.mkdir()
        sentinel = self.destination / 'user-file'
        sentinel.write_bytes(b'preserve-existing-data')
        with self.assertRaises(bundle.BundleError):
            bundle.unpack(self.archive, self.key, self.destination)
        self.assertEqual(b'preserve-existing-data', sentinel.read_bytes())
        self.assertEqual([sentinel], list(self.destination.iterdir()))
        self.assertEqual([], list(self.root.glob('.expertauth-recovery-*')))

    def test_wrong_key_preserves_existing_empty_destination(self):
        self.make_archive()
        self.destination.mkdir()
        self.key.write_bytes(Fernet.generate_key())
        with self.assertRaises(bundle.BundleError):
            bundle.unpack(self.archive, self.key, self.destination)
        self.assertTrue(self.destination.is_dir())
        self.assertEqual([], list(self.destination.iterdir()))

    def test_missing_extra_or_directory_source(self):
        (self.source / 'extra').write_bytes(b'extra')
        with self.assertRaises(bundle.BundleError):
            self.make_archive()
        (self.source / 'extra').unlink()
        (self.source / 'runtime.env').unlink()
        with self.assertRaises(bundle.BundleError):
            self.make_archive()
        (self.source / 'runtime.env').mkdir()
        with self.assertRaises(bundle.BundleError):
            self.make_archive()
        self.assertFalse(self.archive.exists())

    def test_malformed_key(self):
        for raw in (b'', b'secret', Fernet.generate_key() + b'\n', b'!' * 44):
            with self.subTest(length=len(raw)):
                self.key.write_bytes(raw)
                with self.assertRaises(bundle.BundleError):
                    self.make_archive()
                self.assertFalse(self.archive.exists())

    def test_plaintext_limit(self):
        with (self.source / 'database.pgdump').open('wb') as stream:
            stream.truncate(bundle.MAX_PLAINTEXT)
        with self.assertRaises(bundle.BundleError):
            self.make_archive()
        self.assertFalse(self.archive.exists())

    def test_archive_limit(self):
        with self.archive.open('wb') as stream:
            stream.truncate(bundle.MAX_ARCHIVE + 1)
        with self.assertRaises(bundle.BundleError):
            bundle.unpack(self.archive, self.key, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(bundle.MAX_ARCHIVE + 1, self.archive.stat().st_size)

    def test_cli_error_does_not_disclose_contents_or_paths(self):
        self.make_archive()
        self.key.write_bytes(b'secret-key-content')
        output = io.StringIO()
        with redirect_stdout(output):
            code = bundle.main(['unpack', '--archive', str(self.archive), '--key', str(self.key),
                                '--destination', str(self.destination)])
        self.assertEqual(1, code)
        self.assertEqual({'status': 'INVALID_KEY'}, json.loads(output.getvalue()))
        self.assertNotIn('secret', output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    def test_invalid_arguments_do_not_echo_supplied_values(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = bundle.main(['unpack', '--secret=do-not-log-this'])
        self.assertEqual(1, code)
        self.assertEqual({'status': 'INVALID_ARGUMENTS'}, json.loads(output.getvalue()))


if __name__ == '__main__':
    unittest.main()
