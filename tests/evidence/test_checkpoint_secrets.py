import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
from package_checkpoint import local_secrets, secret_leaks


class CheckpointSecretTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.private=self.root/'.runtime/password-reset/run-01/secrets'
        self.private.mkdir(parents=True)
        self.env=self.private/'good.env'
        self.env.write_text('EXPERTAUTH_SMTP_PASSWORD_FILE=/run/mailpit/smtp-password\n')
        (self.private/'smtp-password').write_bytes(b'short-pwd\r\n')
        (self.private/'wrong-password').write_bytes(b'wrong-pwd\n')

    def test_path_is_allowed_but_both_real_credentials_are_rejected(self):
        values=local_secrets(self.root)
        self.assertEqual(values,{b'short-pwd',b'wrong-pwd'})
        self.assertEqual(secret_leaks({'source':b'/run/mailpit/smtp-password'},values),[])
        self.assertEqual(secret_leaks({'real':b'prefix short-pwd suffix','negative':b'wrong-pwd'},values),['real','negative'])

    def test_wrong_auth_mount_scans_both_files(self):
        self.env.rename(self.private/'wrong-auth.env')
        self.assertEqual(local_secrets(self.root),{b'short-pwd',b'wrong-pwd'})

    def test_unsupported_core_profile_scans_actual_smtp_credentials(self):
        self.env.rename(self.private/'unsupported.env')
        self.assertEqual(local_secrets(self.root),{b'short-pwd',b'wrong-pwd'})

    def test_missing_writer_profile_scans_actual_smtp_credentials(self):
        self.env.rename(self.private/'missing-writer.env')
        self.assertEqual(local_secrets(self.root),{b'short-pwd',b'wrong-pwd'})

    def test_significant_spaces_and_bom_are_preserved(self):
        (self.private/'smtp-password').write_bytes(b' spaces \r\n')
        (self.private/'wrong-password').write_bytes(b'\xef\xbb\xbfwrong-pwd')
        self.assertEqual(local_secrets(self.root),{b' spaces ',b'\xef\xbb\xbfwrong-pwd'})

    def test_one_byte_secret_remains_protected(self):
        (self.private/'smtp-password').write_bytes(b'Z')
        self.assertEqual(secret_leaks({'file':b'prefix Z suffix'},local_secrets(self.root)),['file'])

    def test_missing_target_cannot_exempt_reference(self):
        (self.private/'smtp-password').unlink()
        with self.assertRaisesRegex(AssertionError,'missing or unsafe'):
            local_secrets(self.root)

    def test_missing_negative_target_cannot_exempt_reference(self):
        (self.private/'wrong-password').unlink()
        with self.assertRaisesRegex(AssertionError,'missing or unsafe'):
            local_secrets(self.root)

    def test_invalid_or_oversized_credentials_fail_closed(self):
        for raw in (b'',b'a'*4099,b'line\nbreak',b'\xff'):
            with self.subTest(size=len(raw)):
                (self.private/'smtp-password').write_bytes(raw)
                with self.assertRaises((AssertionError,UnicodeDecodeError)):
                    local_secrets(self.root)

    def test_directory_target_fails_closed(self):
        target=self.private/'smtp-password'
        target.unlink()
        target.mkdir()
        with self.assertRaisesRegex(AssertionError,'missing or unsafe'):
            local_secrets(self.root)

    def test_direct_secret_values_remain_protected(self):
        self.env.write_text('EXPERTAUTH_API_KEY=0123456789abcdef0123456789\nPASSWORD=abcdef0123456789\n')
        values=local_secrets(self.root)
        self.assertEqual(secret_leaks({'key':b'0123456789abcdef0123456789','password':b'abcdef0123456789'},values),['key','password'])

    def test_unknown_file_setting_is_not_exempt(self):
        self.env.write_text('OTHER_PASSWORD_FILE=/run/mailpit/smtp-password\n')
        self.assertIn(b'/run/mailpit/smtp-password',local_secrets(self.root))

    def test_unknown_mount_path_is_not_opened_or_exempt(self):
        self.env.write_text('EXPERTAUTH_SMTP_PASSWORD_FILE=/outside/unknown/password\n')
        self.assertIn(b'/outside/unknown/password',local_secrets(self.root))

    def test_known_key_outside_owned_layout_is_not_exempt(self):
        other=self.root/'.runtime/unrelated.env'
        self.env.rename(other)
        self.assertIn(b'/run/mailpit/smtp-password',local_secrets(self.root))

    def test_launcher_authorized_leading_underscore_name(self):
        self.private.parent.rename(self.private.parent.with_name('_owned-run'))
        self.assertEqual(local_secrets(self.root),{b'short-pwd',b'wrong-pwd'})

    def test_name_outside_launcher_namespace_is_not_exempt(self):
        self.private.parent.rename(self.private.parent.with_name('not.a.launcher.run'))
        self.assertIn(b'/run/mailpit/smtp-password',local_secrets(self.root))

    def upgrade_fixture(self, name='fixture.json', value=None):
        directory=self.root/'.runtime/atomic-core-replacement/installed-02/fixture'
        directory.mkdir(parents=True,exist_ok=True)
        path=directory/name
        state=value if value is not None else {
            'password':'upgrade-private-password',
            'session':{'accessToken':{'token':'legacy-access'},'refreshToken':{'token':'legacy-refresh'}},
            'atomic_session':{'accessToken':{'token':'atomic-access'},'refreshToken':{'token':'atomic-refresh'}}}
        path.write_text(json.dumps(state))
        return path

    def test_upgrade_password_and_both_session_generations_are_protected(self):
        self.upgrade_fixture()
        files={str(i):v for i,v in enumerate((b'upgrade-private-password',b'legacy-access',b'legacy-refresh',b'atomic-access',b'atomic-refresh'))}
        self.assertEqual(secret_leaks(files,local_secrets(self.root)),list(files))
        self.assertEqual(secret_leaks({'source':b"Path('/private/fixture.json')"},local_secrets(self.root)),[])

    def test_interrupted_upgrade_save_protects_both_journals(self):
        self.upgrade_fixture()
        self.upgrade_fixture('fixture.tmp',{'password':'interrupted-password'})
        values=local_secrets(self.root)
        self.assertIn(b'upgrade-private-password',values)
        self.assertIn(b'interrupted-password',values)

    def test_seed_before_session_is_protected(self):
        self.upgrade_fixture(value={'password':'seed-only-password'})
        self.assertIn(b'seed-only-password',local_secrets(self.root))

    def test_corrupt_or_incomplete_upgrade_journal_fails_closed(self):
        path=self.upgrade_fixture()
        for raw in ('{', '[]', '{}', '{"password":"p","session":{}}', '{"password":"p","session":{"accessToken":{"token":"a"},"refreshToken":{"token":null}}}'):
            with self.subTest(raw=raw):
                path.write_text(raw)
                with self.assertRaises((AssertionError,ValueError,KeyError)):
                    local_secrets(self.root)

    def test_oversized_or_directory_upgrade_journal_fails_closed(self):
        path=self.upgrade_fixture()
        path.write_bytes(b'x'*262145)
        with self.assertRaisesRegex(AssertionError,'size or file type'):
            local_secrets(self.root)
        path.unlink(); path.mkdir()
        with self.assertRaisesRegex(AssertionError,'size or file type'):
            local_secrets(self.root)

    def test_controller_failure_before_journal_is_allowed(self):
        (self.root/'.runtime/atomic-core-replacement/installed-02').mkdir(parents=True)
        self.assertEqual(local_secrets(self.root),{b'short-pwd',b'wrong-pwd'})


if __name__=='__main__':
    unittest.main()
