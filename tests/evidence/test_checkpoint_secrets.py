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


if __name__=='__main__':
    unittest.main()
