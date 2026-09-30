"""Source-transform guards for the PasswordUpgrade sign-in hook; tooling checks, not engine acceptance."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from patch_password_upgrade import ANCHOR, IMPORT_ANCHOR, PATH, patch
import build_password_session as builder

HEADER = '    public static AuthRecipeUserInfo signIn(TenantIdentifier tenantIdentifier, Storage storage, Main main,\n'
IMPORT_HEADER = '    public static ImportUserResponse importUserWithPasswordHash(TenantIdentifier tenantIdentifier, Storage storage,\n'
BODY = (IMPORT_HEADER + IMPORT_ANCHOR + '        EmailPasswordSQLStorage epStorage = null;\n' +
        HEADER + '        try {\n' + ANCHOR + '                throw new WrongCredentialsException();\n            }\n')


class SignInPatch(unittest.TestCase):
    def test_replaces_only_the_verification_call(self):
        patched = patch(BODY)
        self.assertNotIn('verifyPasswordWithHash', patched)
        self.assertIn('io.expertauth.core.PasswordUpgrade.signIn(main, tenantIdentifier.toAppIdentifier(),', patched)
        self.assertIn('throw new WrongCredentialsException();', patched)
        self.assertIn('PasswordUpgrade.structurallyValid(passwordHash)', patched)
        self.assertLess(patched.index('assertSuperTokensSupportInputPasswordHashFormat'), patched.index('structurallyValid'))
        self.assertTrue(patched.rstrip().endswith('*/'))

    def test_refuses_changed_or_repeated_anchor(self):
        for text in [BODY.replace('lM.passwordHash', 'lm.passwordHash'), BODY + ANCHOR, BODY.replace(HEADER, ''),
                     BODY.replace(IMPORT_ANCHOR, ''), BODY + IMPORT_ANCHOR, BODY.replace(IMPORT_HEADER, '')]:
            with self.assertRaises(ValueError):
                patch(text)

    def test_builder_dispatches_sign_in_path(self):
        filename, patched = builder.patched_source(PATH, BODY)
        self.assertEqual(filename, 'EmailPassword.java')
        self.assertIn('PasswordUpgrade.signIn', patched)

    def test_upgrade_requires_utf8_reader(self):
        source = (ROOT / 'tools/build_password_session.py').read_text()
        self.assertIn("need(not args.password_upgrade or args.firebase_scrypt_bc", source)

    def test_no_legacy_decoding_remains(self):
        for path in ['engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java', 'tools/patch_password_upgrade.py']:
            text = (ROOT / path).read_text()
            self.assertNotIn('iso_8859_1', text.lower())
            self.assertNotIn('legacy', text.lower())

    def test_builder_compiles_password_upgrade(self):
        self.assertIn('engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java', builder.SOURCES)
        self.assertIn('tools/patch_password_upgrade.py', builder.SOURCES)


if __name__ == '__main__':
    unittest.main()
