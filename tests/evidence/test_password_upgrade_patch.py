"""Source-transform guards for the PasswordUpgrade sign-in hook; tooling checks, not engine acceptance."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from patch_password_upgrade import ANCHOR, PATH, patch
import build_password_session as builder

HEADER = '    public static AuthRecipeUserInfo signIn(TenantIdentifier tenantIdentifier, Storage storage, Main main,\n'
BODY = HEADER + '        try {\n' + ANCHOR + '                throw new WrongCredentialsException();\n            }\n'


class SignInPatch(unittest.TestCase):
    def test_replaces_only_the_verification_call(self):
        patched = patch(BODY)
        self.assertNotIn('verifyPasswordWithHash', patched)
        self.assertIn('io.expertauth.core.PasswordUpgrade.signIn(main, tenantIdentifier.toAppIdentifier(),', patched)
        self.assertIn('throw new WrongCredentialsException();', patched)
        self.assertTrue(patched.rstrip().endswith('*/'))

    def test_refuses_changed_or_repeated_anchor(self):
        for text in [BODY.replace('lM.passwordHash', 'lm.passwordHash'), BODY + ANCHOR, BODY.replace(HEADER, '')]:
            with self.assertRaises(ValueError):
                patch(text)

    def test_builder_dispatches_sign_in_path(self):
        filename, patched = builder.patched_source(PATH, BODY)
        self.assertEqual(filename, 'EmailPassword.java')
        self.assertIn('PasswordUpgrade.signIn', patched)

    def test_builder_compiles_password_upgrade(self):
        self.assertIn('engine-extensions/core-reset/src/io/expertauth/core/PasswordUpgrade.java', builder.SOURCES)
        self.assertIn('tools/patch_password_upgrade.py', builder.SOURCES)


if __name__ == '__main__':
    unittest.main()
