"""Route audited Core sign-in verification and single-user import validation through PasswordUpgrade.

Sign-in: only the verification call changes; lookup, WrongCredentials mapping, the Firebase
signer-key error and audit emission stay upstream. Import: the upstream prefix check is kept
and a structural/cost-bound check is added after it. Original source remains untouched.
"""
PATH = 'src/main/java/io/supertokens/emailpassword/EmailPassword.java'
ANCHOR = ('            if (!PasswordHashing.getInstance(main)\n'
          '                    .verifyPasswordWithHash(tenantIdentifier.toAppIdentifier(), password,\n'
          '                            lM.passwordHash)) {\n')
REPLACEMENT = ('            // ExpertAuth: verification plus locked on-login rehash to the configured algorithm.\n'
               '            if (!io.expertauth.core.PasswordUpgrade.signIn(main, tenantIdentifier.toAppIdentifier(),\n'
               '                    storage, lM, password)) {\n')


IMPORT_ANCHOR = ('        PasswordHashingUtils.assertSuperTokensSupportInputPasswordHashFormat(\n'
                 '                tenantIdentifier.toAppIdentifier(), main,\n'
                 '                passwordHash, hashingAlgorithm);\n')
IMPORT_REPLACEMENT = IMPORT_ANCHOR + (
    '        // ExpertAuth: imported hashes need full structure and bounded cost, not just a known prefix.\n'
    '        if (!io.expertauth.core.PasswordUpgrade.structurallyValid(passwordHash)) {\n'
    '            throw new UnsupportedPasswordHashingFormatException("Password hash is malformed or exceeds import cost bounds");\n'
    '        }\n')


def patch(original):
    if original.count(ANCHOR) != 1 or original.count('public static AuthRecipeUserInfo signIn(TenantIdentifier') != 1:
        raise ValueError('Audited sign-in verification anchor differs')
    if original.count(IMPORT_ANCHOR) != 1 or original.count('public static ImportUserResponse importUserWithPasswordHash(TenantIdentifier') != 1:
        raise ValueError('Audited import validation anchor differs')
    return original.replace(ANCHOR, REPLACEMENT).replace(IMPORT_ANCHOR, IMPORT_REPLACEMENT) + (
        '\n/* Modified by ExpertAuth contributors (2026): sign-in verification delegates to PasswordUpgrade, which '
        'calls the unchanged Core hasher and rehashes outdated credentials through the storage plugin transaction API; '
        'single-user import additionally requires full hash structure and bounded cost. */\n')
