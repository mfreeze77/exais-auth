"""Route the audited Core sign-in verification through io.expertauth.core.PasswordUpgrade.

Only the verification call changes. Lookup, WrongCredentials mapping, the Firebase
signer-key error and audit emission stay upstream. Original source remains untouched.
"""
PATH = 'src/main/java/io/supertokens/emailpassword/EmailPassword.java'
ANCHOR = ('            if (!PasswordHashing.getInstance(main)\n'
          '                    .verifyPasswordWithHash(tenantIdentifier.toAppIdentifier(), password,\n'
          '                            lM.passwordHash)) {\n')
REPLACEMENT = ('            // ExpertAuth: explicit legacy-decoding fallback and locked on-login rehash.\n'
               '            if (!io.expertauth.core.PasswordUpgrade.signIn(main, tenantIdentifier.toAppIdentifier(),\n'
               '                    storage, lM, password)) {\n')


def patch(original):
    if original.count(ANCHOR) != 1 or original.count('public static AuthRecipeUserInfo signIn(TenantIdentifier') != 1:
        raise ValueError('Audited sign-in verification anchor differs')
    return original.replace(ANCHOR, REPLACEMENT) + (
        '\n/* Modified by ExpertAuth contributors (2026): sign-in verification delegates to PasswordUpgrade, which '
        'calls the unchanged Core hasher, applies the opt-in ISO-8859-1 legacy decoding fallback and rehashes '
        'outdated credentials through the storage plugin transaction API. */\n')
