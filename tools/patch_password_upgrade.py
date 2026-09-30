"""Route audited Core sign-in verification and single-user/bulk import validation through PasswordUpgrade.

Sign-in: only the verification call changes; lookup, WrongCredentials mapping, the Firebase
signer-key error and audit emission stay upstream. Import: the upstream prefix check is kept
and a structural/cost-bound check is added after it, for single-user import (EmailPassword)
and bulk-import add validation (BulkImportUserUtils). Original source remains untouched.
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


BULK_PATH = 'src/main/java/io/supertokens/bulkimport/BulkImportUserUtils.java'
BULK_ANCHOR = ('        try {\n'
               '            PasswordHashingUtils.assertSuperTokensSupportInputPasswordHashFormat(appIdentifier, main, passwordHash,\n'
               '                    hashingAlgorithm);\n'
               '        } catch (UnsupportedPasswordHashingFormatException e) {\n'
               '            errors.add(e.getMessage());\n'
               '        }\n')
BULK_REPLACEMENT = ('        boolean upstreamFormatAccepted = true;\n'
                    '        try {\n'
                    '            PasswordHashingUtils.assertSuperTokensSupportInputPasswordHashFormat(appIdentifier, main, passwordHash,\n'
                    '                    hashingAlgorithm);\n'
                    '        } catch (UnsupportedPasswordHashingFormatException e) {\n'
                    '            errors.add(e.getMessage());\n'
                    '            upstreamFormatAccepted = false;\n'
                    '        }\n'
                    '        // ExpertAuth: same full-structure and cost bounds as single-user import.\n'
                    '        if (upstreamFormatAccepted && !io.expertauth.core.PasswordUpgrade.structurallyValid(passwordHash)) {\n'
                    '            errors.add("Password hash is malformed or exceeds import cost bounds");\n'
                    '        }\n')


def patch_bulk(original):
    if original.count(BULK_ANCHOR) != 1 or original.count('private String validateAndNormalisePasswordHash(') != 1:
        raise ValueError('Audited bulk-import hash validation anchor differs')
    return original.replace(BULK_ANCHOR, BULK_REPLACEMENT) + (
        '\n/* Modified by ExpertAuth contributors (2026): bulk-import password hashes additionally require full '
        'structure and bounded cost via PasswordUpgrade.structurallyValid; upstream checks and messages retained. */\n')
