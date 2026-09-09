"""Adapt the audited Core Firebase verifier to the existing Bouncy Castle primitive.

No KDF implementation is copied or invented. Original source remains untouched.
"""
PATH = 'src/main/java/io/supertokens/emailpassword/PasswordHashingUtils.java'
INPUT = 'src/main/java/io/supertokens/webserver/InputParser.java'


def patch_input(original):
    anchor = '        StringBuilder sb = new StringBuilder();'
    if original.count(anchor) != 1:
        raise ValueError('Audited JSON input anchor differs')
    return original.replace(anchor,
        '        // ExpertAuth: JSON without an explicit servlet charset uses UTF-8.\n'
        '        if (request.getCharacterEncoding() == null) request.setCharacterEncoding("UTF-8");\n' + anchor) + (
        '\n/* Modified by ExpertAuth contributors (2026): default JSON request decoding to UTF-8 before getReader; '
        'explicit servlet character encodings and all existing parsing/error/authorization behavior retained. */\n')


def patch(original):
    changes = {
        'import com.lambdaworks.crypto.SCrypt;': 'import org.bouncycastle.crypto.generators.SCrypt;',
        'import java.security.GeneralSecurityException;': 'import java.security.MessageDigest;',
        '        int N = 1 << response.memCost;':
            '        // ExpertAuth: reject shift aliases and invalid block sizes before deriving.\n'
            '        if (response.memCost < 1 || response.memCost > 30 || response.rounds < 1) return false;\n'
            '        int N = 1 << response.memCost;',
        'hashedBytes = SCrypt.scrypt(plainTextPassword.getBytes(StandardCharsets.US_ASCII), saltConcat, N,':
            'hashedBytes = SCrypt.generate(plainTextPassword.getBytes(StandardCharsets.UTF_8), saltConcat, N,',
        '        } catch (GeneralSecurityException e) {': '        } catch (IllegalArgumentException e) {',
        '            return Objects.requireNonNull(Base64.encodeBase64String(encryptedPasswordHash))\n'
        '                    .equals(response.passwordHash);':
            '            return MessageDigest.isEqual(Base64.encodeBase64(encryptedPasswordHash),\n'
            '                    response.passwordHash.getBytes(StandardCharsets.US_ASCII));',
        'import java.util.Objects;\n': '',
    }
    for old, new in changes.items():
        if original.count(old) != 1:
            raise ValueError('Audited Firebase verifier anchor differs')
        original = original.replace(old, new)
    return original + ('\n/* Modified by ExpertAuth contributors (2026): delegate scrypt to unchanged Bouncy Castle; '
                       'use UTF-8 passwords, reject shift aliases and compare fixed expected encodings with MessageDigest. '
                       'Existing Core format, configured signer, AES, ownership and authorization retained. */\n')
