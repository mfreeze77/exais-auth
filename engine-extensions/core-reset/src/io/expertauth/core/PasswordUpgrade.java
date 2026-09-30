/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import io.supertokens.Main;
import io.supertokens.config.Config;
import io.supertokens.config.CoreConfig;
import io.supertokens.emailpassword.PasswordHashing;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.authRecipe.AuthRecipeUserInfo;
import io.supertokens.pluginInterface.authRecipe.LoginMethod;
import io.supertokens.pluginInterface.authRecipe.sqlStorage.AuthRecipeSQLStorage;
import io.supertokens.pluginInterface.emailpassword.sqlStorage.EmailPasswordSQLStorage;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.multitenancy.AppIdentifier;
import io.supertokens.pluginInterface.sqlStorage.SQLStorage;
import io.supertokens.pluginInterface.sqlStorage.TransactionConnection;
import io.supertokens.pluginInterface.useridmapping.UserLockingStorage;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * On-login rehash over Core's own hasher and storage (PWD-005).
 *
 * Verification is Core's unchanged PasswordHashing with the UTF-8 decoded password;
 * there is no alternate decoding. When an accepted hash's format or cost differs from
 * the configured Core algorithm (imported bcrypt/argon2/Firebase scrypt, changed bcrypt
 * rounds or argon2 m/t/p, argon2i/d), the correctly decoded password is rehashed and
 * stored through the storage plugin transaction API as a compare-and-replace.
 * No hash primitive is implemented here.
 */
public final class PasswordUpgrade {
    public static final String POLICY = "EXPERTAUTH-PASSWORD-UPGRADE-2";
    private static final Pattern BCRYPT = Pattern.compile("^\\$2[abxy]\\$(\\d{2})\\$.{53}$");
    private static final Pattern ARGON2ID = Pattern.compile("^\\$argon2id\\$v=19\\$m=(\\d{1,10}),t=(\\d{1,10}),p=(\\d{1,10})\\$[^$]+\\$[^$]+$");

    private PasswordUpgrade() {}

    /** Current Core hashing target; FIREBASE_SCRYPT cannot be produced by Core and never triggers rehash. */
    public record Target(String algorithm, int bcryptRounds, int argon2Iterations, int argon2MemoryKb, int argon2Parallelism) {}

    public record Outcome(boolean accepted, String replacementHash) {}

    // Import-time structure and resource bounds. Prefix-only acceptance creates accounts that can never
    // sign in, and unbounded costs turn every login attempt on an imported account into a resource sink.
    public static final int BCRYPT_MIN_COST = 4, BCRYPT_MAX_COST = 16;
    public static final long ARGON2_MAX_MEMORY_KB = 1_048_576, ARGON2_MAX_ITERATIONS = 100, ARGON2_MAX_PARALLELISM = 64;
    public static final int FIREBASE_MAX_MEM_COST = 17, FIREBASE_MAX_ROUNDS = 32;
    private static final Pattern BCRYPT_STRUCTURE = Pattern.compile("^\\$2[abxy]\\$(\\d{2})\\$[./A-Za-z0-9]{53}$");
    private static final Pattern ARGON2_STRUCTURE = Pattern.compile(
        "^\\$argon2(?:id|i|d)\\$v=(?:16|19)\\$m=(\\d{1,10}),t=(\\d{1,10}),p=(\\d{1,10})\\$[A-Za-z0-9+/]{11,}\\$[A-Za-z0-9+/]{16,}$");
    private static final Pattern FIREBASE_STRUCTURE = Pattern.compile(
        "^\\$f_scrypt\\$([A-Za-z0-9+/]+={0,2})\\$([A-Za-z0-9+/]+={0,2})\\$m=(\\d{1,2})\\$r=(\\d{1,2})\\$s=([A-Za-z0-9+/]+={0,2})$");

    /**
     * Full structural check for bcrypt, argon2 and Firebase scrypt strings, including resource bounds.
     * Other strings return true so Core's own format check reports them unchanged.
     */
    public static boolean structurallyValid(String hash) {
        if (hash.startsWith("$2")) {
            Matcher m = BCRYPT_STRUCTURE.matcher(hash);
            if (!m.matches()) return false;
            int cost = Integer.parseInt(m.group(1));
            return cost >= BCRYPT_MIN_COST && cost <= BCRYPT_MAX_COST;
        }
        if (hash.startsWith("$argon2")) {
            Matcher m = ARGON2_STRUCTURE.matcher(hash);
            if (!m.matches()) return false;
            long memory = Long.parseLong(m.group(1)), iterations = Long.parseLong(m.group(2)), parallelism = Long.parseLong(m.group(3));
            return parallelism >= 1 && parallelism <= ARGON2_MAX_PARALLELISM && memory >= 8 * parallelism &&
                memory <= ARGON2_MAX_MEMORY_KB && iterations >= 1 && iterations <= ARGON2_MAX_ITERATIONS;
        }
        if (hash.startsWith("$f_scrypt$")) {
            Matcher m = FIREBASE_STRUCTURE.matcher(hash);
            if (!m.matches()) return false;
            int memCost = Integer.parseInt(m.group(3)), rounds = Integer.parseInt(m.group(4));
            try {
                java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
                if (decoder.decode(m.group(1)).length == 0 || decoder.decode(m.group(2)).length == 0) return false;
                decoder.decode(m.group(5));
            } catch (IllegalArgumentException malformed) {
                return false;
            }
            return memCost >= 1 && memCost <= FIREBASE_MAX_MEM_COST && rounds >= 1 && rounds <= FIREBASE_MAX_ROUNDS;
        }
        return true;
    }

    /** True when an accepted stored hash is not already in the configured Core format and cost. */
    public static boolean needsRehash(String hash, Target target) {
        if ("BCRYPT".equals(target.algorithm())) {
            Matcher m = BCRYPT.matcher(hash);
            return !m.matches() || Integer.parseInt(m.group(1)) != target.bcryptRounds();
        }
        if ("ARGON2".equals(target.algorithm())) {
            Matcher m = ARGON2ID.matcher(hash);
            return !m.matches() || Long.parseLong(m.group(1)) != target.argon2MemoryKb() ||
                Long.parseLong(m.group(2)) != target.argon2Iterations() ||
                Long.parseLong(m.group(3)) != target.argon2Parallelism();
        }
        return false;
    }

    static Target target(CoreConfig config) {
        return new Target(config.getPasswordHashingAlg().name(), config.getBcryptLogRounds(),
            config.getArgon2Iterations(), config.getArgon2MemoryKb(), config.getArgon2Parallelism());
    }

    /**
     * Verifies with Core's hasher and, when accepted but outdated, prepares a replacement hash
     * outside any row lock. Exceptions from verification propagate unchanged.
     */
    public static Outcome check(Main main, AppIdentifier app, String password, String hash) throws Exception {
        PasswordHashing hashing = PasswordHashing.getInstance(main);
        if (!hashing.verifyPasswordWithHash(app, password, hash)) return new Outcome(false, null);
        if (!needsRehash(hash, target(Config.getConfig(app.getAsPublicTenantIdentifier(), main)))) {
            return new Outcome(true, null);
        }
        return new Outcome(true, hashing.createHashWithSalt(app, password));
    }

    /** Replaces the hash on the caller's transaction only if it is still the verified one. */
    public static boolean replace(Storage storage, AppIdentifier app, TransactionConnection transaction,
            String recipeUserId, String verifiedHash, String replacementHash) throws Exception {
        AuthRecipeUserInfo current = ((AuthRecipeSQLStorage) storage).getPrimaryUserById_Transaction(app, transaction, recipeUserId);
        if (current == null) return false;
        for (LoginMethod method : current.loginMethods) {
            if (method.recipeId == RECIPE_ID.EMAIL_PASSWORD && recipeUserId.equals(method.getSupertokensUserId())) {
                if (!verifiedHash.equals(method.passwordHash)) return false;
                ((EmailPasswordSQLStorage) storage).updateUsersPassword_Transaction(app, transaction, recipeUserId, replacementHash);
                return true;
            }
        }
        return false;
    }

    /**
     * Upstream /recipe/signin hook. Acceptance follows verification; the rehash is a
     * best-effort locked compare-and-replace, retried on the next sign-in if it fails.
     */
    public static boolean signIn(Main main, AppIdentifier app, Storage storage, LoginMethod method, String password)
            throws Exception {
        Outcome outcome = check(main, app, password, method.passwordHash);
        if (outcome.replacementHash() == null || !(storage instanceof SQLStorage &&
                storage instanceof EmailPasswordSQLStorage && storage instanceof AuthRecipeSQLStorage &&
                storage instanceof UserLockingStorage)) {
            return outcome.accepted();
        }
        String recipeUserId = method.getSupertokensUserId();
        try {
            ((SQLStorage) storage).startTransaction(transaction -> {
                try {
                    ((UserLockingStorage) storage).lockUser(app, transaction, recipeUserId);
                    if (replace(storage, app, transaction, recipeUserId, method.passwordHash, outcome.replacementHash())) {
                        ((SQLStorage) storage).commitTransaction(transaction);
                    }
                    return null;
                } catch (Exception error) {
                    throw new StorageTransactionLogicException(error);
                }
            });
        } catch (Exception ignored) {
            // The credential was verified; a failed upgrade leaves the prior hash intact.
        }
        return true;
    }
}
