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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Legacy-decoding fallback and on-login rehash over Core's own hasher and storage.
 *
 * Before the UTF-8 JSON reader change, a request without a servlet charset was
 * decoded as ISO-8859-1, so Core hashed the UTF-8 bytes' Latin-1 reading. The
 * fallback reproduces only that decoding, only when explicitly enabled, only for
 * bcrypt/argon2 hashes whose SHA-256 is in the operator's cutover snapshot, and
 * only after the current decoding fails. A post-cutover password never becomes
 * eligible, and a legacy match rehashes the correctly decoded password, which
 * leaves the snapshot by construction once the update commits.
 * No hash primitive is implemented here; verification and hashing stay in Core.
 */
public final class PasswordUpgrade {
    public static final String POLICY = "EXPERTAUTH-PASSWORD-UPGRADE-1";
    public static final String LEGACY_ENV = "EXPERTAUTH_LEGACY_PASSWORD_DECODING";
    public static final String LEGACY_VALUE = "servlet-iso-8859-1-v1";
    public static final String SNAPSHOT_ENV = "EXPERTAUTH_LEGACY_PASSWORD_HASHES";
    private static final Pattern SNAPSHOT_ROW = Pattern.compile("^[0-9a-f]{64}$");
    private static volatile Set<String> snapshot;
    private static final Pattern BCRYPT = Pattern.compile("^\\$2[abxy]\\$(\\d{2})\\$.{53}$");
    private static final Pattern ARGON2ID = Pattern.compile("^\\$argon2id\\$v=19\\$m=(\\d{1,10}),t=(\\d{1,10}),p=(\\d{1,10})\\$[^$]+\\$[^$]+$");

    private PasswordUpgrade() {}

    public enum Match { CURRENT, LEGACY_SERVLET_DECODING, NONE }

    @FunctionalInterface public interface Verifier {
        boolean verify(String password, String hash) throws Exception;
    }

    /** Current Core hashing target; FIREBASE_SCRYPT cannot be produced by Core and never triggers rehash. */
    public record Target(String algorithm, int bcryptRounds, int argon2Iterations, int argon2MemoryKb, int argon2Parallelism) {}

    public record Outcome(Match match, String replacementHash) {
        public boolean accepted() { return match != Match.NONE; }
    }

    public static final class Misconfigured extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        public Misconfigured() { super("Invalid " + LEGACY_ENV + "/" + SNAPSHOT_ENV + " configuration"); }
    }

    /** Absent means disabled. Any value other than the exact policy fails closed rather than guessing. */
    public static boolean legacyEnabled(String value) {
        if (value == null || value.isEmpty()) return false;
        if (LEGACY_VALUE.equals(value)) return true;
        throw new Misconfigured();
    }

    public static String hashId(String storedHash) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(storedHash.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /** One lowercase SHA-256 hex digest of a stored hash per line; blank lines ignored; anything else is refused. */
    public static Set<String> parseSnapshot(List<String> lines) {
        Set<String> rows = new HashSet<>();
        for (String line : lines) {
            String row = line.strip();
            if (row.isEmpty()) continue;
            if (!SNAPSHOT_ROW.matcher(row).matches()) throw new Misconfigured();
            rows.add(row);
        }
        if (rows.isEmpty()) throw new Misconfigured();
        return Set.copyOf(rows);
    }

    /** Null when the fallback is disabled; otherwise membership in the immutable cutover snapshot. */
    static Predicate<String> legacyPolicy() {
        if (!legacyEnabled(System.getenv(LEGACY_ENV))) return null;
        Set<String> rows = snapshot;
        if (rows == null) {
            synchronized (PasswordUpgrade.class) {
                if (snapshot == null) {
                    String file = System.getenv(SNAPSHOT_ENV);
                    if (file == null || file.isEmpty()) throw new Misconfigured();
                    try {
                        snapshot = parseSnapshot(Files.readAllLines(Path.of(file), StandardCharsets.US_ASCII));
                    } catch (java.io.IOException error) {
                        throw new Misconfigured();
                    }
                }
                rows = snapshot;
            }
        }
        Set<String> eligible = rows;
        return hash -> eligible.contains(hashId(hash));
    }

    /** The historical servlet reading of this password, or null when it is identical (pure ASCII). */
    public static String legacyServletDecoding(String password) {
        boolean ascii = true;
        for (int i = 0; i < password.length() && ascii; i++) ascii = password.charAt(i) < 0x80;
        return ascii ? null : new String(password.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    /** Only hashes Core itself could have created from a servlet-decoded string are eligible. */
    static boolean legacyEligible(String hash) {
        return hash.startsWith("$2") || hash.startsWith("$argon2");
    }

    public static Match verify(Verifier verifier, String password, String hash, Predicate<String> legacy) throws Exception {
        if (verifier.verify(password, hash)) return Match.CURRENT;
        if (legacy == null || !legacyEligible(hash) || !legacy.test(hash)) return Match.NONE;
        String historical = legacyServletDecoding(password);
        if (historical == null) return Match.NONE;
        return verifier.verify(historical, hash) ? Match.LEGACY_SERVLET_DECODING : Match.NONE;
    }

    public static boolean needsRehash(Match match, String hash, Target target) {
        if (match == Match.NONE) return false;
        if (match == Match.LEGACY_SERVLET_DECODING) return true;
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
        Match match = verify((p, h) -> hashing.verifyPasswordWithHash(app, p, h), password, hash, legacyPolicy());
        if (!needsRehash(match, hash, target(Config.getConfig(app.getAsPublicTenantIdentifier(), main)))) {
            return new Outcome(match, null);
        }
        return new Outcome(match, hashing.createHashWithSalt(app, password));
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
