/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import io.expertauth.core.PasswordUpgrade;
import io.expertauth.core.PasswordUpgrade.Match;
import io.expertauth.core.PasswordUpgrade.Target;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Predicate;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Decision-logic checks for PasswordUpgrade with the same bcrypt/argon2 libraries Core uses.
 * Legacy hashes are produced exactly as the pre-UTF-8 reader did: hash(ISO-8859-1 reading of UTF-8 bytes).
 * Run: java -cp <classes>:<jbcrypt>:<argon2-jvm>:<jna> PasswordUpgradeTest
 */
public final class PasswordUpgradeTest {
    private static final Map<String, Object> RESULTS = new LinkedHashMap<>();
    private static final Argon2 ARGON2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 16, 32);
    private static final Target BCRYPT_10 = new Target("BCRYPT", 10, 1, 87795, 2);
    private static final Target ARGON2_T = new Target("ARGON2", 10, 1, 87795, 2);

    private static void check(String name, boolean passed) {
        RESULTS.put(name, passed);
        if (!passed) System.err.println("FAILED " + name);
    }

    private static boolean verify(String password, String hash) {
        if (hash.startsWith("$argon2")) return ARGON2.verify(hash, password.toCharArray());
        return BCrypt.checkpw(password, hash);
    }

    private static <T extends Throwable> boolean throwsType(Class<T> type, Runnable action) {
        try { action.run(); return false; } catch (Throwable error) { return type.isInstance(error); }
    }

    public static void main(String[] args) throws Exception {
        String unicode = "pässwörd-密码-🔑";
        String historical = new String(unicode.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        String legacyBcrypt = BCrypt.hashpw(historical, BCrypt.gensalt(10));
        String legacyArgon2 = ARGON2.hash(1, 87795, 2, historical.toCharArray());
        String currentBcrypt = BCrypt.hashpw(unicode, BCrypt.gensalt(10));
        Predicate<String> snapshot = Set.of(PasswordUpgrade.hashId(legacyBcrypt), PasswordUpgrade.hashId(legacyArgon2))::contains;
        Predicate<String> legacy = hash -> snapshot.test(PasswordUpgrade.hashId(hash));

        check("historical_decoding_matches_old_servlet_reader", historical.equals(PasswordUpgrade.legacyServletDecoding(unicode)));
        check("ascii_has_no_distinct_legacy_form", PasswordUpgrade.legacyServletDecoding("plain-ASCII-123") == null);
        check("legacy_disabled_rejects_unicode_legacy_bcrypt", PasswordUpgrade.verify(PasswordUpgradeTest::verify, unicode, legacyBcrypt, null) == Match.NONE);
        check("legacy_enabled_accepts_snapshot_bcrypt", PasswordUpgrade.verify(PasswordUpgradeTest::verify, unicode, legacyBcrypt, legacy) == Match.LEGACY_SERVLET_DECODING);
        check("legacy_enabled_accepts_snapshot_argon2", PasswordUpgrade.verify(PasswordUpgradeTest::verify, unicode, legacyArgon2, legacy) == Match.LEGACY_SERVLET_DECODING);
        check("wrong_unicode_password_rejected", PasswordUpgrade.verify(PasswordUpgradeTest::verify, "pässwörd-wrong", legacyBcrypt, legacy) == Match.NONE);
        check("current_decoding_preferred", PasswordUpgrade.verify(PasswordUpgradeTest::verify, unicode, currentBcrypt, legacy) == Match.CURRENT);

        // A post-cutover password whose text is itself a Latin-1 reading must not gain an alias.
        String aliasTarget = "Ã©";   // "Ã©", the ISO-8859-1 reading of UTF-8 "é"
        String postCutover = BCrypt.hashpw(aliasTarget, BCrypt.gensalt(10));
        check("post_cutover_alias_refused", PasswordUpgrade.verify(PasswordUpgradeTest::verify, "é", postCutover, legacy) == Match.NONE);
        check("post_cutover_alias_would_match_without_snapshot",
            PasswordUpgrade.verify(PasswordUpgradeTest::verify, "é", postCutover, hash -> true) == Match.LEGACY_SERVLET_DECODING);

        // Firebase scrypt imports were hashed by Firebase from real UTF-8 bytes, never by the servlet reader.
        String firebaseLike = "$fbscrypt$v=1$n=14$r=8$p=1$ss=Bw==$sd=YQ==$hash";
        check("non_core_formats_never_legacy_eligible",
            PasswordUpgrade.verify((p, h) -> false, unicode, firebaseLike, hash -> true) == Match.NONE);

        check("legacy_match_always_rehashes", PasswordUpgrade.needsRehash(Match.LEGACY_SERVLET_DECODING, currentBcrypt, BCRYPT_10));
        check("no_match_never_rehashes", !PasswordUpgrade.needsRehash(Match.NONE, firebaseLike, ARGON2_T));
        check("current_bcrypt_same_cost_kept", !PasswordUpgrade.needsRehash(Match.CURRENT, currentBcrypt, BCRYPT_10));
        check("bcrypt_cost_change_rehashes", PasswordUpgrade.needsRehash(Match.CURRENT, currentBcrypt, new Target("BCRYPT", 12, 1, 87795, 2)));
        check("bcrypt_to_argon2_rehashes", PasswordUpgrade.needsRehash(Match.CURRENT, currentBcrypt, ARGON2_T));
        String currentArgon2 = ARGON2.hash(1, 87795, 2, unicode.toCharArray());
        check("current_argon2_same_params_kept", !PasswordUpgrade.needsRehash(Match.CURRENT, currentArgon2, ARGON2_T));
        check("argon2_param_change_rehashes", PasswordUpgrade.needsRehash(Match.CURRENT, currentArgon2, new Target("ARGON2", 10, 2, 87795, 2)));
        check("argon2i_to_argon2id_rehashes", PasswordUpgrade.needsRehash(Match.CURRENT,
            Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i, 16, 32).hash(1, 87795, 2, unicode.toCharArray()), ARGON2_T));
        check("imported_firebase_rehashes_to_configured", PasswordUpgrade.needsRehash(Match.CURRENT, firebaseLike, BCRYPT_10));
        check("firebase_target_never_rehashes", !PasswordUpgrade.needsRehash(Match.CURRENT, currentBcrypt, new Target("FIREBASE_SCRYPT", 10, 1, 87795, 2)));

        check("policy_absent_disabled", !PasswordUpgrade.legacyEnabled(null) && !PasswordUpgrade.legacyEnabled(""));
        check("policy_exact_value_enabled", PasswordUpgrade.legacyEnabled(PasswordUpgrade.LEGACY_VALUE));
        check("policy_unknown_value_fails_closed", throwsType(PasswordUpgrade.Misconfigured.class, () -> PasswordUpgrade.legacyEnabled("true")));
        String id = PasswordUpgrade.hashId(legacyBcrypt);
        check("snapshot_parses_rows", PasswordUpgrade.parseSnapshot(List.of("", id, "  ")).equals(Set.of(id)));
        check("snapshot_rejects_malformed_row", throwsType(PasswordUpgrade.Misconfigured.class, () -> PasswordUpgrade.parseSnapshot(List.of(id.toUpperCase()))));
        check("snapshot_rejects_raw_hash_row", throwsType(PasswordUpgrade.Misconfigured.class, () -> PasswordUpgrade.parseSnapshot(List.of(legacyBcrypt))));
        check("snapshot_rejects_empty", throwsType(PasswordUpgrade.Misconfigured.class, () -> PasswordUpgrade.parseSnapshot(List.of(""))));

        long passed = RESULTS.values().stream().filter(Boolean.TRUE::equals).count();
        StringBuilder out = new StringBuilder("{\"kind\":\"password-upgrade-unit\",\"passed\":").append(passed == RESULTS.size())
            .append(",\"checks\":").append(RESULTS.size()).append(",\"passes\":").append(passed).append(",\"results\":{");
        int i = 0;
        for (var entry : RESULTS.entrySet()) out.append(i++ == 0 ? "" : ",").append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        System.out.println(out.append("}}"));
        System.exit(passed == RESULTS.size() ? 0 : 1);
    }
}
