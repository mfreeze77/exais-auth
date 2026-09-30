/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
import de.mkammerer.argon2.Argon2Factory;
import io.expertauth.core.PasswordUpgrade;
import io.expertauth.core.PasswordUpgrade.Target;
import java.util.*;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Rehash-decision checks for PasswordUpgrade with the same bcrypt/argon2 libraries Core uses.
 * Run: java -cp <classes>:<jbcrypt>:<argon2-jvm>:<jna>:<core>:<plugin-interface> PasswordUpgradeTest
 */
public final class PasswordUpgradeTest {
    private static final Map<String, Object> RESULTS = new LinkedHashMap<>();
    private static final Target BCRYPT_10 = new Target("BCRYPT", 10, 1, 87795, 2);
    private static final Target ARGON2_T = new Target("ARGON2", 10, 1, 87795, 2);

    private static void check(String name, boolean passed) {
        RESULTS.put(name, passed);
        if (!passed) System.err.println("FAILED " + name);
    }

    public static void main(String[] args) {
        String unicode = "pässwörd-密码-🔑";
        String bcrypt10 = BCrypt.hashpw(unicode, BCrypt.gensalt(10));
        String argon2id = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 16, 32).hash(1, 87795, 2, unicode.toCharArray());
        String argon2i = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i, 16, 32).hash(1, 87795, 2, unicode.toCharArray());
        String firebase = "$f_scrypt$aGFzaA==$c2FsdA==$m=14$r=8$s=Bw==";

        check("bcrypt_same_cost_kept", !PasswordUpgrade.needsRehash(bcrypt10, BCRYPT_10));
        check("bcrypt_2y_same_cost_kept", !PasswordUpgrade.needsRehash("$2y" + bcrypt10.substring(3), BCRYPT_10));
        check("bcrypt_cost_change_rehashes", PasswordUpgrade.needsRehash(bcrypt10, new Target("BCRYPT", 12, 1, 87795, 2)));
        check("bcrypt_to_argon2_rehashes", PasswordUpgrade.needsRehash(bcrypt10, ARGON2_T));
        check("argon2_to_bcrypt_rehashes", PasswordUpgrade.needsRehash(argon2id, BCRYPT_10));
        check("argon2id_same_params_kept", !PasswordUpgrade.needsRehash(argon2id, ARGON2_T));
        check("argon2_memory_change_rehashes", PasswordUpgrade.needsRehash(argon2id, new Target("ARGON2", 10, 1, 65536, 2)));
        check("argon2_iteration_change_rehashes", PasswordUpgrade.needsRehash(argon2id, new Target("ARGON2", 10, 2, 87795, 2)));
        check("argon2_parallelism_change_rehashes", PasswordUpgrade.needsRehash(argon2id, new Target("ARGON2", 10, 1, 87795, 1)));
        check("argon2i_to_argon2id_rehashes", PasswordUpgrade.needsRehash(argon2i, ARGON2_T));
        check("firebase_import_to_bcrypt_rehashes", PasswordUpgrade.needsRehash(firebase, BCRYPT_10));
        check("firebase_import_to_argon2_rehashes", PasswordUpgrade.needsRehash(firebase, ARGON2_T));
        check("firebase_target_never_rehashes", !PasswordUpgrade.needsRehash(bcrypt10, new Target("FIREBASE_SCRYPT", 10, 1, 87795, 2)));
        check("truncated_bcrypt_rehashes", PasswordUpgrade.needsRehash(bcrypt10.substring(0, 40), BCRYPT_10));
        check("argon2_other_version_rehashes", PasswordUpgrade.needsRehash(argon2id.replace("$v=19$", "$v=16$"), ARGON2_T));
        // Import structure and cost bounds.
        String argon2d = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2d, 16, 32).hash(1, 87795, 2, unicode.toCharArray());
        check("valid_bcrypt_structure", PasswordUpgrade.structurallyValid(bcrypt10) && PasswordUpgrade.structurallyValid("$2y" + bcrypt10.substring(3)));
        check("valid_argon2_variants_structure", PasswordUpgrade.structurallyValid(argon2id) && PasswordUpgrade.structurallyValid(argon2i) && PasswordUpgrade.structurallyValid(argon2d));
        check("valid_firebase_structure", PasswordUpgrade.structurallyValid(firebase));
        check("truncated_bcrypt_refused", !PasswordUpgrade.structurallyValid("$2a$10$short") && !PasswordUpgrade.structurallyValid(bcrypt10.substring(0, 59)));
        check("bcrypt_bad_alphabet_refused", !PasswordUpgrade.structurallyValid(bcrypt10.substring(0, 59) + "!"));
        check("bcrypt_cost_bounds", !PasswordUpgrade.structurallyValid("$2a$03" + bcrypt10.substring(6)) && !PasswordUpgrade.structurallyValid("$2a$17" + bcrypt10.substring(6))
            && PasswordUpgrade.structurallyValid("$2a$16" + bcrypt10.substring(6)));
        check("argon2_garbage_refused", !PasswordUpgrade.structurallyValid("$argon2id$garbage"));
        check("argon2_memory_bound", !PasswordUpgrade.structurallyValid(argon2id.replace("m=87795", "m=4194304")) && PasswordUpgrade.structurallyValid(argon2id.replace("m=87795", "m=1048576")));
        check("argon2_zero_and_huge_iterations_refused", !PasswordUpgrade.structurallyValid(argon2id.replace("t=1,", "t=0,")) && !PasswordUpgrade.structurallyValid(argon2id.replace("t=1,", "t=101,")));
        check("argon2_memory_below_8p_refused", !PasswordUpgrade.structurallyValid(argon2id.replace("m=87795", "m=15")));
        check("argon2_unknown_version_refused", !PasswordUpgrade.structurallyValid(argon2id.replace("$v=19$", "$v=20$")));
        check("firebase_bad_base64_refused", !PasswordUpgrade.structurallyValid("$f_scrypt$aGFz*A==$c2FsdA==$m=14$r=8$s=Bw=="));
        check("firebase_cost_bounds", !PasswordUpgrade.structurallyValid(firebase.replace("$m=14$", "$m=18$")) && !PasswordUpgrade.structurallyValid(firebase.replace("$r=8$", "$r=0$")));
        check("unknown_formats_left_to_core", PasswordUpgrade.structurallyValid("5f4dcc3b5aa765d61d8327deb882cf99"));
        // The verifier sees only the UTF-8 decoded password; its historical Latin-1 reading is a different secret.
        String latin1Reading = new String(unicode.getBytes(java.nio.charset.StandardCharsets.UTF_8), java.nio.charset.StandardCharsets.ISO_8859_1);
        check("utf8_password_verifies", BCrypt.checkpw(unicode, bcrypt10));
        check("latin1_reading_is_not_accepted", !BCrypt.checkpw(latin1Reading, bcrypt10));

        long passed = RESULTS.values().stream().filter(Boolean.TRUE::equals).count();
        StringBuilder out = new StringBuilder("{\"kind\":\"password-upgrade-unit\",\"policy\":\"").append(PasswordUpgrade.POLICY)
            .append("\",\"passed\":").append(passed == RESULTS.size())
            .append(",\"checks\":").append(RESULTS.size()).append(",\"passes\":").append(passed).append(",\"results\":{");
        int i = 0;
        for (var entry : RESULTS.entrySet()) out.append(i++ == 0 ? "" : ",").append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        System.out.println(out.append("}}"));
        System.exit(passed == RESULTS.size() ? 0 : 1);
    }
}
