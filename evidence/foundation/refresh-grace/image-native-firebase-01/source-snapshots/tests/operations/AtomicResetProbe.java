/* Local, real Core/JDBC integration probe. Synthetic data in a disposable DB only. */
import com.google.gson.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

public class AtomicResetProbe {
    static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    static final String A = System.getenv("RESET_CORE_A"), B = System.getenv("RESET_CORE_B");
    static final String KEY = System.getenv("RESET_CORE_API_KEY");
    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    static final List<JsonObject> ROWS = new ArrayList<>();
    static final List<JsonObject> REQUESTS = Collections.synchronizedList(new ArrayList<>());
    static final String POLICY = "EXPERTAUTH-ATOMIC-RESET-1";
    static final String OLD = "Old-" + UUID.randomUUID(), NEW = "New-" + UUID.randomUUID();
    static String active = "initialization";
    record Reply(int code, JsonObject body) {
        String status() { return body.has("status") ? body.get("status").getAsString() : "NON_JSON_OR_NO_STATUS"; }
        boolean ok() { return code == 200 && status().equals("OK"); }
    }
    static JsonObject obj(Object... values) {
        JsonObject result = new JsonObject();
        for (int i = 0; i < values.length; i += 2) result.add((String) values[i], GSON.toJsonTree(values[i + 1]));
        return result;
    }
    static void need(boolean value, String code) {
        if (!value) throw new IllegalStateException(code);
    }
    static Reply call(String base, String method, String path, JsonObject body, String recipe, boolean authorized) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path)).timeout(Duration.ofSeconds(15))
            .header("cdi-version", "5.4").header("rid", recipe);
        if (authorized) builder.header("api-key", KEY);
        if (body != null) builder.header("Content-Type", "application/json");
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body.toString()));
        long start = System.nanoTime();
        HttpResponse<String> response = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        JsonObject parsed;
        try { parsed = JsonParser.parseString(response.body()).getAsJsonObject(); }
        catch (RuntimeException invalid) { parsed = new JsonObject(); }
        Reply reply = new Reply(response.statusCode(), parsed);
        REQUESTS.add(obj("method", method, "path", path, "replica", base.equals(A) ? "a" : "b", "http", reply.code,
            "status", reply.status(), "elapsed_ms", (System.nanoTime() - start) / 1_000_000, "credential_bodies_recorded", false));
        return reply;
    }
    static Reply post(String base, String path, JsonObject body) throws Exception {
        return call(base, "POST", path, body, path.contains("/session") ? "session" : "emailpassword", true);
    }
    static void pass(String id, Object... detail) {
        JsonObject row = obj(detail); row.addProperty("id", id); row.addProperty("status", "passed"); ROWS.add(row);
        System.out.println(obj("case", id, "status", "passed"));
    }
    static void ready(String base) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(35);
        while (System.nanoTime() < deadline) {
            try {
                Reply r = call(base, "GET", "/users/count", null, "session", true);
                if (r.ok() && r.body.has("count")) return;
            } catch (Exception unavailable) { /* bounded startup polling only */ }
            Thread.sleep(300);
        }
        throw new IllegalStateException("AUTHENTICATED_STORAGE_READINESS_TIMEOUT");
    }
    static String signup(String email) throws Exception {
        Reply r = post(A, "/recipe/signup", obj("email", email, "password", OLD)); need(r.ok(), "SIGNUP_FAILED");
        return r.body.getAsJsonObject("user").get("id").getAsString();
    }
    static JsonObject session(String id, String base) throws Exception {
        Reply r = post(base, "/recipe/session", obj("userId", id, "enableAntiCsrf", false,
            "userDataInJWT", obj(), "userDataInDatabase", obj(), "useDynamicSigningKey", true));
        need(r.ok(), "SESSION_CREATION_FAILED"); return r.body;
    }
    static String issue(String id, String email) throws Exception {
        Reply r = post(A, "/expertauth/password/reset/token", obj("userId", id, "email", email));
        need(r.ok() && r.body.get("policy").getAsString().equals(POLICY), "TOKEN_ISSUE_FAILED");
        return r.body.get("token").getAsString();
    }
    static Reply reset(String base, String token, String password) throws Exception {
        return post(base, "/expertauth/password/reset", obj("token", token, "newPassword", password));
    }
    static Reply verify(JsonObject session, boolean online) throws Exception {
        return post(B, "/recipe/session/verify", obj("accessToken", session.getAsJsonObject("accessToken").get("token").getAsString(),
            "enableAntiCsrf", false, "doAntiCsrfCheck", false, "checkDatabase", online));
    }
    static Reply refresh(JsonObject session) throws Exception {
        return post(B, "/recipe/session/refresh", obj("refreshToken", session.getAsJsonObject("refreshToken").get("token").getAsString(),
            "enableAntiCsrf", false, "useDynamicSigningKey", true));
    }
    static boolean signin(String email, String password) throws Exception {
        return post(B, "/recipe/signin", obj("email", email, "password", password)).ok();
    }
    static Connection db() throws Exception {
        Properties p = new Properties(); p.setProperty("user", "expertauth_reset");
        p.setProperty("password", System.getenv("RESET_DATABASE_PASSWORD"));
        p.setProperty("connectTimeout", "3"); p.setProperty("socketTimeout", "10");
        return DriverManager.getConnection(System.getenv("RESET_JDBC_URL"), p);
    }
    static void transactionFailure(String id, String email) throws Exception {
        JsonObject session = session(id, A); String token = issue(id, email);
        String handle = session.getAsJsonObject("session").get("handle").getAsString();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (Connection locker = db(); Connection observer = db()) {
            locker.setAutoCommit(false);
            int blocker;
            try (Statement s = locker.createStatement(); ResultSet r = s.executeQuery("SELECT pg_backend_pid()")) { r.next(); blocker = r.getInt(1); }
            try (PreparedStatement s = locker.prepareStatement("SELECT session_handle FROM session_info WHERE session_handle = ? FOR UPDATE")) {
                s.setString(1, handle); try (ResultSet r = s.executeQuery()) { need(r.next(), "OWNED_SESSION_ROW_MISSING"); }
            }
            Future<Reply> pending = executor.submit(() -> reset(A, token, NEW));
            Integer victim = null;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (System.nanoTime() < deadline && victim == null) {
                try (PreparedStatement s = observer.prepareStatement("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'DELETE FROM session_info%' AND ? = ANY(pg_blocking_pids(pid))")) {
                    s.setInt(1, blocker); try (ResultSet r = s.executeQuery()) {
                        if (r.next()) { victim = r.getInt(1); need(!r.next(), "AMBIGUOUS_OWNED_BLOCKED_TRANSACTION"); }
                    }
                }
                if (victim == null) Thread.sleep(40);
            }
            need(victim != null, "RESET_DID_NOT_REACH_SESSION_DELETE_LOCK");
            // The blocked reset has executed its password update and token deletion,
            // but neither is committed. Terminate only this identified owned backend.
            try (PreparedStatement s = observer.prepareStatement("SELECT pg_terminate_backend(?, 2000)")) {
                s.setInt(1, victim); try (ResultSet r = s.executeQuery()) { r.next(); need(r.getBoolean(1), "OWNED_BACKEND_NOT_TERMINATED"); }
            }
            locker.rollback();
            Reply failed = pending.get(10, TimeUnit.SECONDS);
            need(failed.code == 500 && failed.status().equals("ATOMIC_RESET_OPERATION_FAILED"), "DATABASE_ABORT_RESPONSE_DIFFERED");
            need(signin(email, OLD) && !signin(email, NEW) && verify(session, true).ok() && refresh(session).ok(), "PARTIAL_RESET_ESCAPED_ROLLBACK");
            need(reset(B, token, NEW).ok(), "ROLLED_BACK_TOKEN_NOT_REUSABLE");
            need(signin(email, NEW) && !verify(session, true).ok() && !refresh(session).ok(), "RESET_RETRY_DID_NOT_COMMIT_ALL_CHANGES");
            pass(active, "blocked_at_session_delete", true, "identified_backend_terminated", true,
                "old_password_and_sessions_preserved_after_abort", true, "same_token_retry_succeeded", true);
        } finally { executor.shutdownNow(); executor.awaitTermination(3, TimeUnit.SECONDS); }
    }
    public static void main(String[] args) throws Exception {
        need(A != null && B != null && KEY != null && A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567") &&
             B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567"), "OWNED_LAB_TARGETS_REQUIRED");
        if (args.length == 1 && args[0].equals("--ready-a")) { ready(A); System.out.println("{\"ready\":true}"); return; }
        JsonObject report = obj("kind", "actual-atomic-reset-core-probe", "started", Instant.now().toString(),
            "subset_passed", false, "full_PWD_006_qualified", false, "foundation_passed", false,
            "independent_human_review", false, "credential_values_recorded", false);
        int exit = 0;
        try {
            ready(A); ready(B);
            active = "ATOMIC-RESET-PRIVATE-API-AUTHORIZATION";
            Reply unauthorized = call(A, "POST", "/expertauth/password/reset", obj("token", "invalid", "newPassword", NEW), "emailpassword", false);
            need(unauthorized.code == 401, "PRIVATE_ENDPOINT_ACCEPTED_MISSING_API_KEY"); pass(active);
            String suffix = UUID.randomUUID().toString(), email = "reset-" + suffix + "@example.test", otherEmail = "other-" + suffix + "@example.test";
            String id = signup(email), otherId = signup(otherEmail);
            JsonObject first = session(id, A), second = session(id, B), other = session(otherId, B);
            String token = issue(id, email), sibling = issue(id, email);
            active = "ATOMIC-RESET-INPUT-AND-CONTEXT-REJECTION";
            need(!reset(A, token, "").ok() && !reset(A, token, "x".repeat(4097)).ok(), "INVALID_PASSWORD_ACCEPTED");
            String tampered = token.substring(0, 5) + (token.charAt(5) == 'a' ? 'b' : 'a') + token.substring(6);
            need(!reset(B, tampered, NEW).ok() && !reset(B, "legacy-invalid-token", NEW).ok() && signin(email, OLD), "INVALID_TOKEN_CHANGED_PASSWORD");
            pass(active, "valid_token_retained_for_next_case", true);
            active = "ATOMIC-RESET-COMMIT-REVOKES-EXISTING-SESSIONS";
            Reply success = reset(B, token, NEW);
            need(success.ok() && success.body.get("policy").getAsString().equals(POLICY), "ATOMIC_RESET_FAILED");
            need(!signin(email, OLD) && signin(email, NEW), "PASSWORD_NOT_REPLACED");
            need(!verify(first, true).ok() && !verify(second, true).ok() && !refresh(first).ok() && !refresh(second).ok(), "EXISTING_SESSION_SURVIVED");
            need(verify(other, true).ok() && refresh(other).ok() && signin(otherEmail, OLD), "UNRELATED_IDENTITY_CHANGED");
            pass(active, "owned_sessions_revoked", 2, "unrelated_identity_preserved", true);
            active = "ATOMIC-RESET-REPLAY-AND-SIBLING-DENIAL";
            need(!reset(A, token, OLD).ok() && !reset(A, sibling, OLD).ok() && signin(email, NEW), "CONSUMED_OR_SIBLING_TOKEN_ACCEPTED"); pass(active);
            active = "ATOMIC-RESET-EIGHT-CONSUMERS-TWO-REPLICAS";
            String raced = issue(id, email); ExecutorService pool = Executors.newFixedThreadPool(8);
            CountDownLatch gate = new CountDownLatch(1); List<Future<Reply>> replies = new ArrayList<>();
            List<String> passwords = new ArrayList<>();
            try {
                for (int i = 0; i < 8; i++) {
                    final int index = i; String password = "Race-" + UUID.randomUUID(); passwords.add(password);
                    replies.add(pool.submit(() -> { gate.await(); return reset(index % 2 == 0 ? A : B, raced, password); }));
                }
                gate.countDown(); int winners = 0, winning = -1;
                for (int i = 0; i < replies.size(); i++) { Reply r = replies.get(i).get(15, TimeUnit.SECONDS); if (r.ok()) { winners++; winning = i; }
                    else need(r.code == 200 && r.status().equals("RESET_PASSWORD_INVALID_TOKEN_ERROR"), "UNEXPECTED_RACE_FAILURE"); }
                need(winners == 1 && signin(email, passwords.get(winning)), "RACE_NOT_SINGLE_COMMITTED_WINNER");
                for (int i = 0; i < 8; i++) if (i != winning) need(!signin(email, passwords.get(i)), "LOSING_PASSWORD_ACCEPTED");
                pass(active, "consumers", 8, "committed_winners", winners);
            } finally { pool.shutdownNow(); pool.awaitTermination(3, TimeUnit.SECONDS); }
            active = "ATOMIC-RESET-TRANSACTION-ABORT-AND-RETRY";
            String faultEmail = "fault-" + suffix + "@example.test", faultId = signup(faultEmail); transactionFailure(faultId, faultEmail);
            active = "ATOMIC-RESET-EXTERNAL-ID-SESSION-REVOCATION";
            String mappedEmail = "mapped-" + suffix + "@example.test", mappedId = signup(mappedEmail), external = "external-" + UUID.randomUUID();
            need(post(A, "/recipe/userid/map", obj("superTokensUserId", mappedId, "externalUserId", external, "force", false)).ok(), "USER_ID_MAPPING_FAILED");
            JsonObject mappedSession = session(external, A);
            Reply mappedReset = reset(B, issue(external, mappedEmail), NEW);
            need(mappedReset.ok() && mappedReset.body.get("userId").getAsString().equals(external) &&
                !verify(mappedSession, true).ok() && !refresh(mappedSession).ok() && signin(mappedEmail, NEW), "MAPPED_SESSION_NOT_REVOKED"); pass(active);
            active = "ATOMIC-RESET-CONFIGURED-EXPIRY";
            String expired = issue(id, email); Thread.sleep(6500);
            need(!reset(B, expired, OLD).ok(), "EXPIRED_TOKEN_ACCEPTED"); pass(active, "configured_lifetime_ms", 6000, "wait_ms", 6500);
            report.addProperty("subset_passed", true);
        } catch (Exception error) {
            exit = 1;
            String code = error instanceof IllegalStateException && error.getMessage() != null && error.getMessage().matches("[A-Z0-9_]+")
                ? error.getMessage() : error.getClass().getSimpleName();
            ROWS.add(obj("id", active, "status", "failed", "error", code));
        } finally {
            report.add("rows", GSON.toJsonTree(ROWS)); report.add("requests", GSON.toJsonTree(REQUESTS));
            report.add("blocked_qualification", GSON.toJsonTree(List.of("Two configured tenant/application namespaces and linked-account cases require a capable unrestricted foundation",
                "Sign-in authenticated before reset but issuing a session afterward remains a separate unresolved race",
                "Node/React atomic-profile integration, live-provider/native and independent human review not covered by this Core probe")));
            report.addProperty("finished", Instant.now().toString());
            Files.writeString(Path.of("/out/probe-report.json"), GSON.toJson(report) + "\n", StandardOpenOption.CREATE_NEW);
            System.out.println(obj("subset_passed", report.get("subset_passed"), "cases_executed", ROWS.size()));
        }
        System.exit(exit);
    }
}
