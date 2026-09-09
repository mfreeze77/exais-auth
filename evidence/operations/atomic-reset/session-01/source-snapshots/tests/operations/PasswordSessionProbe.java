/* Real Core/JDBC races in an owned disposable database. No simulated engine. */
import com.google.gson.*;
import java.nio.file.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class PasswordSessionProbe extends AtomicResetProbe {
    static final String SESSION_POLICY = "EXPERTAUTH-PASSWORD-SESSION-1";
    static Reply passwordSession(String base, String id, String email, String password) throws Exception {
        return post(base, "/expertauth/password/session", obj("userId",id,"email",email,"password",password,
            "enableAntiCsrf",false,"userDataInJWT",obj("owned",true),"userDataInDatabase",obj("owned",true),"useDynamicSigningKey",true));
    }
    static boolean rejected(Reply r) { return r.code()==503 && r.status().equals("PASSWORD_SESSION_REJECTED") && !r.body().has("accessToken"); }
    static int count(String id) throws Exception {
        try (Connection c=db(); PreparedStatement s=c.prepareStatement("SELECT count(*) FROM session_info WHERE app_id='public' AND user_id=?")) {
            s.setString(1,id); try(ResultSet r=s.executeQuery()) {r.next();return r.getInt(1);}
        }
    }
    static int pid(Connection connection) throws Exception {
        try(Statement s=connection.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();return r.getInt(1);}
    }
    static void lockUser(Connection connection,String id) throws Exception {
        connection.setAutoCommit(false);
        try(PreparedStatement s=connection.prepareStatement("SELECT user_id FROM all_auth_recipe_users WHERE app_id='public' AND user_id=? FOR UPDATE")) {
            s.setString(1,id);try(ResultSet r=s.executeQuery()){need(r.next(),"OWNED_IDENTITY_MISSING");}
        }
    }
    static Set<Integer> waiting(Connection observer, int blocker, int previous, String queryPattern, int expected) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(6);
        while(System.nanoTime()<deadline) {
            Set<Integer> found=new HashSet<>();
            try(PreparedStatement s=observer.prepareStatement("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE ? AND (?=ANY(pg_blocking_pids(pid)) OR ?=ANY(pg_blocking_pids(pid)))")) {
                s.setString(1,queryPattern);s.setInt(2,blocker);s.setInt(3,previous);
                try(ResultSet r=s.executeQuery()){while(r.next())found.add(r.getInt(1));}
            }
            need(found.size()<=expected,"AMBIGUOUS_OWNED_WAITERS");
            if(found.size()==expected)return found;
            Thread.sleep(30);
        }
        throw new IllegalStateException("OWNED_OPERATION_DID_NOT_REACH_LOCK");
    }
    static void race(boolean resetFirst) throws Exception {
        String email="session-race-"+UUID.randomUUID()+"@example.test",id=signup(email),token=issue(id,email);
        JsonObject previous=session(id,A);
        ExecutorService pool=Executors.newFixedThreadPool(2);
        try(Connection lock=db();Connection observer=db()) {
            lockUser(lock,id);int blocker=pid(lock);
            Future<Reply> first=pool.submit(()->resetFirst?reset(A,token,NEW):passwordSession(A,id,email,OLD));
            int firstPid=waiting(observer,blocker,blocker,"%all_auth_recipe_users%",1).iterator().next();
            Future<Reply> second=pool.submit(()->resetFirst?passwordSession(B,id,email,OLD):reset(B,token,NEW));
            waiting(observer,blocker,firstPid,"%all_auth_recipe_users%",2);
            lock.commit();
            Reply resetReply=(resetFirst?first:second).get(12,TimeUnit.SECONDS);
            Reply sessionReply=(resetFirst?second:first).get(12,TimeUnit.SECONDS);
            need(resetReply.ok(),"RACED_RESET_DID_NOT_COMMIT");
            if(resetFirst) need(rejected(sessionReply),"PRE_RESET_PASSWORD_CREATED_LATE_SESSION");
            else need(sessionReply.ok()&&!verify(sessionReply.body(),true).ok()&&!refresh(sessionReply.body()).ok(),"EARLIER_SESSION_SURVIVED_RESET");
            need(count(id)==0&&!verify(previous,true).ok()&&!refresh(previous).ok()&&!signin(email,OLD)&&signin(email,NEW),"RACE_LEFT_STALE_AUTHORITY");
            Reply after=passwordSession(B,id,email,NEW);need(after.ok()&&verify(after.body(),true).ok(),"CURRENT_CREDENTIAL_SESSION_DENIED");
            pass(active,"reset_won_lock",resetFirst,"both_requests_observed_waiting",true,"stale_sessions_after_reset",0,"current_password_works",true);
        } finally {pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
    }
    static void abortInsert() throws Exception {
        String email="session-abort-"+UUID.randomUUID()+"@example.test",id=signup(email);
        ExecutorService pool=Executors.newSingleThreadExecutor();
        try(Connection lock=db();Connection observer=db()) {
            lock.setAutoCommit(false);int blocker=pid(lock);
            try(Statement s=lock.createStatement()){s.execute("LOCK TABLE session_info IN SHARE MODE");}
            Future<Reply> pending=pool.submit(()->passwordSession(A,id,email,OLD));
            int victim=waiting(observer,blocker,blocker,"INSERT INTO session_info%",1).iterator().next();
            try(PreparedStatement s=observer.prepareStatement("SELECT pg_terminate_backend(?,2000)")) {
                s.setInt(1,victim);try(ResultSet r=s.executeQuery()){r.next();need(r.getBoolean(1),"INSERT_BACKEND_NOT_TERMINATED");}
            }
            lock.commit();Reply failed=pending.get(12,TimeUnit.SECONDS);
            need(rejected(failed)&&count(id)==0&&signin(email,OLD),"ABORTED_SESSION_INSERT_ESCAPED");
            Reply retried=passwordSession(B,id,email,OLD);need(retried.ok()&&count(id)==1&&verify(retried.body(),true).ok(),"SESSION_RETRY_FAILED");
            pass(active,"backend_terminated_at_insert",true,"sessions_after_abort",0,"same_password_retry_succeeded",true);
        } finally {pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
    }
    public static void main(String[] args) throws Exception {
        need(A!=null&&B!=null&&A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567")&&B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567"),"OWNED_LAB_TARGETS_REQUIRED");
        JsonObject report=obj("kind","actual-password-session-probe","started",Instant.now().toString(),"subset_passed",false,
            "foundation_passed",false,"full_session_qualification",false,"independent_human_review",false,"credential_values_recorded",false);
        int exit=0;
        try {
            ready(A);ready(B);
            active="PASSWORD-SESSION-PRIVATE-CAPABILITY";
            Reply capability=call(A,"GET","/expertauth/password/session",null,"session",true);
            need(capability.ok()&&capability.body().get("policy").getAsString().equals(SESSION_POLICY),"STORAGE_WRITER_NOT_AVAILABLE");
            need(call(B,"GET","/expertauth/password/session",null,"session",false).code()==401,"PRIVATE_CAPABILITY_UNGUARDED");pass(active);
            active="PASSWORD-SESSION-VALID-CREDENTIAL-AND-CLAIMS";
            String email="session-positive-"+UUID.randomUUID()+"@example.test",id=signup(email);
            Reply created=passwordSession(A,id,email.toUpperCase(Locale.ROOT),OLD);
            need(created.ok()&&created.body().get("policy").getAsString().equals(SESSION_POLICY)&&verify(created.body(),true).ok()&&refresh(created.body()).ok(),"SESSION_FLOW_FAILED");
            need(created.body().getAsJsonObject("session").getAsJsonObject("userDataInJWT").get("owned").getAsBoolean(),"JWT_DATA_NOT_PRESERVED");pass(active);
            active="PASSWORD-SESSION-INVALID-CREDENTIAL-AND-SUBSTITUTION";
            need(rejected(passwordSession(A,id,email,NEW))&&rejected(passwordSession(A,id,"other@example.test",OLD))&&rejected(passwordSession(A,id,email,""))&&count(id)==1,"INVALID_CREDENTIAL_MUTATED_SESSION_STATE");pass(active);
            active="PASSWORD-SESSION-RESET-COMMITS-BEFORE-INSERT";race(true);
            active="PASSWORD-SESSION-INSERT-COMMITS-BEFORE-RESET";race(false);
            active="PASSWORD-SESSION-DATABASE-ABORT-AND-RETRY";abortInsert();
            active="PASSWORD-SESSION-EIGHT-CONCURRENT-CREATIONS";
            String raceEmail="session-many-"+UUID.randomUUID()+"@example.test",raceId=signup(raceEmail);
            ExecutorService pool=Executors.newFixedThreadPool(8);CountDownLatch gate=new CountDownLatch(1);
            List<Future<Reply>> futures=new ArrayList<>();Set<String> handles=new HashSet<>();
            try {
                for(int i=0;i<8;i++){final String base=i%2==0?A:B;futures.add(pool.submit(()->{gate.await();return passwordSession(base,raceId,raceEmail,OLD);}));}
                gate.countDown();for(Future<Reply> future:futures){Reply r=future.get(15,TimeUnit.SECONDS);need(r.ok()&&verify(r.body(),true).ok(),"CONCURRENT_LEGITIMATE_SESSION_DENIED");handles.add(r.body().getAsJsonObject("session").get("handle").getAsString());}
                need(handles.size()==8&&count(raceId)==8,"CONCURRENT_SESSION_COUNT_DIFFERED");pass(active,"concurrent_sessions",8);
            } finally {pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
            active="PASSWORD-SESSION-EXTERNAL-ID-MAPPING";
            String mappedEmail="session-mapped-"+UUID.randomUUID()+"@example.test",mappedId=signup(mappedEmail),external="mapped-"+UUID.randomUUID();
            need(post(A,"/recipe/userid/map",obj("superTokensUserId",mappedId,"externalUserId",external,"force",false)).ok(),"MAPPING_CREATION_FAILED");
            Reply mapped=passwordSession(B,external,mappedEmail,OLD);
            need(mapped.ok()&&mapped.body().getAsJsonObject("session").get("userId").getAsString().equals(external)&&count(external)==1&&verify(mapped.body(),true).ok(),"MAPPED_SESSION_DENIED");pass(active);
            report.addProperty("subset_passed",true);
        } catch(Exception error) {
            exit=1;String code=error instanceof IllegalStateException&&error.getMessage()!=null&&error.getMessage().matches("[A-Z0-9_]+")?error.getMessage():error.getClass().getSimpleName();
            ROWS.add(obj("id",active,"status","failed","error",code));
        } finally {
            report.add("rows",GSON.toJsonTree(ROWS));report.add("requests",GSON.toJsonTree(REQUESTS));
            report.add("blocked_qualification",GSON.toJsonTree(List.of("Configured namespace/link/MFA/native/provider profiles remain unqualified","Node/React route integration is a separate proof","Mixed legacy session writers remain outside this explicit password-session API profile","Lost committed responses, audit delivery and independent human review remain unqualified")));
            report.addProperty("finished",Instant.now().toString());Files.writeString(Path.of("/out/password-session-report.json"),GSON.toJson(report)+"\n",StandardOpenOption.CREATE_NEW);
            System.out.println(obj("subset_passed",report.get("subset_passed"),"cases",ROWS.size()));
        }
        System.exit(exit);
    }
}
