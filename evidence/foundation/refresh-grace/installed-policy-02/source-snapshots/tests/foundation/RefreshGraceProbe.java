/* Actual Core HTTP/JDBC policy characterization. Disposable test database only. */
import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

public class RefreshGraceProbe extends AtomicResetProbe {
    static String user;
    static final long GRACE_MS = 5000;
    static final long BARRIER = 765432101;
    static String hash(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    static String refreshToken(JsonObject session) { return session.getAsJsonObject("refreshToken").get("token").getAsString(); }
    static String handle(JsonObject session) { return session.getAsJsonObject("session").get("handle").getAsString(); }
    static String verifier(JsonObject session) throws Exception { return hash(hash(refreshToken(session))); }
    static Reply request(String base, String method, String path, JsonObject body, String version, boolean authorized) throws Exception {
        HttpRequest.Builder builder=HttpRequest.newBuilder(URI.create(base+path)).timeout(Duration.ofSeconds(15))
            .header("cdi-version",version).header("rid",path.equals("/recipe/signup")?"emailpassword":"session");
        if(authorized) builder.header("api-key",KEY);
        if(body!=null) builder.header("content-type","application/json");
        builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body.toString()));
        HttpResponse<String> response=HTTP.send(builder.build(),HttpResponse.BodyHandlers.ofString());
        JsonObject parsed;
        try { parsed=JsonParser.parseString(response.body()).getAsJsonObject(); } catch(RuntimeException e) { parsed=new JsonObject(); }
        Reply reply=new Reply(response.statusCode(),parsed);
        REQUESTS.add(obj("case",active,"replica",base.equals(A)?"a":"b","method",method,"path",path,
            "cdi",version,"http",reply.code(),"status",reply.status(),"credential_bodies_recorded",false));
        return reply;
    }
    static Reply refreshAt(String base, JsonObject session, String cdi) throws Exception {
        return request(base,"POST","/recipe/session/refresh",obj("refreshToken",refreshToken(session),"enableAntiCsrf",false,"useDynamicSigningKey",true),cdi,true);
    }
    static JsonObject create(String cdi) throws Exception {
        Reply r=request(A,"POST","/recipe/session",obj("userId",user,"enableAntiCsrf",false,"useDynamicSigningKey",true,
            "userDataInJWT",obj(),"userDataInDatabase",obj()),cdi,true);
        need(r.ok(),"SESSION_CREATION_FAILED"); return r.body();
    }
    static Reply online(String base,JsonObject session) throws Exception {
        return request(base,"POST","/recipe/session/verify",obj("accessToken",session.getAsJsonObject("accessToken").get("token").getAsString(),
            "enableAntiCsrf",false,"doAntiCsrfCheck",false,"checkDatabase",true),"5.6",true);
    }
    record State(String current,String previous,Long rotated,long expiry) {}
    static State state(JsonObject session) throws Exception {
        try(Connection c=db();PreparedStatement s=c.prepareStatement("SELECT refresh_token_hash_2,prev_refresh_token_hash_2,refresh_token_rotated_at,expires_at FROM session_info WHERE app_id='public' AND session_handle=?")) {
            s.setString(1,handle(session));try(ResultSet r=s.executeQuery()) {
                if(!r.next())return null;
                State v=new State(r.getString(1),r.getString(2),(Long)r.getObject(3),r.getLong(4));need(!r.next(),"DUPLICATE_SESSION_ROW");return v;
            }
        }
    }
    static void deniedFamily(JsonObject root,JsonObject child,JsonObject other) throws Exception {
        need(state(root)==null&&!online(A,child).ok()&&!online(B,child).ok()&&!refreshAt(B,child,"5.6").ok(),"REVOKED_FAMILY_SURVIVED");
        need(online(B,other).ok()&&refreshAt(A,other,"5.6").ok(),"UNRELATED_FAMILY_REVOKED");
    }
    static void reuse(String kind) throws Exception {
        JsonObject root=create("5.6"),other=create("5.6");
        Reply one=refreshAt(A,root,"5.6");need(one.ok(),"FIRST_ROTATION_FAILED");
        JsonObject submitted=root,child=one.body();
        if(kind.equals("ORPHANED_BRANCH")) {
            Reply two=refreshAt(B,root,"5.6");need(two.ok(),"GRACE_RETRY_FAILED");submitted=child;child=two.body();
        } else if(kind.equals("STALE_LINEAGE")) {
            Reply two=refreshAt(B,child,"5.6");need(two.ok(),"DESCENDANT_ROTATION_FAILED");child=two.body();
        } else {
            State committed=state(root);long until=committed.rotated()+GRACE_MS+120;
            while(System.currentTimeMillis()<until) Thread.sleep(Math.min(200,until-System.currentTimeMillis()));
        }
        Reply replay=refreshAt(B,submitted,"5.6");
        need(replay.status().equals("TOKEN_THEFT_DETECTED")&&replay.body().get("recentTokenReuseSubtype").getAsString().equals(kind),"REUSE_CLASSIFICATION_DIFFERED");
        deniedFamily(root,child,other);pass(active,"subtype",kind,"server_side_family_revocation",true,"other_family_preserved",true);
    }
    static void rotation() throws Exception {
        JsonObject root=create("5.6");State before=state(root);
        Reply r=refreshAt(A,root,"5.6");need(r.ok(),"ROTATION_FAILED");State after=state(root);
        need(after.current().equals(verifier(r.body()))&&after.previous().equals(verifier(root))&&!after.current().equals(before.current())&&after.rotated()!=null,"ROTATION_NOT_COMMITTED_AT_REFRESH");
        need(online(B,r.body()).ok(),"COMMITTED_SUCCESSOR_NOT_USABLE");pass(active,"committed_before_first_verify",true);
    }
    static void retries() throws Exception {
        JsonObject root=create("5.6");Reply first=refreshAt(A,root,"5.6");need(first.ok(),"FIRST_ROTATION_FAILED");State initial=state(root);
        for(int i=0;i<3;i++) {
            Reply retry=refreshAt(i%2==0?B:A,root,"5.6");need(retry.ok(),"PARENT_RETRY_FAILED");State current=state(root);
            need(current.previous().equals(initial.previous())&&current.rotated().equals(initial.rotated())&&current.expiry()==initial.expiry()&&current.current().equals(verifier(retry.body())),"RETRY_EXTENDED_WINDOW_OR_FAILED_REPLACEMENT");
            need(online(B,retry.body()).ok(),"RETRY_SUCCESSOR_UNUSABLE");
        }
        need(!online(A,first.body()).ok(),"DISPLACED_ACCESS_TOKEN_ACCEPTED_ONLINE");
        pass(active,"retries",3,"window_and_expiry_unchanged",true);
    }
    static void concurrent() throws Exception {
        JsonObject root=create("5.6");ExecutorService pool=Executors.newFixedThreadPool(8);CountDownLatch gate=new CountDownLatch(1);
        List<Future<Reply>> pending=new ArrayList<>();List<JsonObject> children=new ArrayList<>();
        try {
            for(int i=0;i<8;i++){final String base=i%2==0?A:B;pending.add(pool.submit(()->{gate.await();return refreshAt(base,root,"5.6");}));}
            gate.countDown();for(Future<Reply> f:pending){Reply r=f.get(15,TimeUnit.SECONDS);need(r.ok(),"SAME_PARENT_RACE_REJECTED_WITHIN_WINDOW");children.add(r.body());}
            State settled=state(root);int winners=0;JsonObject selected=null;
            for(JsonObject child:children){boolean current=verifier(child).equals(settled.current());need(online(B,child).ok()==current,"ONLINE_BRANCH_DID_NOT_MATCH_AUTHORITY");if(current){winners++;selected=child;}}
            need(winners==1&&refreshAt(A,selected,"5.6").ok(),"RACE_LEFT_ZERO_OR_MULTIPLE_CURRENT_SUCCESSORS");
            pass(active,"requests",8,"successful_responses",8,"authoritative_current_successors",1,"sdk_credential_coordination_tested",false);
        } finally {pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
    }
    static void abortAfterUpdate() throws Exception {
        JsonObject root=create("5.6");State before=state(root);String h=handle(root);need(h.matches("[a-zA-Z0-9_-]{1,100}"),"UNEXPECTED_OWNED_HANDLE_FORMAT");
        ExecutorService pool=Executors.newSingleThreadExecutor();boolean trigger=false;
        try(Connection locker=db();Connection observer=db()) {
            try(Statement s=observer.createStatement()) {
                s.execute("CREATE FUNCTION expertauth_refresh_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.session_handle = TG_ARGV[0] THEN PERFORM pg_advisory_xact_lock("+BARRIER+"); END IF; RETURN NEW; END $$");
                s.execute("CREATE TRIGGER expertauth_refresh_barrier AFTER UPDATE OF refresh_token_hash_2 ON session_info FOR EACH ROW EXECUTE FUNCTION expertauth_refresh_barrier('"+h+"')");trigger=true;
            }
            int blocker;
            try(Statement s=locker.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid(),pg_advisory_lock("+BARRIER+")")){r.next();blocker=r.getInt(1);}
            Future<Reply> pending=pool.submit(()->refreshAt(A,root,"5.6"));Integer victim=null;long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(7);
            while(victim==null&&System.nanoTime()<deadline) {
                try(PreparedStatement s=observer.prepareStatement("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE session_info%' AND ?=ANY(pg_blocking_pids(pid))")) {
                    s.setInt(1,blocker);try(ResultSet r=s.executeQuery()){if(r.next()){victim=r.getInt(1);need(!r.next(),"AMBIGUOUS_OWNED_UPDATE_BACKEND");}}
                }
                if(victim==null)Thread.sleep(30);
            }
            need(victim!=null&&before.equals(state(root)),"AFTER_UPDATE_BARRIER_NOT_OBSERVED");
            try(PreparedStatement s=observer.prepareStatement("SELECT pg_terminate_backend(?,2000)")){s.setInt(1,victim);try(ResultSet r=s.executeQuery()){r.next();need(r.getBoolean(1),"OWNED_BACKEND_NOT_TERMINATED");}}
            Reply failed=pending.get(12,TimeUnit.SECONDS);need(failed.code()==500&&before.equals(state(root)),"UNCOMMITTED_ROTATION_ESCAPED_ABORT");
            try(Statement s=observer.createStatement()){s.execute("DROP TRIGGER expertauth_refresh_barrier ON session_info");s.execute("DROP FUNCTION expertauth_refresh_barrier()");trigger=false;}
            Reply retry=refreshAt(B,root,"5.6");need(retry.ok()&&online(A,retry.body()).ok(),"ROLLED_BACK_CREDENTIAL_NOT_RETRYABLE");
            pass(active,"fault","identified_database_backend_terminated_in_after_update_trigger","all_rotation_columns_rolled_back",true,"same_token_retry_succeeded",true);
        } finally {
            pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);
            if(trigger)try(Connection c=db();Statement s=c.createStatement()){s.execute("DROP TRIGGER IF EXISTS expertauth_refresh_barrier ON session_info");s.execute("DROP FUNCTION IF EXISTS expertauth_refresh_barrier()");}
        }
    }
    static void lostResponse(boolean partial,boolean logout) throws Exception {
        JsonObject root=create("5.6");State before=state(root);String body=obj("refreshToken",refreshToken(root),"enableAntiCsrf",false,"useDynamicSigningKey",true).toString();
        CompletableFuture<Reply> committed=new CompletableFuture<>();CountDownLatch release=new CountDownLatch(logout?1:0);
        ExecutorService serverThreads=Executors.newSingleThreadExecutor(),clientThreads=Executors.newSingleThreadExecutor();
        HttpServer proxy=HttpServer.create(new InetSocketAddress("127.0.0.1",0),1);proxy.setExecutor(serverThreads);
        proxy.createContext("/refresh",exchange->{
            try {
                byte[] incoming=exchange.getRequestBody().readNBytes(16384);
                need(new String(incoming,StandardCharsets.UTF_8).equals(body),"FAULT_PROXY_REQUEST_CHANGED");
                Reply upstream=request(A,"POST","/recipe/session/refresh",JsonParser.parseString(body).getAsJsonObject(),"5.6",true);
                committed.complete(upstream);need(release.await(8,TimeUnit.SECONDS),"FAULT_PROXY_RELEASE_TIMEOUT");
                byte[] bytes=upstream.body().toString().getBytes(StandardCharsets.UTF_8);
                if(partial||logout){exchange.sendResponseHeaders(upstream.code(),bytes.length);exchange.getResponseBody().write(bytes,0,logout?bytes.length:8);exchange.getResponseBody().flush();}
            } catch(Exception error){committed.completeExceptionally(error);} finally {exchange.close();}
        });proxy.start();int port=proxy.getAddress().getPort();
        try {
            Future<byte[]> received=clientThreads.submit(()->{
                try(Socket socket=new Socket("127.0.0.1",port)) {
                    socket.setSoTimeout(12000);byte[] payload=body.getBytes(StandardCharsets.UTF_8);
                    socket.getOutputStream().write(("POST /refresh HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "+payload.length+"\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().write(payload);socket.getOutputStream().flush();return socket.getInputStream().readNBytes(65536);
                }
            });
            Reply original=committed.get(12,TimeUnit.SECONDS);need(original.ok(),"FAULTED_UPSTREAM_REFRESH_FAILED");State after=state(root);
            need(!after.current().equals(before.current())&&after.current().equals(verifier(original.body())),"FAULT_NOT_AFTER_COMMITTED_ROTATION");
            if(logout){Reply deleted=request(B,"POST","/recipe/session/remove",obj("sessionHandles",new String[]{handle(root)}),"5.6",true);need(deleted.ok()&&state(root)==null,"LOGOUT_NOT_COMMITTED_BEFORE_RESPONSE");release.countDown();}
            byte[] raw=received.get(12,TimeUnit.SECONDS);String wire=new String(raw,StandardCharsets.UTF_8);
            if(logout) {
                int end=wire.indexOf("\r\n\r\n");need(end>0,"LATE_RESPONSE_HEADERS_MISSING");JsonObject delivered=JsonParser.parseString(wire.substring(end+4)).getAsJsonObject();
                need(refreshToken(delivered).equals(refreshToken(original.body()))&&!online(A,delivered).ok()&&!refreshAt(B,delivered,"5.6").ok(),"LATE_RESPONSE_RESURRECTED_SESSION");
                pass(active,"committed_response_delivered_after_logout",true,"server_side_resurrection",false,"sdk_token_installation_tested",false);
            } else {
                if(partial){int end=wire.indexOf("\r\n\r\n");need(end>0&&wire.substring(end+4).getBytes(StandardCharsets.UTF_8).length==8,"PARTIAL_RESPONSE_NOT_EIGHT_BYTES");}
                else need(raw.length==0,"LOST_RESPONSE_SENT_DOWNSTREAM_BYTES");
                Reply retry=refreshAt(B,root,"5.6");need(retry.ok()&&online(B,retry.body()).ok()&&!online(A,original.body()).ok(),"LOST_RESPONSE_RETRY_FAILED_TO_REPLACE_BRANCH");
                State settled=state(root);need(settled.rotated().equals(after.rotated())&&settled.previous().equals(after.previous())&&settled.expiry()==after.expiry(),"LOST_RESPONSE_RETRY_EXTENDED_WINDOW");
                pass(active,"real_upstream_responses",1,"downstream_body_bytes",partial?8:0,"committed_state_observed",true,"window_root_retry_succeeded",true);
            }
        } finally {release.countDown();proxy.stop(0);serverThreads.shutdownNow();clientThreads.shutdownNow();serverThreads.awaitTermination(3,TimeUnit.SECONDS);clientThreads.awaitTermination(3,TimeUnit.SECONDS);}
    }
    static void mixed() throws Exception {
        JsonObject root=create("5.4");Reply legacy=refreshAt(A,root,"5.4");need(legacy.ok(),"LEGACY_CANDIDATE_MINT_FAILED");
        Reply upgraded=refreshAt(B,legacy.body(),"5.6");need(upgraded.ok()&&online(A,upgraded.body()).ok(),"LEGACY_CANDIDATE_UPGRADE_FAILED");
        Reply again=refreshAt(A,upgraded.body(),"5.4");need(again.ok(),"LEGACY_CLIENT_REJECTED_CURRENT_TOKEN");
        Reply finalChild=refreshAt(B,again.body(),"5.6");need(finalChild.ok()&&online(A,finalChild.body()).ok()&&state(root).current().equals(verifier(finalChild.body())),"MIXED_PROTOCOL_CHAIN_FAILED");
        pass(active,"sequence",new String[]{"5.4-create","5.4-refresh","5.6-refresh","5.4-refresh","5.6-refresh"},"sdk_support_inferred",false);
    }
    interface Check { void run() throws Exception; }
    static void test(String id,Check action){active=id;try{action.run();}catch(Exception e){ROWS.add(obj("id",id,"status","failed","error",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName()));System.out.println(obj("case",id,"status","failed"));}}
    public static void main(String[] args) throws Exception {
        need(A!=null&&B!=null&&A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567")&&B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567"),"OWNED_DISPOSABLE_TARGETS_REQUIRED");
        if(args.length==1&&args[0].equals("--ready-a")){ready(A);return;}
        JsonObject report=obj("kind","actual-core-cdi56-grace-policy","policy","OSS-CDI56-GRACE5-V1","started",Instant.now().toString(),"complete",false,
            "foundation_passed",false,"sdk_qualified",false,"independent_human_review",false,"credential_values_recorded",false);
        try {
            ready(A);ready(B);user=signup("grace-"+UUID.randomUUID()+"@example.test");
            test("GRACE56-PRIVATE-CONTRACT",()->{
                Reply r=request(B,"POST","/recipe/session/refresh",obj("refreshToken","invalid","enableAntiCsrf",false,"useDynamicSigningKey",true),"5.6",false);need(r.code()==401,"PRIVATE_REFRESH_UNGUARDED");
                for(String replica:List.of(A,B)) {
                    Reply capability=request(replica,"GET","/public/expertauth/password/session",null,"5.4",true);
                    need(capability.ok(),"PRIVATE_CAPABILITY_UNAVAILABLE");
                    JsonObject effective=capability.body().getAsJsonObject("sessionPolicy");
                    need(effective!=null&&effective.get("refreshTokenRotationGracePeriodSeconds").getAsInt()==5&&
                        effective.get("recentTokenReuseBehaviour").getAsString().equals("TOKEN_THEFT"),"EFFECTIVE_POLICY_DIFFERS");
                    need(request(replica,"GET","/public/expertauth/password/session",null,"5.4",false).code()==401,"PRIVATE_POLICY_UNGUARDED");
                }
                pass(active,"effective_grace_seconds",5,"effective_reuse_behaviour","TOKEN_THEFT","replicas_checked",2);
            });
            test("GRACE56-ROTATION-AT-REFRESH",RefreshGraceProbe::rotation);
            test("GRACE56-PARENT-RETRY-ANCHOR",RefreshGraceProbe::retries);
            test("GRACE56-EIGHT-REQUEST-CONVERGENCE",RefreshGraceProbe::concurrent);
            test("GRACE56-RECENT-PREV-OUTSIDE-WINDOW",()->reuse("RECENT_PREV"));
            test("GRACE56-ORPHANED-BRANCH-REVOCATION",()->reuse("ORPHANED_BRANCH"));
            test("GRACE56-STALE-LINEAGE-REVOCATION",()->reuse("STALE_LINEAGE"));
            test("GRACE56-TRANSACTION-ABORT-AFTER-UPDATE",RefreshGraceProbe::abortAfterUpdate);
            test("GRACE56-COMMITTED-LOST-RESPONSE",()->lostResponse(false,false));
            test("GRACE56-PARTIAL-RESPONSE",()->lostResponse(true,false));
            test("GRACE56-LOGOUT-LATE-RESPONSE",()->lostResponse(false,true));
            test("GRACE56-CROSS-VERSION-BRIDGE",RefreshGraceProbe::mixed);
        } catch(Exception e){report.addProperty("fatal",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName());}
        report.add("rows",GSON.toJsonTree(ROWS));report.add("requests",GSON.toJsonTree(REQUESTS));report.addProperty("finished",Instant.now().toString());
        boolean passed=!report.has("fatal")&&ROWS.size()==12&&ROWS.stream().allMatch(r->r.get("status").getAsString().equals("passed"));report.addProperty("passed",passed);
        Files.writeString(Path.of("/out/probe-report.json"),GSON.toJson(report)+"\n");System.out.println(obj("passed",passed,"cases",ROWS.size()));System.exit(passed?0:1);
    }
}
