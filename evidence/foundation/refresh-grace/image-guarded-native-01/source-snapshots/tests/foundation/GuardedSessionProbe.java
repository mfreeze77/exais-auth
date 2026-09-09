/* Real guarded Core HTTP/JDBC behavior on owned disposable configurations. */
import com.google.gson.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class GuardedSessionProbe extends RefreshGraceProbe {
    static final String C=System.getenv("RESET_CORE_C"),D=System.getenv("RESET_CORE_D");
    static Reply guarded(String base,JsonObject session,boolean refresh,String version,boolean authorized) throws Exception {
        JsonObject body=refresh?obj("refreshToken",refreshToken(session),"enableAntiCsrf",false,"useDynamicSigningKey",true):
            obj("accessToken",session.getAsJsonObject("accessToken").get("token").getAsString(),"enableAntiCsrf",false,"doAntiCsrfCheck",false,"checkDatabase",true);
        return request(base,"POST","/expertauth/session/"+(refresh?"refresh":"verify"),body,version,authorized);
    }
    static boolean policyDenied(Reply r){return r.code()==503&&r.status().equals("SESSION_POLICY_MISMATCH")&&!r.body().has("accessToken")&&!r.body().has("refreshToken");}
    static void mismatch(String replica) throws Exception {
        JsonObject root=create("5.6");State before=state(root);
        Reply preflight=request(A,"GET","/public/expertauth/password/session",null,"5.4",true);
        need(preflight.ok()&&preflight.body().getAsJsonObject("sessionPolicy").get("refreshTokenRotationGracePeriodSeconds").getAsInt()==5,"HEALTHY_PREFLIGHT_FAILED");
        need(policyDenied(guarded(replica,root,true,"5.6",true))&&policyDenied(guarded(replica,root,false,"5.6",true)),"MISMATCHED_OPERATION_EXECUTED");
        need(before.equals(state(root)),"MISMATCH_CHANGED_SESSION");
        Reply retry=guarded(A,root,true,"5.6",true);need(retry.ok()&&guarded(A,retry.body(),false,"5.6",true).ok(),"SAME_CREDENTIAL_RECOVERY_FAILED");
        pass(active,"healthy_preflight_http",200,"refresh_http",503,"verify_http",503,"session_columns_unchanged",true,"retry_http",200);
    }
    public static void main(String[] args) throws Exception {
        need(A!=null&&B!=null&&C!=null&&A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567")&&
            B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567")&&C.matches("http://expertauth-reset-core-c-[a-f0-9]+:3567")&&
            (D==null||D.matches("http://expertauth-reset-core-d-[a-f0-9]+:3567")),"OWNED_LAB_TARGETS_REQUIRED");
        JsonObject report=obj("kind","actual-guarded-session-operations","started",Instant.now().toString(),"passed",false,
            "foundation_passed",false,"sdk_qualified",false,"independent_human_review",false,"complete",false,"legacy_replica_included",D!=null);
        int exit=0;
        try {
            ready(A);ready(B);ready(C);if(D!=null)ready(D);
            user=signup("guarded-"+UUID.randomUUID()+"@example.test");
            test("GUARD56-PRIVATE-CAPABILITY",()->{
                Reply r=request(A,"GET","/public/expertauth/password/session",null,"5.4",true);
                need(r.ok()&&r.body().get("guardedSessionOperations").getAsString().equals("OSS-CDI56-GRACE5-V1"),"GUARDED_CAPABILITY_MISSING");
                JsonObject root=create("5.6");State before=state(root);
                need(guarded(A,root,true,"5.6",false).code()==401&&guarded(A,root,false,"5.6",false).code()==401,"GUARDED_API_UNAUTHENTICATED");
                need(before.equals(state(root)),"UNAUTHENTICATED_REQUEST_CHANGED_SESSION");pass(active,"unauthenticated_http",401);
            });
            test("GUARD56-SERIAL-ROTATION",()->{
                JsonObject root=create("5.6");Reply child=guarded(A,root,true,"5.6",true);
                need(child.ok()&&state(root).current().equals(verifier(child.body()))&&guarded(A,child.body(),false,"5.6",true).ok(),"GUARDED_ROTATION_FAILED");
                Reply retry=guarded(A,root,true,"5.6",true);need(retry.ok()&&state(root).current().equals(verifier(retry.body())),"GUARDED_GRACE_RETRY_FAILED");
                pass(active,"refresh_http",200,"verify_http",200,"grace_retry_http",200);
            });
            test("GUARD56-PREFLIGHT-ZERO-GRACE-OPERATION",()->mismatch(B));
            test("GUARD56-PREFLIGHT-OTHER-REUSE-OPERATION",()->mismatch(C));
            test("GUARD56-VERSION-DOWNGRADE-REFUSED",()->{
                JsonObject root=create("5.6");State before=state(root);
                for(String version:List.of("5.3","5.4"))for(boolean refresh:List.of(true,false))need(policyDenied(guarded(A,root,refresh,version,true)),"GUARDED_PROTOCOL_DOWNGRADED");
                need(before.equals(state(root)),"DOWNGRADE_CHANGED_SESSION");pass(active,"denied_requests",4,"session_columns_unchanged",true);
            });
            test("GUARD56-ORIGINAL-INVALID-TOKEN-ERRORS",()->{
                for(String operation:List.of("refresh","verify")) {
                    JsonObject body=operation.equals("refresh")?obj("refreshToken","invalid","enableAntiCsrf",false,"useDynamicSigningKey",true):
                        obj("accessToken","invalid","enableAntiCsrf",false,"doAntiCsrfCheck",false,"checkDatabase",true);
                    Reply original=request(A,"POST","/recipe/session/"+operation,body,"5.6",true);
                    Reply guarded=request(A,"POST","/expertauth/session/"+operation,body,"5.6",true);
                    need(!original.ok()&&guarded.code()==original.code()&&guarded.status().equals(original.status()),"ORIGINAL_INVALID_TOKEN_CONTRACT_CHANGED");
                }
                pass(active,"original_and_guarded_errors_equal",true);
            });
            test("GUARD56-CONCURRENT-MIXED-POLICY",()->{
                JsonObject root=create("5.6");ExecutorService pool=Executors.newFixedThreadPool(8);CountDownLatch gate=new CountDownLatch(1);
                List<Future<Reply>> futures=new ArrayList<>();List<JsonObject> successes=new ArrayList<>();int denials=0;
                try {
                    for(int i=0;i<16;i++){final String base=i%2==0?A:(i%4==1?B:C);futures.add(pool.submit(()->{gate.await();return guarded(base,root,true,"5.6",true);}));}
                    gate.countDown();for(Future<Reply> f:futures){Reply r=f.get(18,TimeUnit.SECONDS);if(r.ok())successes.add(r.body());else if(policyDenied(r))denials++;else throw new IllegalStateException("MIXED_REQUEST_RESULT_UNEXPECTED");}
                    need(successes.size()==8&&denials==8,"CONCURRENT_POLICY_COUNTS_DIFFER");int current=0;State finalState=state(root);
                    for(JsonObject candidate:successes)if(finalState.current().equals(verifier(candidate))){current++;need(guarded(A,candidate,false,"5.6",true).ok(),"CURRENT_SUCCESSOR_DENIED");}
                    need(current==1,"CURRENT_SUCCESSOR_NOT_UNIQUE");pass(active,"requests",16,"successful_refreshes",8,"mismatched_refusals",8,"authoritative_successors",1);
                }finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
            });
            test("GUARD56-ORIGINAL-ROUTES-UNCHANGED",()->{
                JsonObject root=create("5.6");need(policyDenied(guarded(B,root,true,"5.6",true)),"MISMATCH_NOT_REFUSED");
                Reply original=refreshAt(B,root,"5.6");need(original.ok()&&online(B,original.body()).ok(),"ORIGINAL_POLICY_INHERITED_GUARD");
                pass(active,"guarded_http",503,"original_refresh_http",200,"original_verify_http",200);
            });
            if(D!=null)test("GUARD56-OLD-REPLICA-FAILS-CLOSED",()->{
                JsonObject root=create("5.6");State before=state(root);
                need(guarded(D,root,true,"5.6",true).code()==404&&guarded(D,root,false,"5.6",true).code()==404,"OLD_REPLICA_ACCEPTED_NEW_GUARDED_ROUTE");
                need(before.equals(state(root)),"OLD_REPLICA_CHANGED_SESSION");need(refreshAt(D,root,"5.6").ok(),"OLD_REPLICA_UNAVAILABLE");
                pass(active,"guarded_refresh_http",404,"guarded_verify_http",404,"session_columns_unchanged",true,"original_refresh_http",200);
            });
        }catch(Exception error){exit=1;ROWS.add(obj("id",active,"status","failed","error",error.getClass().getSimpleName()));}
        finally {
            try{if(user!=null)need(post(A,"/user/remove",obj("userId",user,"removeAllLinkedAccounts",false)).ok(),"OWNED_CLEANUP_FAILED");
                pass("GUARD56-OWNED-FIXTURE-CLEANUP","owned_users_removed",user==null?0:1);
            }catch(Exception error){exit=1;ROWS.add(obj("id","GUARD56-OWNED-FIXTURE-CLEANUP","status","failed","error",error.getClass().getSimpleName()));}
            boolean passed=exit==0&&ROWS.stream().allMatch(r->r.get("status").getAsString().equals("passed"));
            report.addProperty("passed",passed);report.add("rows",GSON.toJsonTree(ROWS));report.add("requests",GSON.toJsonTree(REQUESTS));
            report.addProperty("finished",Instant.now().toString());Files.writeString(Path.of("/out/guarded-report.json"),GSON.toJson(report)+"\n",StandardOpenOption.CREATE_NEW);
            System.out.println(obj("passed",passed,"rows",ROWS.size()));if(!passed)exit=1;
        }
        System.exit(exit);
    }
}
