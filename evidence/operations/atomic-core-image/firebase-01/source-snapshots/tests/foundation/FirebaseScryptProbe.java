/* ExpertAuth contributors, 2026. Apache-2.0.
 * Actual Core APIs and independent Node/OpenSSL public fixtures, never mock responses.
 */
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.crypto.generators.SCrypt;

public class FirebaseScryptProbe extends PasswordSessionProbe {
    static final List<String> USERS=Collections.synchronizedList(new ArrayList<>());
    static final String PEER=System.getenv("FIREBASE_REFERENCE_PROFILE");
    static JsonObject FIXTURES;
    static boolean oldPeer(){return PEER.equals("original-lambdaworks-ascii");}
    static String mail(){return "firebase-"+UUID.randomUUID()+"@example.test";}
    static JsonObject fixture(String id){for(JsonElement e:FIXTURES.getAsJsonArray("fixtures")){if(e.getAsJsonObject().get("id").getAsString().equals(id))return e.getAsJsonObject();}throw new IllegalStateException("FIXTURE_MISSING");}
    static String value(JsonObject f,String field){return f.get(field).getAsString();}
    static String imported(String email,String encoded,String base)throws Exception{
        Reply r=post(base,"/recipe/user/passwordhash/import",obj("email",email,"passwordHash",encoded,"hashingAlgorithm","FIREBASE_SCRYPT"));
        need(r.ok(),"IMPORT_FAILED");need(!r.body().toString().contains("passwordHash"),"HASH_EXPOSED");
        String id=r.body().getAsJsonObject("user").get("id").getAsString();USERS.add(id);return id;
    }
    static String stored(String id)throws Exception{
        try(Connection c=db();PreparedStatement s=c.prepareStatement("SELECT password_hash FROM emailpassword_users WHERE user_id=?")){
            s.setString(1,id);try(ResultSet r=s.executeQuery()){need(r.next(),"OWNED_HASH_MISSING");String hash=r.getString(1);need(!r.next(),"DUPLICATE_OWNED_HASH");return hash;}
        }
    }
    static Reply escapedLogin(String base,String email,String password)throws Exception{
        String json=obj("email",email,"password",password).toString();StringBuilder ascii=new StringBuilder();
        for(char c:json.toCharArray()){if(c>127)ascii.append(String.format("\\u%04x",(int)c));else ascii.append(c);}
        HttpRequest request=HttpRequest.newBuilder(URI.create(base+"/recipe/signin")).timeout(Duration.ofSeconds(15))
            .header("cdi-version","5.4").header("rid","emailpassword").header("api-key",KEY).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(ascii.toString(),StandardCharsets.US_ASCII)).build();
        long started=System.nanoTime();HttpResponse<String> response=HTTP.send(request,HttpResponse.BodyHandlers.ofString());
        Reply r=new Reply(response.statusCode(),JsonParser.parseString(response.body()).getAsJsonObject());
        REQUESTS.add(obj("method","POST","path","/recipe/signin","replica",base.equals(A)?"a":"b","http",r.code(),"status",r.status(),
            "elapsed_ms",TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started),"body_encoding","ascii-json-unicode-escapes","credential_bodies_recorded",false));return r;
    }
    static Reply login(String base,String email,String password)throws Exception{
        // Historical hasher comparison is separated from its known default-charset defect.
        return oldPeer()&&base.equals(B)?escapedLogin(base,email,password):post(base,"/recipe/signin",obj("email",email,"password",password));
    }
    static void accepted(String base,String email,String password,String id)throws Exception{
        Reply r=login(base,email,password);need(r.ok()&&r.body().getAsJsonObject("user").get("id").getAsString().equals(id),"PASSWORD_OR_SUBJECT_DIFFERS");
        need(!r.body().toString().contains("passwordHash"),"HASH_EXPOSED");
    }
    static void denied(String base,String email,String password)throws Exception{
        Reply r=login(base,email,password);need(r.code()==200&&r.status().equals("WRONG_CREDENTIALS_ERROR"),"PASSWORD_NOT_DENIED_CLEANLY");
    }
    static void vector(String name,boolean unicode)throws Exception{
        JsonObject f=fixture(name);String email=mail(),encoded=value(f,"encoded"),id=imported(email,encoded,A),password=value(f,"password");
        need(stored(id).equals(encoded),"IMPORT_NOT_HASH_PRESERVING");accepted(A,email,password,id);denied(A,email,password+"-wrong");
        need(escapedLogin(A,email,password).ok(),"JSON_ESCAPED_PASSWORD_DIFFERS");
        if(unicode&&oldPeer())denied(B,email,password);else accepted(B,email,password,id);
        denied(B,email,password+"-wrong");need(stored(id).equals(encoded),"UNDECLARED_REHASH");
        pass(active,"unicode",unicode,"old_peer_rejects_correct_unicode",unicode&&oldPeer(),"automatic_rehash",false,"hash_exposed",false);
    }
    static void collision()throws Exception{
        JsonObject f=fixture("question-mark");String email=mail(),id=imported(email,value(f,"encoded"),A);accepted(A,email,"?",id);denied(A,email,"\u00e9");
        if(oldPeer())accepted(B,email,"\u00e9",id);else denied(B,email,"\u00e9");
        pass(active,"candidate_refuses_distinct_unicode_password",true,"historical_peer_false_acceptance",oldPeer(),"historical_behavior_is_security_failure",oldPeer());
    }
    static void invalidParameters()throws Exception{
        JsonObject f=fixture("cost-two");String alias=value(f,"encoded").replace("$m=1$","$m=33$"),email=mail(),id=imported(email,alias,A);
        denied(A,email,value(f,"password"));if(oldPeer())accepted(B,email,value(f,"password"),id);else denied(B,email,value(f,"password"));
        String zero=value(fixture("upstream-ascii"),"encoded").replace("$r=8$","$r=0$");String other=mail();imported(other,zero,A);denied(A,other,"testPass123");
        pass(active,"candidate_rejects_shift_alias_and_zero_block",true,"historical_peer_accepts_shift_alias",oldPeer(),"full_import_parameter_validation",false);
    }
    static void atomicSession()throws Exception{
        JsonObject f=fixture("utf8");String email=mail(),id=imported(email,value(f,"encoded"),A),password=value(f,"password");
        Reply session=passwordSession(A,id,email,password);need(session.ok()&&verify(session.body(),true).ok(),"ATOMIC_IMPORTED_SESSION_FAILED");
        int before=count(id);Reply wrong=passwordSession(A,id,email,password+"-wrong");need(rejected(wrong)&&count(id)==before,"WRONG_PASSWORD_ISSUED_SESSION");
        pass(active,"actual_atomic_password_recheck",true,"wrong_password_no_session",true);
    }
    static void resetImport()throws Exception{
        JsonObject f=fixture("upstream-ascii");String email=mail(),id=imported(email,value(f,"encoded"),A),password=value(f,"password");
        for(String writer:List.of(A,B)){
            Reply previous=passwordSession(A,id,email,password);need(previous.ok(),"PRE_RESET_SESSION_FAILED");String token=issue(id,email),next="Reset-"+UUID.randomUUID();
            need(reset(writer,token,next).ok(),"RESET_IMPORT_FAILED");accepted(A,email,next,id);accepted(B,email,next,id);
            denied(A,email,password);denied(B,email,password);need(!verify(previous.body(),true).ok()&&!refresh(previous.body()).ok(),"OLD_SESSION_SURVIVED_RESET");
            need(!reset(writer,token,password).ok(),"RESET_TOKEN_REPLAYED");need(stored(id).startsWith("$2a$"),"RESET_POLICY_DIFFERS");password=next;
        }
        pass(active,"reset_writers",2,"existing_sessions_denied",true,"configured_bcrypt_after_reset",true);
    }
    static void concurrent()throws Exception{
        ExecutorService pool=Executors.newFixedThreadPool(8);CountDownLatch gate=new CountDownLatch(1);List<Future<String>> jobs=new ArrayList<>();
        try{
            for(int i=0;i<8;i++){final int n=i;jobs.add(pool.submit(()->{
                JsonObject f=fixture("owner-"+n);String email=mail();gate.await();String id=imported(email,value(f,"encoded"),n%2==0?A:B);
                String target=!oldPeer()&&n%2!=0?B:A;accepted(target,email,value(f,"password"),id);denied(target,email,value(f,"password")+"-wrong");
                Reply s=passwordSession(target,id,email,value(f,"password"));need(s.ok()&&verify(s.body(),true).ok(),"CONCURRENT_IMPORTED_SESSION_FAILED");return id;
            }));}
            gate.countDown();Set<String> ids=new HashSet<>();for(Future<String> f:jobs)ids.add(f.get(40,TimeUnit.SECONDS));need(ids.size()==8,"CONCURRENT_SUBJECT_COLLISION");
            pass(active,"concurrent_owners",8,"correct_distinct_subjects",true,"pool_size_per_core",1);
        }finally{pool.shutdownNow();need(pool.awaitTermination(10,TimeUnit.SECONDS),"CONCURRENT_WORKERS_REMAIN");}
    }
    interface Check{void run()throws Exception;}
    static void test(String id,Check action){active=id;try{action.run();}catch(Exception e){ROWS.add(obj("id",id,"status","failed","error",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName()));System.out.println(obj("case",id,"status","failed"));}}
    public static void main(String[] args)throws Exception{
        need(A!=null&&B!=null&&A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567")&&B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567"),"OWNED_DISPOSABLE_TARGETS_REQUIRED");
        need(List.of("original-lambdaworks-ascii","bouncycastle-utf8-v1").contains(PEER),"UNKNOWN_PEER");
        FIXTURES=JsonParser.parseString(Files.readString(Path.of("/out/firebase-fixtures.json"))).getAsJsonObject();
        JsonObject report=obj("kind","actual-firebase-scrypt-core-qualification","started",Instant.now().toString(),"complete",false,"foundation_passed",false,
            "full_migration_qualified",false,"independent_human_review",false,"peer_profile",PEER,"credential_bodies_recorded",false);
        try{
            ready(A);ready(B);
            test("FIREBASE-PRIVATE-IMPORT",()->{need(call(A,"POST","/recipe/user/passwordhash/import",obj("email",mail(),"passwordHash","invalid"),"emailpassword",false).code()==401,"IMPORT_NOT_PRIVATE");pass(active);});
            test("FIREBASE-NODE-BC-PRIMITIVES",()->{
                for(JsonElement e:FIXTURES.getAsJsonArray("primitives")){JsonObject v=e.getAsJsonObject();byte[] bytes=SCrypt.generate(value(v,"password").getBytes(StandardCharsets.UTF_8),value(v,"salt").getBytes(StandardCharsets.UTF_8),v.get("N").getAsInt(),v.get("r").getAsInt(),v.get("p").getAsInt(),64);need(HexFormat.of().formatHex(bytes).equals(value(v,"hex")),"INDEPENDENT_KDF_DIFFERS");}
                String version=System.getenv("FIREBASE_BC_VERSION");need(List.of("1.84","1.85.2").contains(version)&&SCrypt.class.getProtectionDomain().getCodeSource().getLocation().getPath().endsWith("/bcprov-jdk18on-"+version+".jar"),"PRIMITIVE_SOURCE_DIFFERS");pass(active,"vectors",3,"bouncycastle_version",version,"full_parameter_space",false);
            });
            test("FIREBASE-UPSTREAM-ASCII-IMPORT",()->vector("upstream-ascii",false));
            test("FIREBASE-UTF8-IMPORT",()->vector("utf8",true));
            test("FIREBASE-UNICODE-COLLISION-REFUSED",FirebaseScryptProbe::collision);
            test("FIREBASE-MALFORMED-IMPORT",()->{need(post(A,"/recipe/user/passwordhash/import",obj("email",mail(),"passwordHash","$f_scrypt$bad","hashingAlgorithm","FIREBASE_SCRYPT")).code()==400,"MALFORMED_IMPORT_ACCEPTED");pass(active);});
            test("FIREBASE-INVALID-PARAMETER-DENIAL",FirebaseScryptProbe::invalidParameters);
            test("FIREBASE-WRONG-HASH",()->{JsonObject f=fixture("upstream-ascii");String email=mail(),encoded=value(f,"encoded").replace("$qZM","$rZM");need(!encoded.equals(value(f,"encoded")),"HASH_FAULT_MISSING");imported(email,encoded,A);denied(A,email,value(f,"password"));denied(B,email,value(f,"password"));pass(active);});
            test("FIREBASE-ATOMIC-PASSWORD-SESSION",FirebaseScryptProbe::atomicSession);
            test("FIREBASE-RESET-IMPORTED-ACCOUNT",FirebaseScryptProbe::resetImport);
            test("FIREBASE-EIGHT-CONCURRENT-OWNERS",FirebaseScryptProbe::concurrent);
        }catch(Exception e){report.addProperty("fatal",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName());}
        finally{
            test("FIREBASE-OWNED-FIXTURE-CLEANUP",()->{for(String id:USERS)need(post(A,"/user/remove",obj("userId",id)).ok(),"OWNED_DELETE_FAILED");Reply count=call(A,"GET","/users/count",null,"session",true);need(count.ok()&&count.body().get("count").getAsInt()==0,"OWNED_USERS_REMAIN");pass(active,"removed_users",USERS.size());});
        }
        boolean passed=!report.has("fatal")&&ROWS.size()==12&&ROWS.stream().allMatch(r->r.get("status").getAsString().equals("passed"));
        report.addProperty("passed",passed);report.add("rows",GSON.toJsonTree(ROWS));report.add("requests",GSON.toJsonTree(REQUESTS));report.addProperty("finished",Instant.now().toString());
        Files.writeString(Path.of("/out/firebase-scrypt-report.json"),GSON.toJson(report)+"\n");System.exit(passed?0:1);
    }
}
