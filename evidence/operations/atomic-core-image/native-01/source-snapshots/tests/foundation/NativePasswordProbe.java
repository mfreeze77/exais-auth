/* Actual Core HTTP/JDBC qualification of a source-built Argon2 library.
 * PHC vectors below are from the unchanged CC0-1.0/Apache-2.0 src/test.c at
 * 62358ba2123abd17fccf2a108a301d4b52c01a7c. Other fixtures are disposable.
 */
import com.google.gson.*;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.mindrot.jbcrypt.BCrypt;

public class NativePasswordProbe extends AtomicResetProbe {
    static final List<String> users = Collections.synchronizedList(new ArrayList<>());
    static String email() { return "native-"+UUID.randomUUID()+"@example.test"; }
    static String user(Reply r) {
        need(r.ok(), "USER_CREATION_FAILED");
        String id=r.body().getAsJsonObject("user").get("id").getAsString();users.add(id);return id;
    }
    static String signupAt(String base,String mail,String password) throws Exception {
        return user(post(base,"/recipe/signup",obj("email",mail,"password",password)));
    }
    static Reply signinAt(String base,String mail,String password) throws Exception {
        return post(base,"/recipe/signin",obj("email",mail,"password",password));
    }
    static String stored(String id) throws Exception {
        try(Connection c=db();PreparedStatement s=c.prepareStatement("SELECT password_hash FROM emailpassword_users WHERE user_id=?")) {
            s.setString(1,id);try(ResultSet r=s.executeQuery()){need(r.next(),"OWNED_HASH_MISSING");String h=r.getString(1);need(!r.next(),"AMBIGUOUS_HASH");return h;}
        }
    }
    static void both(String mail,String password,String id) throws Exception {
        for(String base:List.of(A,B)) {
            Reply correct=signinAt(base,mail,password),wrong=signinAt(base,mail,password+"-wrong");
            need(correct.ok()&&correct.body().getAsJsonObject("user").get("id").getAsString().equals(id),"CROSS_LIBRARY_PASSWORD_DENIED_OR_WRONG_SUBJECT");
            need(wrong.code()==200&&wrong.status().equals("WRONG_CREDENTIALS_ERROR"),"WRONG_PASSWORD_NOT_DENIED");
        }
    }
    static void newHash(String base) throws Exception {
        String mail=email(),id=signupAt(base,mail,OLD),hash=stored(id);
        need(hash.startsWith("$argon2id$v=19$m=87795,t=1,p=2$"),"CONFIGURED_NATIVE_HASH_PARAMETERS_DIFFER");
        both(mail,OLD,id);need(stored(id).equals(hash),"VERIFY_CHANGED_PASSWORD_HASH");
        pass(active,"configured_memory_kib",87795,"configured_iterations",1,"configured_parallelism",2,"both_libraries_verified",true);
    }
    static void vector(String encoded,String algorithm) throws Exception {
        String mail=email();Reply imported=post(A,"/recipe/user/passwordhash/import",obj("email",mail,"passwordHash",encoded,"hashingAlgorithm",algorithm));
        String id=user(imported);need(stored(id).equals(encoded),"IMPORT_ALTERED_HASH");both(mail,"password",id);
        need(stored(id).equals(encoded),"VERIFICATION_REHASHED_LEGACY_INPUT");
        pass(active,"both_libraries_verified",true,"imported_hash_preserved",true,"automatic_rehash",false);
    }
    static void resetAcross() throws Exception {
        String mail=email(),id=signupAt(A,mail,OLD),password=OLD;
        for(String writer:List.of(A,B)) {
            JsonObject original=session(id,A);String token=issue(id,mail),next="Next-"+UUID.randomUUID();
            need(reset(writer,token,next).ok(),"NATIVE_RESET_FAILED");both(mail,next,id);
            need(!signinAt(A,mail,password).ok()&&!signinAt(B,mail,password).ok(),"OLD_PASSWORD_SURVIVED");
            need(!verify(original,true).ok()&&!refresh(original).ok(),"RESET_SESSION_SURVIVED");
            need(!reset(writer,token,password).ok(),"RESET_TOKEN_REUSED");password=next;
        }
        pass(active,"reset_writers",2,"old_sessions_denied",true,"one_time_tokens_enforced",true);
    }
    static void concurrency() throws Exception {
        ExecutorService pool=Executors.newFixedThreadPool(8);CountDownLatch gate=new CountDownLatch(1);List<Future<String>> jobs=new ArrayList<>();
        try {
            for(int i=0;i<8;i++){final String base=i%2==0?A:B;jobs.add(pool.submit(()->{
                String mail=email(),password="Concurrent-"+UUID.randomUUID();gate.await();String id=signupAt(base,mail,password);both(mail,password,id);return id;
            }));}
            gate.countDown();Set<String> ids=new HashSet<>();for(Future<String> job:jobs)ids.add(job.get(40,TimeUnit.SECONDS));need(ids.size()==8,"CONCURRENT_SUBJECT_COLLISION");
            pass(active,"concurrent_users",8,"distinct_subjects",ids.size(),"both_libraries_verified",true);
        }finally{pool.shutdownNow();need(pool.awaitTermination(20,TimeUnit.SECONDS),"NATIVE_WORKERS_DID_NOT_FINISH");}
    }
    interface Check{void run()throws Exception;}
    static void test(String id,Check action){active=id;try{action.run();}catch(Exception e){ROWS.add(obj("id",id,"status","failed","error",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName()));System.out.println(obj("case",id,"status","failed"));}}
    public static void main(String[] args)throws Exception{
        need(A!=null&&B!=null&&A.matches("http://expertauth-reset-core-a-[a-f0-9]+:3567")&&B.matches("http://expertauth-reset-core-b-[a-f0-9]+:3567"),"OWNED_DISPOSABLE_TARGETS_REQUIRED");
        if(args.length==1&&args[0].equals("--ready-a")){ready(A);return;}
        JsonObject report=obj("kind","native-argon2-core-password-qualification","complete",false,"foundation_passed",false,"full_migration_qualified",false,
            "independent_human_review",false,"credential_values_recorded",false,"started",Instant.now().toString());
        try{
            ready(A);ready(B);
            test("NATIVE-PRIVATE-IMPORT",()->{need(call(A,"POST","/recipe/user/passwordhash/import",obj("email",email(),"passwordHash","invalid"),"emailpassword",false).code()==401,"IMPORT_NOT_PRIVATE");pass(active);});
            test("NATIVE-SOURCE-HASH-BUNDLED-VERIFY",()->newHash(A));
            test("NATIVE-BUNDLED-HASH-SOURCE-VERIFY",()->newHash(B));
            test("NATIVE-PHC-ARGON2I-V16",()->vector("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ","ARGON2"));
            test("NATIVE-PHC-ARGON2I-V19",()->vector("$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E","ARGON2"));
            test("NATIVE-PHC-ARGON2ID-V19",()->vector("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc","ARGON2"));
            test("NATIVE-BCRYPT-IMPORT-COMPATIBILITY",()->vector(BCrypt.hashpw("password",BCrypt.gensalt(10)),"BCRYPT"));
            test("NATIVE-MALFORMED-IMPORT",()->{
                String mail=email();need(post(A,"/recipe/user/passwordhash/import",obj("email",mail,"passwordHash","bad","hashingAlgorithm","ARGON2")).code()==400,"INVALID_IMPORT_ACCEPTED");
                need(!signinAt(A,mail,OLD).ok()&&!signinAt(B,mail,OLD).ok(),"INVALID_IMPORT_AUTHENTICATED");pass(active);
            });
            test("NATIVE-ATOMIC-RESET-CROSS-LIBRARY",NativePasswordProbe::resetAcross);
            test("NATIVE-EIGHT-CONCURRENT-OWNERS",NativePasswordProbe::concurrency);
        }catch(Exception e){report.addProperty("fatal",e instanceof IllegalStateException?e.getMessage():e.getClass().getSimpleName());}
        finally{
            test("NATIVE-OWNED-FIXTURE-CLEANUP",()->{
                for(String id:users)need(post(A,"/user/remove",obj("userId",id)).ok(),"OWNED_DELETE_FAILED");
                Reply count=call(A,"GET","/users/count",null,"session",true);need(count.ok()&&count.body().get("count").getAsInt()==0,"DISPOSABLE_USERS_REMAIN");pass(active,"removed_users",users.size());
            });
        }
        boolean passed=!report.has("fatal")&&ROWS.size()==11&&ROWS.stream().allMatch(r->r.get("status").getAsString().equals("passed"));
        report.addProperty("passed",passed);report.add("rows",GSON.toJsonTree(ROWS));report.add("requests",GSON.toJsonTree(REQUESTS));report.addProperty("finished",Instant.now().toString());
        Files.writeString(Path.of("/out/native-password-report.json"),GSON.toJson(report)+"\n");System.exit(passed?0:1);
    }
}
