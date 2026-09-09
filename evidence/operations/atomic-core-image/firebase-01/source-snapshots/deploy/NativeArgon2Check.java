/* ExpertAuth contributors, 2026. Apache-2.0.
 * Uses maintained wrapper/JNA primitives. The public CC0/Apache PHC vector is
 * unchanged from src/test.c at62358ba2123abd17fccf2a108a301d4b52c01a7c.
 */
import com.sun.jna.NativeLibrary;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.io.File;

public class NativeArgon2Check {
    public static void main(String[] args) {
        try {
            File loaded=NativeLibrary.getInstance("argon2").getFile();
            if(loaded==null || !loaded.getCanonicalPath().equals("/opt/expertauth/native/libargon2.so"))
                throw new IllegalStateException("Unexpected native library");
            Argon2 argon=Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
            String vector="$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc";
            if(!argon.verify(vector,"password".toCharArray()) || argon.verify(vector,"wrong-password".toCharArray()))
                throw new IllegalStateException("Native known-answer failure");
            System.out.println("NATIVE_ARGON2_SELF_TEST_PASSED");
        }catch(Throwable failure){System.err.println("NATIVE_ARGON2_SELF_TEST_FAILED");System.exit(78);}
    }
}
