package servlets.util;

import javax.servlet.http.Cookie;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class SecurityWebUtil {

    private static final String PUBLIC_KEY_FILE = "keys/public_key.pem";
    private static final String PRIVATE_KEY_FILE = "keys/private_key.pem";

    public static Cookie getSignedCookieInstance(String param, String value) {
        String newValueName = mixValueWithTime(value);
        String hashValue = Security.cipher().hash(newValueName);
        String signed = null;
        try {
            signed = Security.cipher().sign(hashValue, getPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        Cookie myCookie=new Cookie(param, newValueName + "_" + signed);
        myCookie.setHttpOnly(true);
        return myCookie;
    }

    public static Boolean verifyCookieSignature(Cookie cookie) {
        return verifyCookieSignature(cookie.getValue());
    }

    public static String getCookieValueWithoutMixTime(String mixValue) {
        return mixValue.split("_")[0];
    }

    public static Boolean verifyCookieSignature(String mixValue) {
        try {
            String mixTimeValue = mixValue.split("_")[0] + "_" + mixValue.split("_")[1];
            String signature = mixValue.split("_")[2];
            String hashValue = Security.cipher().hash(mixTimeValue);
            return Security.cipher().verifySignature(signature, hashValue, getPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static String mixValueWithTime(String value) {
        long cuurent = System.currentTimeMillis();
        return value + "_" + cuurent;
    }

    private static PrivateKey getPrivateKey() throws Exception {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        return Security.keyFactory().rsa().readPrivateKeyFile(classloader.getResourceAsStream(PRIVATE_KEY_FILE));
    }

    private static PublicKey getPublicKey() throws Exception {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        return Security.keyFactory().rsa().readPublicKeyFile(classloader.getResourceAsStream(PUBLIC_KEY_FILE));
    }


}
