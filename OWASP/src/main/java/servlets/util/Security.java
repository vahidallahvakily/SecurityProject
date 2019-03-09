package servlets.util;

public class Security {

    public static final String CIPHER_AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    public static final String CIPHER_RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static KeyFactory keyFactory() {
        return KeyFactory.getInstance();
    }

    public static Cipher cipher() {
        return Cipher.getInstance();
    }

    public static Encoder encoder() {
        return Encoder.getInstance();
    }
}
