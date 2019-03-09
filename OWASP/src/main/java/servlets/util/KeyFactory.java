package servlets.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyFactory {
    private static final KeyFactory instance = new KeyFactory();

    public static KeyFactory getInstance() {
        return instance;
    }

    public SecretKey generateSecret(byte[] keyBytes, String algorithm) {
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, algorithm);
        return secretKey;
    }

    public RsaKeyFactory rsa() {
        return RsaKeyFactory.getInstance();
    }
}
