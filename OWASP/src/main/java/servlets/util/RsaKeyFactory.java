package servlets.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaKeyFactory {
    private static final RsaKeyFactory instance = new RsaKeyFactory();

    public static RsaKeyFactory getInstance() {
        return instance;
    }

    private RsaKeyFactory() {
    }

    private String readKeyFileContent(final InputStream in) throws Exception {
        try {
            byte[] keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();

            return new String(keyBytes, "UTF-8");
        } catch (java.io.IOException e) {
            throw new Exception(e);
        }
    }

    private String readKeyFileContent(final String filePath) throws Exception {
        try {
            FileInputStream in = new FileInputStream(filePath);

            byte[] keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();

            return new String(keyBytes, "UTF-8");
        } catch (java.io.IOException e) {
            throw new Exception(e);
        }
    }

    public PrivateKey readPrivateKeyFile(final InputStream in) throws Exception {
        try {
            String privateKey = readKeyFileContent(in);
            return generatePrivateKey(privateKey);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public PrivateKey readPrivateKeyFile(final String fileName) throws Exception {
        try {
            String privateKey = readKeyFileContent(fileName);
            return generatePrivateKey(privateKey);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public PublicKey readPublicKeyFile(final InputStream in) throws Exception {
        try {
            String pubKey = readKeyFileContent(in);
            return generatePublicKey(pubKey);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public PublicKey readPublicKeyFile(final String fileName) throws Exception {
        try {
            String pubKey = readKeyFileContent(fileName);
            return generatePublicKey(pubKey);
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    public PublicKey generatePublicKey(String encodeBase64PublicKey) throws Exception {
        try {
            encodeBase64PublicKey = encodeBase64PublicKey.replaceAll("(-+BEGIN .*PUBLIC KEY-+\\r?\\n|-+END .*PUBLIC KEY-+\\r?\\n?)", "");
            byte[] keyBytes = Security.encoder().decodeFromBase64(encodeBase64PublicKey);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);

        } catch (GeneralSecurityException e) {
            throw new Exception(e);
        }
    }

    public PrivateKey generatePrivateKey(String encodeBase64PrivateKey) throws Exception {
        try {
            encodeBase64PrivateKey = encodeBase64PrivateKey.replaceAll("(-+BEGIN .*PRIVATE KEY-+\\r?\\n|-+END .*PRIVATE KEY-+\\r?\\n?)", "");
            byte[] keyBytes = Security.encoder().decodeFromBase64(encodeBase64PrivateKey);

            // generate private key
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);

        } catch (GeneralSecurityException e) {
            throw new Exception(e);
        }
    }

}
