package servlets.util;


import java.nio.charset.Charset;
import java.security.*;

public class Cipher {

    private static final Cipher instance = new Cipher();
    private String hashAlgorithm = "SHA-256";
    private String signatureAlgorithm = "SHA1WithRSA";

    private Charset charset = Charset.forName("UTF-8");

    public static Cipher getInstance() {
        return instance;
    }

    public String sign(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(data.getBytes(charset));

        return Security.encoder().encodeForHex(signature.sign());
    }

    public boolean verifySignature(String signature, String data, PublicKey publicKey) {
        try {
            byte[] e = Security.encoder().decodeFormHex(signature);
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initVerify(publicKey);
            signer.update(data.getBytes(charset));
            return signer.verify(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Invalid signature", e);
        }
    }

    public String hash(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(text.getBytes(charset));
            byte[] digest = md.digest();
            return Security.encoder().encodeForHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("Unable to compute hash while signing request: " + e.getMessage(), e);
        }
    }


}
