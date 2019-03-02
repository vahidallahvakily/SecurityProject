import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class _0180_RSA_Signature {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(1024);
        KeyPair key = kg.genKeyPair();

        /*
        System.out.println(key.getPublic());
        System.out.println("-".repeat(30));
        System.out.println(key.getPrivate());
        System.out.println("-".repeat(30));
*/
        // RSA-PSS, a very secure variant of RSA signature
        // See: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
        Signature rsa_pss1 = Signature.getInstance("SHA256withRSAandMGF1", "BC");
        Signature rsa_pss2 = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        byte[] data = "I love crypto!".getBytes();

        rsa_pss1.initSign(key.getPrivate());
        rsa_pss1.update(data);
        byte[] signature1 = rsa_pss1.sign();

        rsa_pss2.initSign(key.getPrivate());
        rsa_pss2.update(data);
        byte[] signature2 = rsa_pss2.sign();

        System.out.printf("Signature1: %s\n", Hex.toHexString(signature1));
        System.out.printf("Signature1 length: %d\n", signature1.length);

        System.out.printf("Signature2: %s\n", Hex.toHexString(signature2));
        System.out.printf("Signature2 length: %d\n", signature2.length);

        /*
        System.out.println("-".repeat(30));

        rsa_pss1.initVerify(key.getPublic());
        rsa_pss1.update(data);
        boolean valid1 = rsa_pss1.verify(signature1);
        System.out.printf("Signature1 validated: %b\n", valid1);

        rsa_pss2.initVerify(key.getPublic());
        rsa_pss2.update(data);
        boolean valid2 = rsa_pss2.verify(signature2);
        System.out.printf("Signature2 validated: %b\n", valid2);

        System.out.println("-".repeat(30));

        data[0] ^= 1;
        rsa_pss1.update(data);
        boolean validx = rsa_pss1.verify(signature1);
        System.out.printf("Signature1x validated: %b\n", validx);
        */
    }
}
