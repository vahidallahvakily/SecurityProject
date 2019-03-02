import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class _0170_AES_GCM_Speed {
    // AES Mode parameters
    private static final int AES_KEY_SIZE = 128; // in bits
    private static final int AES_COUNTER_SIZE = 16; // in bytes
    private static final int GCM_NONCE_LENGTH = 12; // in bytes. 12 is the recommended value.
    private static final int GCM_TAG_LENGTH = 16 * 8; // in bits

    private static final int WARMUP = 100000;

    public static void main(String[] args) throws Exception {
        SecureRandom sr = new SecureRandom();

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey key = kg.generateKey();

        byte[] counter = new byte[AES_COUNTER_SIZE];
        Cipher aes_ctr = Cipher.getInstance("AES/CTR/NoPadding");

        // Warm-up
        for (int i = 0; i < WARMUP; i++) {
            sr.nextBytes(counter);
            aes_ctr.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(counter));
            enc(aes_ctr, new byte[16]);
        }

        sr.nextBytes(counter);
        aes_ctr.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(counter));
        speedTest(aes_ctr);

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        Cipher aes_gcm = Cipher.getInstance("AES/GCM/NoPadding");

        // Warm-up
        for (int i = 0; i < WARMUP; i++) {
            sr.nextBytes(nonce);
            aes_gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
            enc(aes_gcm, new byte[16]);
        }

        sr.nextBytes(nonce);
        aes_gcm.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        speedTest(aes_gcm);

    }

    private static void speedTest(Cipher cipher) throws Exception {
        byte[] ptxt = new byte[1 << 26];
        long start, end;

        start = System.nanoTime();
        enc(cipher, ptxt);
        end = System.nanoTime();


        System.out.printf("%s took %f seconds.\n",
                cipher.getAlgorithm(),
                (end - start) / 1E9);
    }

    private static void enc(Cipher cipher, byte[] ptxt) throws Exception {
        cipher.doFinal(ptxt);
    }
}
