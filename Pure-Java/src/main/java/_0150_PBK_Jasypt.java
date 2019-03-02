import org.jasypt.util.password.StrongPasswordEncryptor;

public class _0150_PBK_Jasypt {

    public static void main(String[] args) {
        long WARMUP = 1;
        String plainPassword = "A_Simple_Password";
        long start, end;

        StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

        for (int i = 0; i < WARMUP; i++) {
            passwordEncryptor.encryptPassword("");
        }

        start = System.nanoTime();
        String encryptedPassword = passwordEncryptor.encryptPassword(plainPassword);
        end = System.nanoTime();
        System.out.printf("encryptPassword() took %f seconds.\n", (end - start) / 1E9);


        System.out.println(encryptedPassword);

        for (int i = 0; i < WARMUP; i++) {
            passwordEncryptor.checkPassword("", encryptedPassword);
        }

        start = System.nanoTime();
        boolean matches = passwordEncryptor.checkPassword("Alaki", encryptedPassword);
        end = System.nanoTime();
        System.out.printf("checkPassword() took %f seconds.\n", (end - start) / 1E9);

        System.out.println(matches);

        matches = passwordEncryptor.checkPassword(plainPassword, encryptedPassword);
        System.out.println(matches);

    }
}
