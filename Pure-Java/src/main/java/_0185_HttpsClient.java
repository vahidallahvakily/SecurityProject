import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class _0185_HttpsClient {

    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream("C:/Tools/tomcat/conf/client.p12");
        ks.load(fis, "1".toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "1".toCharArray());
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), null, null);


        URL url = new URL("https://sadeq.com:8443/");
        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setSSLSocketFactory(sc.getSocketFactory());

        print_https_cert(con);
//        print_content(con);
    }

    private static void print_https_cert(HttpsURLConnection con) throws IOException {
        System.out.println("Response Code : " + con.getResponseCode());
        System.out.println("Cipher Suite : " + con.getCipherSuite());
        System.out.println("\n");

        Certificate[] certs = con.getServerCertificates();
        for (Certificate cert : certs) {
            System.out.println("Cert Type : " + cert.getType());
            System.out.println("Cert Hash Code : " + cert.hashCode());
            System.out.println("Cert Public Key Algorithm : "
                    + cert.getPublicKey().getAlgorithm());
            System.out.println("Cert Public Key Format : "
                    + cert.getPublicKey().getFormat());
            System.out.println("\n");
        }
    }

    @SuppressWarnings("unused")
    private static void print_content(HttpsURLConnection con) throws IOException {
        System.out.println("****** Content of the URL ********");
        BufferedReader br =
                new BufferedReader(
                        new InputStreamReader(con.getInputStream()));

        String input;

        while ((input = br.readLine()) != null) {
            System.out.println(input);
        }
        br.close();

    }

}
