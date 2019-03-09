package servlets.util;

import java.io.*;

public class LookAheadDeserializer {
    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        byte[] buffer = baos.toByteArray();
        oos.close();
        baos.close();
        return buffer;
    }

    public static Object deserialize(InputStream bais) throws IOException,
            ClassNotFoundException {
//        ByteArrayInputStream bais = new ByteArrayInputStream();

        // We use LookAheadObjectInputStream instead of InputStream
        ObjectInputStream ois = new UserLookAheadObjectInputStream(bais);

        Object obj = ois.readObject();
        ois.close();
        bais.close();
        return obj;
    }
}
