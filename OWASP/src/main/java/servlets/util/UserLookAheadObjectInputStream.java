package servlets.util;

import models.User;

import java.io.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class UserLookAheadObjectInputStream extends ObjectInputStream {

    final List<String> validClasses = new ArrayList<String>() {{
        add(User.class.getName());
        add(String.class.getName());
        add(Timestamp.class.getName());
        add(Date.class.getName());
    }};

    public UserLookAheadObjectInputStream(InputStream inputStream)
            throws IOException {
        super(inputStream);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

        if (!validClasses.contains(desc.getName())) {
            throw new InvalidClassException(
                    "Unauthorized deserialization attempt",
                    desc.getName());
        }
        return super.resolveClass(desc);
    }

}