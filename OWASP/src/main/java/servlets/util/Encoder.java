package servlets.util;

import javax.xml.bind.DatatypeConverter;

public class Encoder {

    private static final Encoder instance = new Encoder();

    private Encoder() {
    }

    public static Encoder getInstance() {
        return instance;
    }

    public byte[] decodeFromBase64(String s) {
        return DatatypeConverter.parseBase64Binary(s);
    }



    public String encodeForHex(byte[] bytes){
        return HexUtil.toHex(bytes);
    }

    public byte[] decodeFormHex(String hex){
        return HexUtil.fromHex(hex);
    }


}
