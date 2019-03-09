package servlets.util;



class HexUtil {
    private HexUtil() { }

    private static final char[] HEX_DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F'};

    private static final char BYTE_SEPARATOR = ' ';

    public static String toHex(final byte[] ba) {
        return toHex(ba, false);
    }

    public static String toHex(final byte[] ba, final boolean withSeparator) {
        return toHex(ba, 0, ba.length, withSeparator);
    }

    private static String toHex(final byte[] ba, final int offset, final int length, final boolean withSeparator) {
        final char[] buf;
        if (withSeparator) {
            buf = new char[length * 3];
        } else {
            buf = new char[length * 2];
        }
        for (int i = offset, j = 0; i < offset + length;) {
            final char[] chars = toHexChars(ba[i++]);
            buf[j++] = chars[0];
            buf[j++] = chars[1];
            if (withSeparator) {
                buf[j++] = BYTE_SEPARATOR;
            }
        }
        return new String(buf);
    }

    private static char[] toHexChars(final int b) {
        final char left = HEX_DIGITS[(b >>> 4) & 0x0F];
        final char right = HEX_DIGITS[b & 0x0F];
        return new char[]{left, right};
    }

    public static String toHex(final int b) {
        final char[] chars = toHexChars(b);
        return String.valueOf(chars);
    }
    public static String toHex(final byte b) {
        final char[] chars = toHexChars(b);
        return String.valueOf(chars);
    }

    public static byte[] fromHex(final char[] hex) {
        final int length = hex.length / 2;
        final byte[] raw = new byte[length];
        for (int i = 0; i < length; i++) {
            final int high = Character.digit(hex[i * 2], 16);
            final int low = Character.digit(hex[i * 2 + 1], 16);
            int value = (high << 4) | low;
            if (value > 127) {
                value -= 256;
            }
            raw[i] = (byte) value;
        }
        return raw;
    }

    public static byte[] fromHex(final String s) {
        return fromHex(s.replace(" ", "").toCharArray());
    }


}