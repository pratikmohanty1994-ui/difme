package dev.difme.hsm;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** ISO 9564-1 PIN block format 4 (AES): PIN field enciphered, XORed with the PAN field, enciphered again. */
final class Iso4 {
    private static final SecureRandom RNG = new SecureRandom();

    private Iso4() {}

    static byte[] pinField(String pin) {
        if (!pin.matches("[0-9]{4,12}")) throw new IllegalArgumentException("PIN: 4-12 digits");
        StringBuilder h = new StringBuilder("4").append(Integer.toHexString(pin.length())).append(pin);
        while (h.length() < 16) h.append('A');
        byte[] f = new byte[16];
        byte[] first = java.util.HexFormat.of().parseHex(h);
        System.arraycopy(first, 0, f, 0, 8);
        byte[] rnd = new byte[8];
        RNG.nextBytes(rnd);
        System.arraycopy(rnd, 0, f, 8, 8);
        return f;
    }

    static byte[] panField(String pan) {
        if (!pan.matches("[0-9]{1,19}")) throw new IllegalArgumentException("PAN: digits");
        int m = Math.max(0, pan.length() - 12);
        StringBuilder h = new StringBuilder().append(m).append(pan.length() < 12 ? "0".repeat(12 - pan.length()) + pan : pan);
        while (h.length() < 32) h.append('0');
        return java.util.HexFormat.of().parseHex(h);
    }

    static byte[] encipher(byte[] key, String pin, String pan) {
        byte[] a = aes(Cipher.ENCRYPT_MODE, key, pinField(pin));
        byte[] p = panField(pan);
        for (int i = 0; i < 16; i++) a[i] ^= p[i];
        return aes(Cipher.ENCRYPT_MODE, key, a);
    }

    static String decipher(byte[] key, byte[] block, String pan) {
        byte[] b = aes(Cipher.DECRYPT_MODE, key, block);
        byte[] p = panField(pan);
        for (int i = 0; i < 16; i++) b[i] ^= p[i];
        String h = java.util.HexFormat.of().withUpperCase().formatHex(aes(Cipher.DECRYPT_MODE, key, b));
        int len = Character.digit(h.charAt(1), 16);
        if (h.charAt(0) != '4' || len < 4 || len > 12 || !h.substring(2, 2 + len).matches("[0-9]+") || !h.substring(2 + len, 16).matches("A*"))
            throw new IllegalArgumentException("not a format 4 PIN block for this PAN");
        return h.substring(2, 2 + len);
    }

    private static byte[] aes(int mode, byte[] key, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(mode, new SecretKeySpec(key, "AES"));
            return c.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
