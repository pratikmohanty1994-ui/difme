package dev.difme.hsm;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * TR-31 / ANSI X9.143 key blocks, version D (AES key block protection key, CMAC-derived encryption and MAC keys,
 * AES-CBC with the 16-byte MAC as IV). How DIFME stores and exchanges AES keys (the jPOS software module has no AES):
 * every AES working key is a key block wrapped under the module's KBPK. Interoperates with psec's tr31 (tests).
 */
public final class Tr31 {
    private static final HexFormat HEX = HexFormat.of().withUpperCase();
    private static final SecureRandom RNG = new SecureRandom();

    public record Unwrapped(String header, byte[] key) {}

    private Tr31() {}

    static byte[] cmac(byte[] key, byte[] data) {
        CMac m = new CMac(AESEngine.newInstance());
        m.init(new KeyParameter(key));
        m.update(data, 0, data.length);
        byte[] out = new byte[16];
        m.doFinal(out, 0);
        return out;
    }

    /** NIST SP 800-108 counter-mode KDF with AES-CMAC, as X9.143 specifies for version D. usage 0000 = encryption, 0001 = MAC. */
    static byte[] derive(byte[] kbpk, int usage) {
        int alg = switch (kbpk.length) { case 16 -> 2; case 24 -> 3; case 32 -> 4; default -> throw new IllegalArgumentException("KBPK length"); };
        int bits = kbpk.length * 8;
        byte[] out = new byte[kbpk.length];
        for (int i = 0, counter = 1; i < out.length; i += 16, counter++) {
            byte[] d = {(byte) counter, (byte) (usage >> 8), (byte) usage, 0, 0, (byte) alg, (byte) (bits >> 8), (byte) bits};
            byte[] block = cmac(kbpk, d);
            System.arraycopy(block, 0, out, i, Math.min(16, out.length - i));
        }
        return out;
    }

    /** Wraps {@code key} under {@code kbpk}; {@code header16} is the 16-character header without its length digits filled (they are set here). */
    public static String wrap(byte[] kbpk, String header16, byte[] key) {
        if (header16.length() != 16 || header16.charAt(0) != 'D') throw new IllegalArgumentException("version D header, 16 characters");
        // key-length masking (X9.143): pad as if the key were as long as the KBPK, so the block does not reveal it
        int padded = ((2 + Math.max(key.length, kbpk.length) + 15) / 16) * 16;
        byte[] payload = new byte[padded];
        payload[0] = (byte) ((key.length * 8) >> 8);
        payload[1] = (byte) (key.length * 8);
        System.arraycopy(key, 0, payload, 2, key.length);
        byte[] pad = new byte[padded - 2 - key.length];
        RNG.nextBytes(pad);
        System.arraycopy(pad, 0, payload, 2 + key.length, pad.length);
        int total = 16 + padded * 2 + 32;
        String header = header16.charAt(0) + String.format("%04d", total) + header16.substring(5);
        byte[] mac = cmac(derive(kbpk, 1), concat(header.getBytes(StandardCharsets.US_ASCII), payload));
        byte[] enc = aesCbc(Cipher.ENCRYPT_MODE, derive(kbpk, 0), mac, payload);
        return header + HEX.formatHex(enc) + HEX.formatHex(mac);
    }

    public static Unwrapped unwrap(byte[] kbpk, String block) {
        if (block.length() < 16 + 64 || block.charAt(0) != 'D') throw new IllegalArgumentException("not a version D key block");
        int total = Integer.parseInt(block.substring(1, 5));
        if (total != block.length()) throw new IllegalArgumentException("key block length mismatch");
        String header = block.substring(0, 16); // optional blocks are not used by DIFME
        byte[] enc = HEX.parseHex(block.substring(16, block.length() - 32));
        byte[] mac = HEX.parseHex(block.substring(block.length() - 32));
        byte[] payload = aesCbc(Cipher.DECRYPT_MODE, derive(kbpk, 0), mac, enc);
        byte[] expect = cmac(derive(kbpk, 1), concat(header.getBytes(StandardCharsets.US_ASCII), payload));
        if (!java.security.MessageDigest.isEqual(expect, mac)) throw new IllegalArgumentException("key block MAC invalid");
        int len = ((payload[0] & 0xff) << 8 | (payload[1] & 0xff)) / 8;
        return new Unwrapped(header, Arrays.copyOfRange(payload, 2, 2 + len));
    }

    static byte[] aesCbc(int mode, byte[] key, byte[] iv, byte[] data) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }
}
