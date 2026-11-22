package dev.difme.hsm;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES DUKPT, ANSI X9.24-3-2017 (host side): Initial Key from the BDK and the Initial Key ID (6.3.1, usage 8001),
 * transaction key by one derivation per set bit of the 32-bit counter, most significant first (usage 8000), and the
 * working keys from the transaction key (6.3.4; here the PIN encryption key, usage 1000). Derive_Key = AES-ECB of
 * the 16-byte derivation data (Table 2/3) under the parent key, one block per 128 bits, key block counter from 1.
 * Derived keys have the BDK's algorithm and length. The KSN is 12 bytes: 8-byte Initial Key ID (4-byte BDK ID,
 * 4-byte derivation ID) and the counter.
 *
 * <p>Every returned array is clear key material owned by the caller, who zeroes it; intermediate keys are zeroed
 * here. Package-private: only {@link DifmeSecurityModule} calls it, with keys it unwrapped from key blocks.
 */
final class AesDukpt {
    static final int USAGE_PIN_ENCRYPTION = 0x1000, USAGE_KEY_DERIVATION = 0x8000, USAGE_INITIAL_KEY = 0x8001;

    private AesDukpt() {}

    /** Accepts a 12-byte KSN whose counter a conforming device can use: non-zero, at most 16 bits set (X9.24-3 6.1). */
    static void checkKsn(byte[] ksn) {
        if (ksn == null || ksn.length != 12) throw new IllegalArgumentException("AES DUKPT KSN: 12 bytes");
        int bits = Integer.bitCount(counter(ksn));
        if (bits == 0 || bits > 16) throw new IllegalArgumentException("AES DUKPT KSN: counter zero or more than 16 bits set");
    }

    static int counter(byte[] ksn) {
        return (ksn[8] & 0xff) << 24 | (ksn[9] & 0xff) << 16 | (ksn[10] & 0xff) << 8 | ksn[11] & 0xff;
    }

    /** The device's Initial Key: Derive_Key(BDK, usage 8001, Initial Key ID). */
    static byte[] initialKey(byte[] bdk, byte[] ksn) {
        byte[] d = data(USAGE_INITIAL_KEY, bdk.length);
        System.arraycopy(ksn, 0, d, 8, 8);
        return derive(bdk, d);
    }

    /** The transaction key for the KSN's counter, from the Initial Key. */
    static byte[] transactionKey(byte[] ik, byte[] ksn) {
        checkKsn(ksn);
        int tc = counter(ksn), working = 0;
        byte[] key = ik.clone();
        for (int mask = 0x80000000; mask != 0; mask >>>= 1) {
            if ((tc & mask) == 0) continue;
            working |= mask;
            byte[] next = derive(key, tableThree(USAGE_KEY_DERIVATION, key.length, ksn, working));
            Arrays.fill(key, (byte) 0);
            key = next;
        }
        return key;
    }

    /** A working key of {@code usage} from the transaction key (6.3.4), e.g. {@link #USAGE_PIN_ENCRYPTION}. */
    static byte[] workingKey(byte[] tk, byte[] ksn, int usage) {
        return derive(tk, tableThree(usage, tk.length, ksn, counter(ksn)));
    }

    /** The PIN encryption key for this KSN from the BDK; intermediate keys are zeroed. */
    static byte[] pinKey(byte[] bdk, byte[] ksn) {
        checkKsn(ksn);
        byte[] ik = initialKey(bdk, ksn), tk = null;
        try {
            tk = transactionKey(ik, ksn);
            return workingKey(tk, ksn, USAGE_PIN_ENCRYPTION);
        } finally {
            Arrays.fill(ik, (byte) 0);
            if (tk != null) Arrays.fill(tk, (byte) 0);
        }
    }

    /** Table 3 derivation data: the derivation ID (KSN bytes 4-7) and a counter value. */
    private static byte[] tableThree(int usage, int keyLength, byte[] ksn, int tc) {
        byte[] d = data(usage, keyLength);
        System.arraycopy(ksn, 4, d, 8, 4);
        d[12] = (byte) (tc >>> 24); d[13] = (byte) (tc >>> 16); d[14] = (byte) (tc >>> 8); d[15] = (byte) tc;
        return d;
    }

    /** Version 01, key block counter 01, usage, algorithm (0002/0003/0004 AES-128/192/256), length in bits. */
    private static byte[] data(int usage, int keyLength) {
        int alg = switch (keyLength) { case 16 -> 2; case 24 -> 3; case 32 -> 4; default -> throw new IllegalArgumentException("AES DUKPT key: 16, 24 or 32 bytes"); };
        int bits = keyLength * 8;
        return new byte[] {1, 1, (byte) (usage >> 8), (byte) usage, 0, (byte) alg, (byte) (bits >> 8), (byte) bits, 0, 0, 0, 0, 0, 0, 0, 0};
    }

    private static byte[] derive(byte[] key, byte[] data) {
        byte[] out = new byte[key.length];
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            for (int i = 0; i < out.length; i += 16, data[1]++) {
                byte[] block = c.doFinal(data);
                System.arraycopy(block, 0, out, i, Math.min(16, out.length - i));
                Arrays.fill(block, (byte) 0);
            }
            return out;
        } catch (GeneralSecurityException e) {
            Arrays.fill(out, (byte) 0);
            throw new IllegalStateException(e);
        }
    }
}
