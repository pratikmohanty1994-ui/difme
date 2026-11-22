package dev.difme.hsm;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * EMV card personalisation data (EMV 4.4 Book 2, DIFME extension: the jPOS software module only recovers these):
 * the Issuer Public Key Certificate (tag 90, format 02, signed by the scheme CA) and the ICC Public Key Certificate
 * (tag 9F46, format 04, signed by the issuer, binding the static application data). SHA-1 and RSA (indicators 01) as
 * EMV requires. Signing is raw RSA (EMV recovery format), done where the private key lives: the scheme CA key in tests
 * and the scheme simulator only; the issuer key inside the security module.
 */
public final class EmvPerso {
    private EmvPerso() {}

    /** A certificate (tag 90 / 9F46) and its public-key remainder (tag 92 / 9F48; empty when none). */
    public record Certificate(byte[] certificate, byte[] remainder, byte[] exponent) {}

    static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) System.arraycopy(b, b.length - len, out, 0, len);
        else System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }

    /** Leftmost digits of the PAN, BCD, right-padded with F to {@code bytes}. */
    static byte[] bcdF(String digits, int bytes) {
        StringBuilder h = new StringBuilder(digits);
        while (h.length() < bytes * 2) h.append('F');
        return java.util.HexFormat.of().parseHex(h.substring(0, bytes * 2));
    }

    private static byte[] sign(RSAPrivateKey signer, byte[] recovered) {
        int n = (signer.getModulus().bitLength() + 7) / 8;
        if (recovered.length != n) throw new IllegalArgumentException("certificate length must equal the signer's modulus length");
        return unsigned(new BigInteger(1, recovered).modPow(signer.getPrivateExponent(), signer.getModulus()), n);
    }

    private static byte[] build(RSAPrivateKey signer, byte format, byte[] identity, byte[] expiryMmyy, byte[] serial, RSAPublicKey subject,
            int fixedLen, byte[] extraHashed) {
        int n = (signer.getModulus().bitLength() + 7) / 8;
        byte[] mod = unsigned(subject.getModulus(), (subject.getModulus().bitLength() + 7) / 8);
        byte[] exp = subject.getPublicExponent().toByteArray();
        exp = exp[0] == 0 ? Arrays.copyOfRange(exp, 1, exp.length) : exp;
        int room = n - fixedLen;
        byte[] leftmost = new byte[room];
        Arrays.fill(leftmost, (byte) 0xBB);
        System.arraycopy(mod, 0, leftmost, 0, Math.min(room, mod.length));
        byte[] remainder = mod.length > room ? Arrays.copyOfRange(mod, room, mod.length) : new byte[0];
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(format);
        body.writeBytes(identity);
        body.writeBytes(expiryMmyy);
        body.writeBytes(serial);
        body.write(1); // hash algorithm: SHA-1
        body.write(1); // public key algorithm: RSA
        body.write(mod.length);
        body.write(exp.length);
        body.writeBytes(leftmost);
        byte[] hash;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(body.toByteArray());
            sha1.update(remainder);
            sha1.update(exp);
            if (extraHashed != null) sha1.update(extraHashed);
            hash = sha1.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(0x6A);
        rec.writeBytes(body.toByteArray());
        rec.writeBytes(hash);
        rec.write(0xBC);
        return sign(signer, rec.toByteArray());
    }

    /** Issuer Public Key Certificate (format 02): issuer identifier = leftmost 3-8 PAN digits (BIN). */
    public static Certificate issuerCertificate(RSAPrivateKey caKey, RSAPublicKey issuerKey, String bin, byte[] expiryMmyy, byte[] serial) {
        byte[] cert = build(caKey, (byte) 0x02, bcdF(bin, 4), expiryMmyy, serial, issuerKey, 36, null);
        return new Certificate(cert, remainder(caKey, issuerKey, 36), exponent(issuerKey));
    }

    /** ICC Public Key Certificate (format 04) binding the card's PAN and its static application data. */
    public static Certificate iccCertificate(RSAPrivateKey issuerKey, RSAPublicKey iccKey, String pan, byte[] expiryMmyy, byte[] serial,
            byte[] staticApplicationData) {
        byte[] cert = build(issuerKey, (byte) 0x04, bcdF(pan, 10), expiryMmyy, serial, iccKey, 42, staticApplicationData);
        return new Certificate(cert, remainder(issuerKey, iccKey, 42), exponent(iccKey));
    }

    private static byte[] remainder(RSAPrivateKey signer, RSAPublicKey subject, int fixed) {
        int room = (signer.getModulus().bitLength() + 7) / 8 - fixed;
        byte[] mod = unsigned(subject.getModulus(), (subject.getModulus().bitLength() + 7) / 8);
        return mod.length > room ? Arrays.copyOfRange(mod, room, mod.length) : new byte[0];
    }

    private static byte[] exponent(RSAPublicKey k) {
        byte[] e = k.getPublicExponent().toByteArray();
        return e[0] == 0 ? Arrays.copyOfRange(e, 1, e.length) : e;
    }
}
