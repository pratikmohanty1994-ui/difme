package dev.difme.hsm;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * One-time PIN reveal to the cardholder's app (DIFME extension, ADR-026): the clear PIN exists only inside the module
 * and leaves it as a JWE (RFC 7516, compact serialisation) encrypted to the app's public key, so only the app's
 * key (in the phone's secure element / keystore) can read it.
 *
 * <ul>
 *   <li>RSA app key (2048 bits or more): {@code alg} RSA-OAEP-256, {@code enc} A256GCM.</li>
 *   <li>EC P-256 app key: {@code alg} ECDH-ES (direct key agreement, Concat KDF per RFC 7518 §4.6), {@code enc} A256GCM.</li>
 * </ul>
 * Plaintext: the PIN digits (ASCII). Protected header: {@code cty} "difme-pin" and {@code kid} = the last four PAN
 * digits, so the app can tell which card the PIN is for. Interoperates with jwcrypto (tests).
 */
public final class AppPinReveal {
    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();

    private AppPinReveal() {}

    /** Parses an X.509 SubjectPublicKeyInfo (DER) as an RSA or EC key and checks it is acceptable. */
    static PublicKey appKey(byte[] spki) {
        for (String alg : new String[] {"RSA", "EC"}) {
            PublicKey k;
            try {
                k = KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(spki));
            } catch (GeneralSecurityException e) {
                continue;
            }
            if (k instanceof RSAPublicKey r && r.getModulus().bitLength() < 2048) throw new IllegalArgumentException("app RSA key: at least 2048 bits");
            if (k instanceof ECPublicKey e && e.getParams().getCurve().getField().getFieldSize() != 256)
                throw new IllegalArgumentException("app EC key: P-256 only");
            return k;
        }
        throw new IllegalArgumentException("app key: X.509 SubjectPublicKeyInfo, RSA or EC P-256");
    }

    /** Encrypts {@code plaintext} to {@code appKey} as a compact JWE. */
    static String encrypt(PublicKey appKey, byte[] plaintext, String kid) throws GeneralSecurityException {
        byte[] cek, encryptedKey;
        String header;
        if (appKey instanceof RSAPublicKey) {
            cek = new byte[32];
            RNG.nextBytes(cek);
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.ENCRYPT_MODE, appKey, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            encryptedKey = c.doFinal(cek);
            header = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"cty\":\"difme-pin\",\"kid\":\"" + kid + "\"}";
        } else if (appKey instanceof ECPublicKey ec) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair eph = g.generateKeyPair();
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(eph.getPrivate());
            ka.doPhase(ec, true); // validates the app's point is on the curve
            byte[] z = ka.generateSecret();
            cek = concatKdf(z, "A256GCM", 256);
            Arrays.fill(z, (byte) 0);
            encryptedKey = new byte[0];
            ECPublicKey e = (ECPublicKey) eph.getPublic();
            header = "{\"alg\":\"ECDH-ES\",\"enc\":\"A256GCM\",\"cty\":\"difme-pin\",\"kid\":\"" + kid + "\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
                    + B64U.encodeToString(EmvPerso.unsigned(e.getW().getAffineX(), 32)) + "\",\"y\":\""
                    + B64U.encodeToString(EmvPerso.unsigned(e.getW().getAffineY(), 32)) + "\"}}";
        } else {
            throw new IllegalArgumentException("app key: RSA or EC");
        }
        try {
            String h = B64U.encodeToString(header.getBytes(StandardCharsets.UTF_8));
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            gcm.updateAAD(h.getBytes(StandardCharsets.US_ASCII));
            byte[] ct = gcm.doFinal(plaintext);
            byte[] body = Arrays.copyOf(ct, ct.length - 16), tag = Arrays.copyOfRange(ct, ct.length - 16, ct.length);
            return h + "." + B64U.encodeToString(encryptedKey) + "." + B64U.encodeToString(iv) + "." + B64U.encodeToString(body) + "."
                    + B64U.encodeToString(tag);
        } finally {
            Arrays.fill(cek, (byte) 0);
        }
    }

    /** NIST SP 800-56A Concat KDF with SHA-256 as JWA uses it (empty PartyUInfo / PartyVInfo). */
    static byte[] concatKdf(byte[] z, String algorithmId, int keyBits) throws GeneralSecurityException {
        byte[] alg = algorithmId.getBytes(StandardCharsets.US_ASCII);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] out = new byte[keyBits / 8];
        for (int counter = 1, off = 0; off < out.length; counter++, off += 32) {
            sha.reset();
            sha.update(int32(counter));
            sha.update(z);
            sha.update(int32(alg.length));
            sha.update(alg);
            sha.update(int32(0)); // PartyUInfo
            sha.update(int32(0)); // PartyVInfo
            sha.update(int32(keyBits)); // SuppPubInfo
            byte[] d = sha.digest();
            System.arraycopy(d, 0, out, off, Math.min(32, out.length - off));
        }
        return out;
    }

    private static byte[] int32(int v) { return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v}; }
}
