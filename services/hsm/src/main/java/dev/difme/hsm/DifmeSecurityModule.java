package dev.difme.hsm;

import java.security.Key;
import org.jpos.iso.ISOUtil;
import org.jpos.security.EncryptedPIN;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.jpos.security.jceadapter.JCESecurityModule;

/**
 * DIFME's extensions to jPOS's software security module, for functions jPOS lacks (see
 * docs/architecture/card-cryptography-plan.md, "ext"). Same rules as jPOS's: keys arrive and leave only under the
 * LMK; clear keys and PINs exist only inside these methods. Written so they could be contributed to jPOS (AGPL-3.0).
 */
public class DifmeSecurityModule extends JCESecurityModule {
    private byte[] kbpk; // AES-256 key block protection key: AES working keys exist only as TR-31 D blocks under it

    /** Sets the AES KBPK (released with the LMK by the attested key release). */
    public void setKbpk(byte[] kbpk) {
        if (kbpk == null || kbpk.length != 32) throw new IllegalArgumentException("KBPK: 32 bytes");
        this.kbpk = kbpk.clone();
    }

    private byte[] kbpk() throws SMException {
        if (kbpk == null) throw new SMException("no AES key block protection key loaded");
        return kbpk;
    }

    /** A new random AES key of {@code bytes} length as a TR-31 version D block; {@code usage} e.g. "P0" PIN, "M7" CMAC, "E0" EMV. */
    public String generateAesKey(String usage, int bytes) throws SMException {
        byte[] k = new byte[bytes];
        new java.security.SecureRandom().nextBytes(k);
        return Tr31.wrap(kbpk(), "D0000" + usage + "AE00E0000", k);
    }

    /** Key ceremony for an AES key: from clear components (XOR), as a key block. */
    public String aesKeyFromComponents(String usage, String... clearHex) throws SMException {
        byte[] k = null;
        for (String c : clearHex) {
            byte[] b = ISOUtil.hex2byte(c);
            if (k == null) k = b; else for (int i = 0; i < k.length; i++) k[i] ^= b[i];
        }
        return Tr31.wrap(kbpk(), "D0000" + usage + "AE00E0000", k);
    }

    private byte[] aes(String keyBlock, String usage) throws SMException {
        Tr31.Unwrapped u;
        try {
            u = Tr31.unwrap(kbpk(), keyBlock);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        if (!u.header().substring(5, 7).equals(usage)) throw new SMException("key block usage " + u.header().substring(5, 7) + ", need " + usage);
        return u.key();
    }

    /** ISO 9564 format 4 PIN block under an AES PIN key, translated to format 0 under a TDES ZPK (network side). */
    public EncryptedPIN translateIso4ToZpk(byte[] iso4, String pan, String aesPinKeyBlock, SecureDESKey zpk) throws SMException {
        String pin;
        try {
            pin = Iso4.decipher(aes(aesPinKeyBlock, "P0"), iso4, pan);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        EncryptedPIN underLmk = encryptPIN(pin, pan, true);
        return exportPIN(underLmk, zpk, FORMAT01);
    }

    /**
     * AES DUKPT (ANSI X9.24-3-2017): an ISO 9564 format 4 PIN block from a terminal, enciphered under the PIN
     * encryption key derived from the BDK key block ("B0") and the 12-byte KSN, translated to format 0 under a TDES
     * ZPK. The BDK, Initial Key, transaction key and PIN key exist in clear only inside this call and are zeroed.
     */
    public EncryptedPIN translateDukptAesToZpk(byte[] iso4, String pan, byte[] ksn, String bdkKeyBlock, SecureDESKey zpk) throws SMException {
        byte[] bdk = aes(bdkKeyBlock, "B0"), pinKey = null;
        String pin;
        try {
            pinKey = AesDukpt.pinKey(bdk, ksn);
            pin = Iso4.decipher(pinKey, iso4, pan);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        } finally {
            java.util.Arrays.fill(bdk, (byte) 0);
            if (pinKey != null) java.util.Arrays.fill(pinKey, (byte) 0);
        }
        EncryptedPIN underLmk = encryptPIN(pin, pan, true);
        return exportPIN(underLmk, zpk, FORMAT01);
    }

    /** Common PINs refused at PIN set and never generated (plus repeated digits and ascending/descending runs). */
    static final java.util.Set<String> COMMON = java.util.Set.of("1212", "2580", "0852", "1004", "2000", "6969", "1122", "1313", "4321", "1010",
            "7777", "2001", "1999", "2222", "5683", "0007", "1066", "2468", "1357", "0101");

    /** True for PINs a guesser tries first: all one digit, a straight ascending or descending run, or a common PIN. */
    public static boolean weakPin(String pin) {
        if (pin.chars().distinct().count() == 1 || COMMON.contains(pin)) return true;
        boolean up = true, down = true;
        for (int i = 1; i < pin.length(); i++) {
            int d = pin.charAt(i) - pin.charAt(i - 1);
            up &= d == 1 || d == -9;
            down &= d == -1 || d == 9;
        }
        return up || down;
    }

    /** As {@link #translateIso4ToZpk} but refuses weak PINs (app PIN set). */
    public EncryptedPIN translateIso4ToZpkRejectWeak(byte[] iso4, String pan, String aesPinKeyBlock, SecureDESKey zpk) throws SMException {
        String pin;
        try {
            pin = Iso4.decipher(aes(aesPinKeyBlock, "P0"), iso4, pan);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        if (weakPin(pin)) throw new WeakPin();
        return exportPIN(encryptPIN(pin, pan, true), zpk, FORMAT01);
    }

    /** A weak PIN was refused. */
    public static final class WeakPin extends SMException {
        WeakPin() { super("weak PIN"); }
    }

    /**
     * A random PIN generated in the module (weak PINs excluded): returned under the ZPK (for the PVV) and as an ISO 4
     * block under the app's AES PIN key (shown once in the app). The clear PIN never leaves this method.
     */
    public String[] generatePin(String pan, int length, SecureDESKey zpk, String aesPinKeyBlock) throws SMException {
        java.security.SecureRandom r = new java.security.SecureRandom();
        String pin;
        do {
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < length; i++) b.append(r.nextInt(10));
            pin = b.toString();
        } while (weakPin(pin));
        EncryptedPIN underZpk = exportPIN(encryptPIN(pin, pan, true), zpk, FORMAT01);
        byte[] app = Iso4.encipher(aes(aesPinKeyBlock, "P0"), pin, pan);
        return new String[] {ISOUtil.hexString(underZpk.getPINBlock()), ISOUtil.hexString(app)};
    }

    /** A PIN under a TDES ZPK, re-enciphered as an ISO 9564 format 4 block under an AES PIN key (app PIN set / reveal). */
    public byte[] translateZpkToIso4(EncryptedPIN pinUnderZpk, String pan, SecureDESKey zpk, String aesPinKeyBlock) throws SMException {
        String pin = decryptPIN(importPIN(pinUnderZpk, zpk));
        return Iso4.encipher(aes(aesPinKeyBlock, "P0"), pin, pan);
    }

    /**
     * One-time PIN reveal: a PIN held as an ISO 9564 format 4 block under the AES PIN key (as {@link #generatePin}
     * returns it) is deciphered here and leaves only as a JWE encrypted to the app's public key ({@link AppPinReveal}).
     * {@code appSpki}: the app's X.509 SubjectPublicKeyInfo (RSA 2048+ or EC P-256).
     */
    public String revealPinToApp(byte[] iso4, String pan, String aesPinKeyBlock, byte[] appSpki) throws SMException {
        java.security.PublicKey app = AppPinReveal.appKey(appSpki); // IllegalArgumentException: caller's error
        byte[] k = aes(aesPinKeyBlock, "P0");
        byte[] pin = null;
        try {
            pin = Iso4.decipher(k, iso4, pan).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            return AppPinReveal.encrypt(app, pin, pan.substring(pan.length() - 4));
        } catch (IllegalArgumentException | java.security.GeneralSecurityException e) {
            throw new SMException("PIN reveal failed");
        } finally {
            java.util.Arrays.fill(k, (byte) 0);
            if (pin != null) java.util.Arrays.fill(pin, (byte) 0);
        }
    }

    /** AES-CMAC (NIST SP 800-38B) with a MAC key block, e.g. for ISO 8583 / ISO 20022 message authentication. */
    public byte[] aesCmac(String macKeyBlock, byte[] data) throws SMException {
        return Tr31.cmac(aes(macKeyBlock, "M7"), data);
    }

    /**
     * IBM 3624 PIN offset: natural PIN = decimalised 3DES(PVK, validation data), offset = (customer PIN - natural PIN)
     * digit-wise mod 10. Validation data: {@code pan.substring(start, start + length)} padded right with F to 16.
     */
    public String ibm3624Offset(EncryptedPIN pinUnderLmk, String pan, SecureDESKey pvk, String decimalisation, int start, int length) throws SMException {
        if (decimalisation == null || !decimalisation.matches("[0-9]{16}")) throw new SMException("decimalisation table: 16 digits");
        String pin = decryptPIN(pinUnderLmk);
        String vd = pan.substring(start, start + length);
        vd = (vd + "FFFFFFFFFFFFFFFF").substring(0, 16);
        Key k = decryptFromLMK(pvk);
        byte[] enc;
        try {
            enc = jceHandler.encryptData(ISOUtil.hex2byte(vd), k);
        } catch (Exception e) {
            throw new SMException(e);
        }
        String h = ISOUtil.hexString(enc);
        StringBuilder off = new StringBuilder();
        for (int i = 0; i < pin.length(); i++) {
            int natural = decimalisation.charAt(Character.digit(h.charAt(i), 16)) - '0';
            off.append((pin.charAt(i) - '0' - natural + 10) % 10);
        }
        return off.toString();
    }

    /**
     * DIFME dCVV2 profile (no public scheme profile exists): a time-based 3-digit code for card-not-present payments.
     * Per-card key = EMV option A derivation of IMK-DCVV2 with PAN and PSN 00; code = CVV algorithm over the PAN, the
     * time step's digits 4-7 (from the right) in the expiry slot and its last 3 digits in the service-code slot.
     * {@code step} = seconds since the epoch / step length (300 s by default in card-issuer).
     */
    public String dcvv2(SecureDESKey imkDcvv2, String pan, long step) throws SMException {
        String panpsn = (pan + "00");
        panpsn = panpsn.substring(panpsn.length() - 16);
        try {
            Key card = deriveICCMasterKey(decryptFromLMK(imkDcvv2), ISOUtil.hex2byte(panpsn));
            return calculateCVD(pan, card, String.format("%04d", step / 1000 % 10000), String.format("%03d", step % 1000));
        } catch (Exception e) {
            throw e instanceof SMException s ? s : new SMException(e);
        }
    }

    /** Accepts the code for the current step and the {@code window} steps before it (clock skew, typing time). */
    public boolean verifyDcvv2(SecureDESKey imkDcvv2, String pan, long step, int window, String code) throws SMException {
        for (int i = 0; i <= window; i++) if (dcvv2(imkDcvv2, pan, step - i).equals(code)) return true;
        return false;
    }

    /** A new RSA-2048 signing key as a TR-31 D block ("S0", PKCS#8 inside) plus its self-signed certificate (DER). */
    public String[] generateRsaSigningKey(String commonName) throws SMException {
        try {
            java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            java.security.KeyPair kp = g.generateKeyPair();
            byte[] cert = SelfSigned.certificate(kp, commonName);
            return new String[] {Tr31.wrap(kbpk(), "D0000S0RN00E0000", kp.getPrivate().getEncoded()), java.util.Base64.getEncoder().encodeToString(cert)};
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException(e);
        }
    }

    /** A new RSA-2048 encryption key as a TR-31 D block ("D1", PKCS#8 inside) plus its public key (X.509 SubjectPublicKeyInfo, base64). */
    public String[] generateRsaEncryptionKey() throws SMException {
        try {
            java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            java.security.KeyPair kp = g.generateKeyPair();
            return new String[] {Tr31.wrap(kbpk(), "D0000D1RN00E0000", kp.getPrivate().getEncoded()),
                    java.util.Base64.getEncoder().encodeToString(kp.getPublic().getEncoded())};
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException(e);
        }
    }

    /** RSA-OAEP with SHA-256 (JWE RSA-OAEP-256 key unwrap) with an encryption key block ("D1"). */
    public byte[] rsaOaepDecrypt(String rsaKeyBlock, byte[] data) throws SMException {
        Tr31.Unwrapped u;
        try {
            u = Tr31.unwrap(kbpk(), rsaKeyBlock);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        if (!u.header().substring(5, 7).equals("D1")) throw new SMException("not an encryption key");
        try {
            java.security.PrivateKey k = java.security.KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(u.key()));
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(javax.crypto.Cipher.DECRYPT_MODE, k, new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                    java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT));
            return c.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException("RSA-OAEP decryption failed");
        } finally {
            java.util.Arrays.fill(u.key(), (byte) 0);
        }
    }

    /** RSASSA-PSS with SHA-256 (JWS PS256) with a signing key block; the key exists in clear only inside this call. */
    public byte[] signPs256(String rsaKeyBlock, byte[] data) throws SMException {
        Tr31.Unwrapped u;
        try {
            u = Tr31.unwrap(kbpk(), rsaKeyBlock);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        if (!u.header().substring(5, 7).equals("S0")) throw new SMException("not a signing key");
        try {
            java.security.PrivateKey k = java.security.KeyFactory.getInstance("RSA").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(u.key()));
            java.security.Signature sig = java.security.Signature.getInstance("RSASSA-PSS");
            sig.setParameter(new java.security.spec.PSSParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
            sig.initSign(k);
            sig.update(data);
            return sig.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException(e);
        } finally {
            java.util.Arrays.fill(u.key(), (byte) 0);
        }
    }

    /** HMAC-SHA-256 with a MAC key block ("M7"): card references and passcode hashes for the ACS. */
    public byte[] hmacSha256(String macKeyBlock, byte[] data) throws SMException {
        byte[] k = aes(macKeyBlock, "M7");
        try {
            javax.crypto.Mac m = javax.crypto.Mac.getInstance("HmacSHA256");
            m.init(new javax.crypto.spec.SecretKeySpec(k, "HmacSHA256"));
            return m.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException(e);
        } finally {
            java.util.Arrays.fill(k, (byte) 0);
        }
    }

    /** AES-256-GCM with a data key block ("D0"): the card vault's PAN encryption. Output: 12-byte IV || ciphertext || tag. */
    public byte[] aesGcm(String dataKeyBlock, boolean encrypt, byte[] data, byte[] aad) throws SMException {
        byte[] k = aes(dataKeyBlock, "D0");
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            if (encrypt) {
                byte[] iv = new byte[12];
                new java.security.SecureRandom().nextBytes(iv);
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(k, "AES"), new javax.crypto.spec.GCMParameterSpec(128, iv));
                if (aad != null) c.updateAAD(aad);
                byte[] ct = c.doFinal(data);
                byte[] out = java.util.Arrays.copyOf(iv, 12 + ct.length);
                System.arraycopy(ct, 0, out, 12, ct.length);
                return out;
            }
            if (data.length < 28) throw new SMException("ciphertext too short");
            c.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(k, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, java.util.Arrays.copyOf(data, 12)));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(data, 12, data.length - 12);
        } catch (java.security.GeneralSecurityException e) {
            throw new SMException("data decryption failed");
        } finally {
            java.util.Arrays.fill(k, (byte) 0);
        }
    }

    // ---- LMK / KBPK rotation (jPOS's software module declares translateKeyFromOldLMK but does not implement it) ----

    private DifmeSecurityModule oldLmk; // the previous LMK, loaded only for a rotation drill
    private byte[] oldKbpk;

    /** Loads the previous LMK (file, jPOS format) and KBPK for {@link #translateKeyFromOldLMK} / {@link #translateFromOldKbpk}. */
    public void setOldKeys(java.nio.file.Path oldLmkFile, byte[] oldKbpk) throws SMException {
        try {
            DifmeSecurityModule m = new DifmeSecurityModule();
            java.util.Properties p = new java.util.Properties();
            p.setProperty("lmk", oldLmkFile.toString());
            p.setProperty("rebuildlmk", "false");
            p.setProperty("provider", "org.bouncycastle.jce.provider.BouncyCastleProvider");
            m.setConfiguration(new org.jpos.core.SimpleConfiguration(p));
            this.oldLmk = m;
        } catch (org.jpos.core.ConfigurationException e) {
            throw new SMException(e);
        }
        if (oldKbpk != null) {
            if (oldKbpk.length != 32) throw new IllegalArgumentException("old KBPK: 32 bytes");
            this.oldKbpk = oldKbpk.clone();
        }
    }

    /** A key under the old LMK, re-encrypted under the current one (same type, length and check value). */
    @Override
    protected SecureDESKey translateKeyFromOldLMKImpl(SecureDESKey kd) throws SMException {
        if (oldLmk == null) throw new SMException("no old LMK loaded");
        Key clear = oldLmk.decryptFromLMK(kd);
        return encryptToLMK(kd.getKeyLength(), kd.getKeyType(), clear);
    }

    /** Forgets the old LMK and KBPK after a rotation; translations fail from then on. */
    @Override
    protected void eraseOldLMKImpl() {
        oldLmk = null;
        if (oldKbpk != null) java.util.Arrays.fill(oldKbpk, (byte) 0);
        oldKbpk = null;
    }

    /** A TR-31 key block under the old KBPK, re-wrapped under the current one with the same header. */
    public String translateFromOldKbpk(String block) throws SMException {
        if (oldKbpk == null) throw new SMException("no old KBPK loaded");
        Tr31.Unwrapped u;
        try {
            u = Tr31.unwrap(oldKbpk, block);
        } catch (IllegalArgumentException e) {
            throw new SMException(e.getMessage());
        }
        try {
            return Tr31.wrap(kbpk(), "D0000" + u.header().substring(5), u.key());
        } finally {
            java.util.Arrays.fill(u.key(), (byte) 0);
        }
    }

    /** The KBPK in a form for the key release store (bootstrap only, inside the TEE). */
    byte[] kbpkForRelease() throws SMException { return kbpk().clone(); }
}
