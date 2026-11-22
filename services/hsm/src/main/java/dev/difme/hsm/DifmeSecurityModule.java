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

    /** A PIN under a TDES ZPK, re-enciphered as an ISO 9564 format 4 block under an AES PIN key (app PIN set / reveal). */
    public byte[] translateZpkToIso4(EncryptedPIN pinUnderZpk, String pan, SecureDESKey zpk, String aesPinKeyBlock) throws SMException {
        String pin = decryptPIN(importPIN(pinUnderZpk, zpk));
        return Iso4.encipher(aes(aesPinKeyBlock, "P0"), pin, pan);
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
}
