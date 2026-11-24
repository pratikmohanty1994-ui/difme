package dev.difme.hsm;

import java.nio.file.Path;
import java.util.Properties;
import org.jpos.core.SimpleConfiguration;
import org.jpos.security.EncryptedPIN;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.jpos.security.jceadapter.JCESecurityModule;

/**
 * DIFME security module (ADR-026). Callers hold only keys encrypted under the module's master key (LMK) and get
 * cryptograms back; clear keys never leave the module. Everything goes through jPOS's {@link SMAdapter}, so a certified
 * payment HSM adapter replaces the software {@link JCESecurityModule} without caller changes. In production the LMK
 * file is written by the attested key release (Trustee + OpenBao) into memory-backed storage inside the TEE.
 */
public final class SecurityModule {
    private final SMAdapter<SecureDESKey> sm;
    private final DifmeSecurityModule ext; // DIFME extensions; null on a hardware HSM adapter that has them natively

    public SecurityModule(SMAdapter<SecureDESKey> sm) {
        this.sm = sm;
        this.ext = sm instanceof DifmeSecurityModule d ? d : null;
    }

    private DifmeSecurityModule ext() throws SMException {
        if (ext == null) throw new SMException("function not available on this security module");
        return ext;
    }

    // ---- key management (phase 0) -------------------------------------------------------------------------------

    /** Key ceremony for any key type (SMAdapter.TYPE_*): double-length key from clear components, under the LMK. */
    public SecureDESKey keyFromComponents(String type, String... clearHexComponents) throws SMException {
        return sm.formKEYfromClearComponents(SMAdapter.LENGTH_DES3_2KEY, type, clearHexComponents);
    }

    /** A new random double-length key of a type, under the LMK. */
    public SecureDESKey generateKey(String type) throws SMException {
        return sm.generateKey(SMAdapter.LENGTH_DES3_2KEY, type);
    }

    /** Key exchange: a key encrypted under a zone master key (ZMK) for another party, and back. */
    public byte[] exportKey(SecureDESKey key, SecureDESKey zmk) throws SMException { return sm.exportKey(key, zmk); }

    public SecureDESKey importKey(String type, byte[] underZmk, SecureDESKey zmk) throws SMException {
        return sm.importKey(SMAdapter.LENGTH_DES3_2KEY, type, underZmk, zmk, false);
    }

    // ---- PIN (phase 2) ----------------------------------------------------------------------------------------

    /** A PIN block (ISO 9564 format 0) encrypted under a ZPK, as received from a network or acquirer. */
    public static EncryptedPIN pinBlock(String hex, String pan) {
        return new EncryptedPIN(hex, SMAdapter.FORMAT01, pan, true);
    }

    /** Translates a PIN block from one zone PIN key to another (network to issuer), format 0 out. */
    public String translatePin(EncryptedPIN pinUnderZpk1, SecureDESKey zpk1, SecureDESKey zpk2) throws SMException {
        return org.jpos.iso.ISOUtil.hexString(sm.translatePIN(pinUnderZpk1, zpk1, zpk2, SMAdapter.FORMAT01).getPINBlock());
    }

    /** Visa PVV for a PIN arriving under a ZPK (PIN issuance / change). */
    public String pvv(EncryptedPIN pinUnderZpk, SecureDESKey zpk, SecureDESKey pvk, int pvki) throws SMException {
        return sm.calculatePVV(pinUnderZpk, zpk, pvk, null, pvki);
    }

    /** Online PIN verification, Visa PVV method. */
    public boolean verifyPvv(EncryptedPIN pinUnderZpk, SecureDESKey zpk, SecureDESKey pvk, int pvki, String pvv) throws SMException {
        return sm.verifyPVV(pinUnderZpk, zpk, pvk, null, pvki, pvv);
    }

    /** IBM 3624 offset for a PIN under a ZPK (DIFME extension). */
    public String ibm3624Offset(EncryptedPIN pinUnderZpk, String pan, SecureDESKey zpk, SecureDESKey pvk, String decimalisation, int start, int length)
            throws SMException {
        return ext().ibm3624Offset(sm.importPIN(pinUnderZpk, zpk), pan, pvk, decimalisation, start, length);
    }

    public boolean verifyIbm3624Offset(EncryptedPIN pinUnderZpk, String pan, SecureDESKey zpk, SecureDESKey pvk, String decimalisation, int start,
            int length, String offset) throws SMException {
        return ibm3624Offset(pinUnderZpk, pan, zpk, pvk, decimalisation, start, length).equals(offset);
    }

    // ---- chip (phase 3) ---------------------------------------------------------------------------------------

    /** Chip cryptogram profiles: master-key derivation, session-key derivation and ARPC method per scheme CVN. */
    public enum Cvn {
        // Visa CVN 10: card master key as session key, zero padding (jPOS's MAC default), ARPC method 1
        VISA_10(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.VSDC, org.jpos.security.ARPCMethod.METHOD_1, false, org.jpos.security.SKDMethod.VSDC),
        // Visa CVN 18: EMV common session key from the ATC, ISO 9797 method 2 padding, ARPC method 2 (CSU)
        VISA_18(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.EMV_CSKD, org.jpos.security.ARPCMethod.METHOD_2, true, org.jpos.security.SKDMethod.VSDC),
        // Visa CVN 22: master key option B, common session keys for AC and secure messaging, method 2 padding, ARPC method 2
        VISA_22(org.jpos.security.MKDMethod.OPTION_B, org.jpos.security.SKDMethod.EMV_CSKD, org.jpos.security.ARPCMethod.METHOD_2, true, org.jpos.security.SKDMethod.EMV_CSKD),
        // Mastercard M/Chip CVN 16: session key from ATC and unpredictable number, method 2 padding, ARPC method 1
        MASTERCARD_16(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.MCHIP, org.jpos.security.ARPCMethod.METHOD_1, true, org.jpos.security.SKDMethod.MCHIP),
        // Mastercard CVN 17: as 16, transaction data also carries the counters
        MASTERCARD_17(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.MCHIP, org.jpos.security.ARPCMethod.METHOD_1, true, org.jpos.security.SKDMethod.EMV_CSKD),
        // Mastercard CVN 20 / 21 (21 with counters): EMV common session keys for AC and ARPC, ARPC method 1
        MASTERCARD_20(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.EMV_CSKD, org.jpos.security.ARPCMethod.METHOD_1, true, org.jpos.security.SKDMethod.EMV_CSKD),
        MASTERCARD_21(org.jpos.security.MKDMethod.OPTION_A, org.jpos.security.SKDMethod.EMV_CSKD, org.jpos.security.ARPCMethod.METHOD_1, true, org.jpos.security.SKDMethod.EMV_CSKD);
        final org.jpos.security.MKDMethod mkd;
        final org.jpos.security.SKDMethod skd;
        final org.jpos.security.ARPCMethod arpc;
        final boolean method2Padding;
        final org.jpos.security.SKDMethod smSkd; // secure messaging session keys (Visa: from the ATC, also for CVN 18)
        Cvn(org.jpos.security.MKDMethod m, org.jpos.security.SKDMethod s, org.jpos.security.ARPCMethod a, boolean p, org.jpos.security.SKDMethod sm) {
            mkd = m; skd = s; arpc = a; method2Padding = p; smSkd = sm;
        }
        byte[] pad(byte[] d) {
            if (!method2Padding) return d;
            byte[] out = new byte[(d.length / 8 + 1) * 8];
            System.arraycopy(d, 0, out, 0, d.length);
            out[d.length] = (byte) 0x80;
            return out;
        }
    }

    /**
     * Verifies an ARQC and returns the ARPC (null when the ARQC is wrong). {@code arcOrCsu}: the response code for
     * method 1, the card status update for method 2. {@code upn}: the unpredictable number (tag 9F37).
     */
    public byte[] verifyArqcGenerateArpc(Cvn cvn, SecureDESKey imkAc, String pan, String psn, byte[] arqc, byte[] atc, byte[] upn, byte[] txnData,
            byte[] arcOrCsu) throws SMException {
        return sm.verifyARQCGenerateARPC(cvn.mkd, cvn.skd, imkAc, pan, psn, arqc, atc, upn, cvn.pad(txnData), cvn.arpc, arcOrCsu, null);
    }

    private static byte[] scriptMacInput(byte[] command, byte[] atc, byte[] arqc) {
        byte[] out = new byte[5 + atc.length + arqc.length + command.length - 5];
        System.arraycopy(command, 0, out, 0, 5);
        System.arraycopy(atc, 0, out, 5, atc.length);
        System.arraycopy(arqc, 0, out, 5 + atc.length, arqc.length);
        System.arraycopy(command, 5, out, 5 + atc.length + arqc.length, command.length - 5);
        return out;
    }

    /** Issuer script MAC (secure messaging integrity) over the script command, keyed from the card's MK-SMI. */
    public byte[] scriptMac(Cvn cvn, SecureDESKey imkSmi, String pan, String psn, byte[] atc, byte[] arqc, byte[] command) throws SMException {
        // MAC input per EMV: command header || ATC || ARQC || command data (jPOS MACs what it is given)
        return sm.generateSM_MAC(cvn.mkd, cvn.smSkd, imkSmi, pan, psn, atc, arqc, scriptMacInput(command, atc, arqc));
    }

    /**
     * Offline PIN change script: the new PIN (arriving under a ZPK) re-encrypted for the card under its MK-SMC session
     * key, with the script MAC. Returns the encrypted PIN data and the MAC.
     */
    public org.javatuples.Pair<EncryptedPIN, byte[]> pinChangeScript(Cvn cvn, SecureDESKey imkSmi, SecureDESKey imkSmc, SecureDESKey imkAc, String pan,
            String psn, byte[] atc, byte[] arqc, byte[] command, EncryptedPIN newPinUnderZpk, SecureDESKey zpk) throws SMException {
        return sm.translatePINGenerateSM_MAC(cvn.mkd, cvn.smSkd, org.jpos.security.PaddingMethod.VSDC, imkSmi, pan, psn, atc, arqc, scriptMacInput(command, atc, arqc), null,
                newPinUnderZpk, zpk, imkSmc, imkAc, SMAdapter.FORMAT41);
    }

    /** Mastercard CVC3 (contactless magstripe): track template, ATC and unpredictable number with the card's CVC3 key. */
    public boolean verifyCvc3(SecureDESKey imkCvc3, String pan, String psn, byte[] atc, byte[] upn, byte[] trackTemplate, String cvc3) throws SMException {
        return sm.verifyCVC3(imkCvc3, pan, psn, atc, upn, trackTemplate, org.jpos.security.MKDMethod.OPTION_A, cvc3);
    }

    /** DUKPT (ANSI X9.24-1, TDES): a PIN block from a terminal, identified by its KSN, translated to a ZPK. */
    public String translateDukptPin(byte[] pinBlockUnderDuk, String pan, String ksnHex, SecureDESKey bdk, SecureDESKey zpk) throws SMException {
        EncryptedPIN in = new EncryptedPIN(pinBlockUnderDuk, SMAdapter.FORMAT01, pan, true);
        org.jpos.security.KeySerialNumber ksn = new org.jpos.security.KeySerialNumber(org.jpos.iso.ISOUtil.hex2byte(ksnHex));
        return org.jpos.iso.ISOUtil.hexString(sm.translatePIN(in, ksn, bdk, zpk, SMAdapter.FORMAT01, true).getPINBlock());
    }

    // ---- AES (DIFME extensions: TR-31 version D key blocks under the module's KBPK) --------------------------------

    public String generateAesKey(String usage, int bytes) throws SMException { return ext().generateAesKey(usage, bytes); }

    public String aesKeyFromComponents(String usage, String... clearHex) throws SMException { return ext().aesKeyFromComponents(usage, clearHex); }

    public String translateIso4ToZpk(byte[] iso4, String pan, String aesPinKey, SecureDESKey zpk) throws SMException {
        return org.jpos.iso.ISOUtil.hexString(ext().translateIso4ToZpk(iso4, pan, aesPinKey, zpk).getPINBlock());
    }

    /** AES DUKPT (ANSI X9.24-3-2017): a format 4 PIN block from a terminal, by its 12-byte KSN, to format 0 under a ZPK. */
    public String translateDukptAesToZpk(byte[] iso4, String pan, byte[] ksn, String bdkKeyBlock, SecureDESKey zpk) throws SMException {
        return org.jpos.iso.ISOUtil.hexString(ext().translateDukptAesToZpk(iso4, pan, ksn, bdkKeyBlock, zpk).getPINBlock());
    }

    public String translateIso4ToZpkRejectWeak(byte[] iso4, String pan, String aesPinKey, SecureDESKey zpk) throws SMException {
        return org.jpos.iso.ISOUtil.hexString(ext().translateIso4ToZpkRejectWeak(iso4, pan, aesPinKey, zpk).getPINBlock());
    }

    public String[] generatePin(String pan, int length, SecureDESKey zpk, String aesPinKey) throws SMException {
        return ext().generatePin(pan, length, zpk, aesPinKey);
    }

    public byte[] translateZpkToIso4(EncryptedPIN pinUnderZpk, String pan, SecureDESKey zpk, String aesPinKey) throws SMException {
        return ext().translateZpkToIso4(pinUnderZpk, pan, zpk, aesPinKey);
    }

    /** One-time PIN reveal: the ISO 4 block under the AES PIN key, re-encrypted inside the module to the app's public key (JWE). */
    public String revealPinToApp(byte[] iso4, String pan, String aesPinKey, byte[] appSpki) throws SMException {
        return ext().revealPinToApp(iso4, pan, aesPinKey, appSpki);
    }

    public byte[] aesCmac(String macKey, byte[] data) throws SMException { return ext().aesCmac(macKey, data); }

    // ---- issuer RSA key and personalisation (DIFME extension) ---------------------------------------------------

    public String[] generateIssuerRsaKey(int bits) throws SMException { return ext().generateIssuerRsaKey(bits); }

    public PersoFile.Record persoRecord(int seq, String pan, String psn, String expiryYymm, String serviceCode, SecureDESKey imkAc, SecureDESKey imkSmi,
            SecureDESKey imkSmc, SecureDESKey cvk, String issuerKeyBlock, SecureDESKey kek, int iccBits, byte[] sad) throws SMException {
        return ext().persoRecord(seq, pan, psn, expiryYymm, serviceCode, imkAc, imkSmi, imkSmc, cvk, issuerKeyBlock, kek, iccBits, sad);
    }

    /** Static application data the ICC certificate binds: 5A (PAN), 5F24 (expiry, last day of the month), 5F34 (PSN). */
    public static byte[] staticApplicationData(String pan, String psn, String expiryYymm) {
        String p = pan.length() % 2 == 0 ? pan : pan + "F";
        java.time.YearMonth ym = java.time.YearMonth.of(2000 + Integer.parseInt(expiryYymm.substring(0, 2)), Integer.parseInt(expiryYymm.substring(2)));
        return org.jpos.iso.ISOUtil.hex2byte("5A" + String.format("%02X", p.length() / 2) + p + "5F2403" + expiryYymm + String.format("%02d", ym.lengthOfMonth())
                + "5F3401" + psn);
    }

    // ---- LMK rotation -------------------------------------------------------------------------------------------

    /** Loads the previous LMK and KBPK into the module for a rotation (attested release only, ADR-026). */
    public void setOldKeys(Path oldLmkFile, byte[] oldKbpk) throws SMException { ext().setOldKeys(oldLmkFile, oldKbpk); }

    /** jPOS {@code translateKeyFromOldLMK}: a DES key under the old LMK re-encrypted under the current LMK. */
    public SecureDESKey translateKeyFromOldLmk(SecureDESKey underOld) throws SMException { return sm.translateKeyFromOldLMK(underOld); }

    /** An AES/RSA key block under the old KBPK re-wrapped under the current KBPK. */
    public String translateFromOldKbpk(String block) throws SMException { return ext().translateFromOldKbpk(block); }

    /** jPOS {@code eraseOldLMK}: forgets the old LMK and KBPK. */
    public void eraseOldLmk() throws SMException { sm.eraseOldLMK(); }

    /** Sets the AES key block protection key (from the attested key release). */
    public void setKbpk(byte[] kbpk) throws SMException { ext().setKbpk(kbpk); }

    public String[] generateRsaSigningKey(String cn) throws SMException { return ext().generateRsaSigningKey(cn); }

    public String[] generateRsaEncryptionKey() throws SMException { return ext().generateRsaEncryptionKey(); }

    public byte[] rsaOaepDecrypt(String rsaKeyBlock, byte[] data) throws SMException { return ext().rsaOaepDecrypt(rsaKeyBlock, data); }

    public byte[] signPs256(String rsaKeyBlock, byte[] data) throws SMException { return ext().signPs256(rsaKeyBlock, data); }
    public byte[] signDigestRs256(String rsaKeyBlock, byte[] digest) throws SMException { return ext().signDigestRs256(rsaKeyBlock, digest); }
    public byte[] csr(String rsaKeyBlock, String certB64, String cn) throws SMException { return ext().csr(rsaKeyBlock, certB64, cn); }
    public String[] generateRsaCaKey(String cn) throws SMException { return ext().generateRsaCaKey(cn); }

    public byte[] hmacSha256(String macKeyBlock, byte[] data) throws SMException { return ext().hmacSha256(macKeyBlock, data); }

    public byte[] aesGcm(String dataKeyBlock, boolean encrypt, byte[] data, byte[] aad) throws SMException {
        return ext().aesGcm(dataKeyBlock, encrypt, data, aad);
    }

    public String dcvv2(SecureDESKey imkDcvv2, String pan, long step) throws SMException { return ext().dcvv2(imkDcvv2, pan, step); }

    public boolean verifyDcvv2(SecureDESKey imkDcvv2, String pan, long step, int window, String code) throws SMException {
        return ext().verifyDcvv2(imkDcvv2, pan, step, window, code);
    }

    /** ISO 9797-1 MAC algorithm 3 (retail MAC, method 2 padding) with a TAK/ZAK, for ISO 8583 message authentication. */
    public byte[] retailMac(SecureDESKey mak, byte[] data) throws SMException { return sm.generateCBC_MAC(data, mak); }

    /**
     * Verifies a retail MAC (ISO 9797-1 alg 3): the MAC is recomputed in the module and compared in constant time over
     * the bytes received, which may be truncated to its leftmost 4 to 8 bytes (ISO 8583 fields 64/128 carry 8).
     */
    public boolean verifyRetailMac(SecureDESKey mak, byte[] data, byte[] mac) throws SMException {
        return macEquals(retailMac(mak, data), mac, 4);
    }

    /** Verifies an AES-CMAC (NIST SP 800-38B), possibly truncated to its leftmost 8 to 16 bytes, in constant time. */
    public boolean verifyAesCmac(String macKey, byte[] data, byte[] mac) throws SMException {
        return macEquals(aesCmac(macKey, data), mac, 8);
    }

    /** Constant-time comparison of a received MAC with the leftmost bytes of the computed one. */
    static boolean macEquals(byte[] computed, byte[] received, int minLength) {
        if (received == null || received.length < minLength || received.length > computed.length)
            throw new IllegalArgumentException("MAC length " + (received == null ? 0 : received.length) + ": " + minLength + " to " + computed.length + " bytes");
        return java.security.MessageDigest.isEqual(java.util.Arrays.copyOf(computed, received.length), received);
    }

    /** Visa dCVV (contactless MSD): CVV over PAN, expiry, service code and ATC with the card's derived key. */
    public boolean verifyDcvv(SecureDESKey imkDcvv, String pan, String dcvv, String expiryYymm, String serviceCode, byte[] atc) throws SMException {
        return sm.verifydCVV(pan, imkDcvv, dcvv, expiryYymm, serviceCode, atc, org.jpos.security.MKDMethod.OPTION_A);
    }

    /** The software module on an LMK file; {@code rebuild} generates a fresh random LMK (tests and dev only). */
    public static SecurityModule software(Path lmk, boolean rebuild) throws SMException {
        Properties p = new Properties();
        p.setProperty("lmk", lmk.toString());
        p.setProperty("rebuildlmk", Boolean.toString(rebuild));
        p.setProperty("provider", "org.bouncycastle.jce.provider.BouncyCastleProvider"); // ISO 9797-1 MACs
        try {
            DifmeSecurityModule m = new DifmeSecurityModule();
            m.setConfiguration(new SimpleConfiguration(p));
            // AES key block protection key next to the LMK (same release path); generated with a rebuilt LMK
            Path aes = Path.of(lmk + ".aes");
            if (rebuild) {
                byte[] k = new byte[32];
                new java.security.SecureRandom().nextBytes(k);
                java.nio.file.Files.writeString(aes, java.util.HexFormat.of().formatHex(k));
            }
            if (java.nio.file.Files.exists(aes)) m.setKbpk(java.util.HexFormat.of().parseHex(java.nio.file.Files.readString(aes).trim()));
            return new SecurityModule(m);
        } catch (org.jpos.core.ConfigurationException | java.io.IOException e) {
            throw new SMException(e);
        }
    }

    /** Key ceremony: a double-length card verification key from clear components (XORed), returned under the LMK. */
    public SecureDESKey cvkFromComponents(String... clearHexComponents) throws SMException {
        return sm.formKEYfromClearComponents(SMAdapter.LENGTH_DES3_2KEY, SMAdapter.TYPE_CVK, clearHexComponents);
    }

    /** The key check value (first 6 hex digits of the key encrypting zeros), to identify a key without revealing it. */
    public String checkValue(SecureDESKey k) throws SMException {
        return org.jpos.iso.ISOUtil.hexString(sm.generateKeyCheckValue(k)).substring(0, 6);
    }

    /** A CVK as stored after the key ceremony: its encryption under the LMK, in hex. */
    public static SecureDESKey cvkUnderLmk(String hex) {
        if (hex == null || !hex.matches("[0-9A-Fa-f]{32}")) throw new IllegalArgumentException("HSM_CVK_UNDER_LMK: 32 hex digits");
        return new SecureDESKey(SMAdapter.LENGTH_DES3_2KEY, SMAdapter.TYPE_CVK, org.jpos.iso.ISOUtil.hex2byte(hex), null);
    }

    /** CVV2 / CVC2: the CVV algorithm on PAN, expiry (YYMM) and service code 000. */
    public String cvv2(String pan, String expiryYymm, SecureDESKey cvk) throws SMException {
        return sm.calculateCVD(pan, cvk, null, expiryYymm, "000");
    }

    public boolean verifyCvv2(String pan, String expiryYymm, SecureDESKey cvk, String cvv2) throws SMException {
        return sm.verifyCVD(pan, cvk, null, cvv2, expiryYymm, "000");
    }

    /** Magnetic-stripe CVV (service code from the track), for card-present flows. */
    public String cvv(String pan, String expiryYymm, String serviceCode, SecureDESKey cvk) throws SMException {
        return sm.calculateCVD(pan, cvk, null, expiryYymm, serviceCode);
    }

    /**
     * Visa CAVV (3-D Secure / network-token cryptogram, CVV-based method): {@code upn} the 4-digit unpredictable number,
     * {@code authrc} the authentication result code, {@code sfarc} the second-factor result code.
     */
    public String cavv(String pan, SecureDESKey cvk, String upn, String authrc, String sfarc) throws SMException {
        return sm.calculateCAVV(pan, cvk, upn, authrc, sfarc);
    }

    public boolean verifyCavv(String pan, SecureDESKey cvk, String cavv, String upn, String authrc, String sfarc) throws SMException {
        return sm.verifyCAVV(pan, cvk, cavv, upn, authrc, sfarc);
    }
}
