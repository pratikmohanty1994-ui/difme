package dev.difme.hsm;

import java.nio.file.Path;
import java.util.Properties;
import org.jpos.core.SimpleConfiguration;
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

    public SecurityModule(SMAdapter<SecureDESKey> sm) { this.sm = sm; }

    /** The software module on an LMK file; {@code rebuild} generates a fresh random LMK (tests and dev only). */
    public static SecurityModule software(Path lmk, boolean rebuild) throws SMException {
        Properties p = new Properties();
        p.setProperty("lmk", lmk.toString());
        p.setProperty("rebuildlmk", Boolean.toString(rebuild));
        try {
            JCESecurityModule m = new JCESecurityModule();
            m.setConfiguration(new SimpleConfiguration(p));
            return new SecurityModule(m);
        } catch (org.jpos.core.ConfigurationException e) {
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
