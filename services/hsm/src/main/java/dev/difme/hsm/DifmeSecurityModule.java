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
