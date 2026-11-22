package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import org.jpos.iso.ISOUtil;
import org.jpos.security.EncryptedPIN;
import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * PIN and chip functions against independent references computed with psec 1.x and pyemv 1.5 (MIT) for the same
 * keys and data (values in comments are the Python calls' results).
 */
class PinAndChipTest {
    static final String PAN = "4375510000000001";
    static final String KEY = "0123456789ABCDEFFEDCBA9876543210";
    static final String ZPK = "1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A";
    static SecurityModule hsm;
    static SecureDESKey zpk, pvk, imk;

    @BeforeAll
    static void setUp() throws Exception {
        hsm = SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
        zpk = hsm.keyFromComponents(SMAdapter.TYPE_ZPK, ZPK);
        pvk = hsm.keyFromComponents(SMAdapter.TYPE_PVK, KEY);
        imk = hsm.keyFromComponents(SMAdapter.TYPE_MK_AC, KEY);
    }

    // psec: encrypt_tdes_ecb(ZPK, encode_pinblock_iso_0("1234", PAN)) = EAEF33E33F471DA9
    static EncryptedPIN pin1234() { return SecurityModule.pinBlock("EAEF33E33F471DA9", PAN); }

    @Test
    void visaPvvMatchesPsec() throws Exception {
        assertEquals("0582", hsm.pvv(pin1234(), zpk, pvk, 1)); // psec generate_visa_pvv(KEY, "1", "1234", PAN)
        assertTrue(hsm.verifyPvv(pin1234(), zpk, pvk, 1, "0582"));
        assertFalse(hsm.verifyPvv(pin1234(), zpk, pvk, 1, "0583"));
    }

    @Test
    void ibm3624OffsetMatchesPsec() throws Exception {
        // psec generate_ibm3624_offset(KEY, "0123456789012345", "1234", PAN, 4, 12, "F") = 7985
        assertEquals("7985", hsm.ibm3624Offset(pin1234(), PAN, zpk, pvk, "0123456789012345", 4, 12));
        assertFalse(hsm.verifyIbm3624Offset(pin1234(), PAN, zpk, pvk, "0123456789012345", 4, 12, "7986"));
    }

    @Test
    void pinTranslationBetweenZonesKeepsThePin() throws Exception {
        SecureDESKey zpk2 = hsm.generateKey(SMAdapter.TYPE_ZPK);
        String under2 = hsm.translatePin(pin1234(), zpk, zpk2);
        assertTrue(hsm.verifyPvv(SecurityModule.pinBlock(under2, PAN), zpk2, pvk, 1, "0582"));
    }

    @Test
    void keyExchangeUnderAZmk() throws Exception {
        SecureDESKey zmk = hsm.generateKey(SMAdapter.TYPE_ZMK);
        byte[] out = hsm.exportKey(zpk, zmk);
        SecureDESKey back = hsm.importKey(SMAdapter.TYPE_ZPK, out, zmk);
        assertEquals(hsm.checkValue(zpk), hsm.checkValue(back));
        assertEquals("B292", hsm.checkValue(zpk).substring(0, 4)); // psec generate_kcv(ZPK)
    }

    static final String TXN = "000000012500000000000000035600000000000356261122001234567818000001";
    static final byte[] ATC = ISOUtil.hex2byte("0001"), UPN = ISOUtil.hex2byte("12345678");

    @Test
    void visaCvn10ArqcAndArpcMatchPyemv() throws Exception {
        byte[] arpc = hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.VISA_10, imk, PAN, "00", ISOUtil.hex2byte("D9ABDDB9BE215B12"), ATC, UPN,
                ISOUtil.hex2byte(TXN + "03A00000"), ISOUtil.hex2byte("3030"));
        assertArrayEquals(ISOUtil.hex2byte("C8FF4574A0EAB961"), arpc);
        assertNull(hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.VISA_10, imk, PAN, "00", ISOUtil.hex2byte("D9ABDDB9BE215B13"), ATC, UPN,
                ISOUtil.hex2byte(TXN + "03A00000"), ISOUtil.hex2byte("3030")));
    }

    @Test
    void visaCvn18ArqcAndArpcMatchPyemv() throws Exception {
        byte[] arpc = hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.VISA_18, imk, PAN, "00", ISOUtil.hex2byte("3875B6B0C1E9CCCD"), ATC, UPN,
                ISOUtil.hex2byte(TXN + "06011203A00000"), ISOUtil.hex2byte("00000000"));
        assertArrayEquals(ISOUtil.hex2byte("BDED80AB"), arpc);
    }

    @Test
    void mastercardCvn16ArqcAndArpcMatchPyemv() throws Exception {
        byte[] arpc = hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.MASTERCARD_16, imk, PAN, "00", ISOUtil.hex2byte("72A75147CCAFB6D0"), ATC, UPN,
                ISOUtil.hex2byte(TXN + "A00003220000"), ISOUtil.hex2byte("0010"));
        assertArrayEquals(ISOUtil.hex2byte("47006C9808C545B2"), arpc);
    }
}
