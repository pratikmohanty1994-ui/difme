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

    @Test
    void issuerScriptMacsMatchPyemv() throws Exception {
        SecureDESKey smi = hsm.keyFromComponents(SMAdapter.TYPE_MK_SMI, KEY);
        // pyemv VisaCVN10.generate_command_mac(841E000004, ARQC, ATC) = 8CAB713A77715915 (block application)
        assertArrayEquals(ISOUtil.hex2byte("8CAB713A77715915"), hsm.scriptMac(SecurityModule.Cvn.VISA_10, smi, PAN, "00", ATC,
                ISOUtil.hex2byte("D9ABDDB9BE215B12"), ISOUtil.hex2byte("841E000004")));
        // pyemv VisaCVN18.generate_command_mac(...) = 8915C0D89FD214B5
        assertArrayEquals(ISOUtil.hex2byte("8915C0D89FD214B5"), hsm.scriptMac(SecurityModule.Cvn.VISA_18, smi, PAN, "00", ATC,
                ISOUtil.hex2byte("3875B6B0C1E9CCCD"), ISOUtil.hex2byte("841E000004")));
    }

    @Test
    void cvc3MatchesPyemv() throws Exception {
        SecureDESKey cvc3 = hsm.keyFromComponents(SMAdapter.TYPE_MK_CVC3, KEY);
        byte[] track = ISOUtil.hex2byte("4375510000000001D2812101000000000F");
        // pyemv generate_cvc3(derive_icc_mk_a(KEY, PAN, "00"), track, 0005, 00000899) = 37940
        assertTrue(hsm.verifyCvc3(cvc3, PAN, "00", ISOUtil.hex2byte("0005"), ISOUtil.hex2byte("00000899"), track, "37940"));
        assertFalse(hsm.verifyCvc3(cvc3, PAN, "00", ISOUtil.hex2byte("0006"), ISOUtil.hex2byte("00000899"), track, "37940"));
    }

    @Test
    void dukptPinFromATerminalMatchesTheX924Vector() throws Exception {
        // ANSI X9.24-1 test data: BDK 0123456789ABCDEFFEDCBA9876543210, KSN FFFF9876543210E00001, PAN 4012345678909,
        // PIN 1234 -> encrypted PIN block 1B9C1845EB993A7A
        SecureDESKey bdk = hsm.keyFromComponents(SMAdapter.TYPE_BDK, KEY);
        String underZpk = hsm.translateDukptPin(ISOUtil.hex2byte("1B9C1845EB993A7A"), "4012345678909", "FFFF9876543210E00001", bdk, zpk);
        // the same PIN block under our ZPK: psec encrypt_tdes_ecb(ZPK, encode_pinblock_iso_0("1234", "4012345678909"))
        assertEquals(REF_DUKPT_UNDER_ZPK, underZpk);
    }
    @Test
    void offlinePinChangeScriptMatchesPyemv() throws Exception {
        SecureDESKey smi = hsm.keyFromComponents(SMAdapter.TYPE_MK_SMI, KEY), smc = hsm.keyFromComponents(SMAdapter.TYPE_MK_SMC, KEY);
        // pyemv VisaCVN10.generate_pin_change_command("5678", ARQC, ATC) =
        // 8424000218 | ED5FEFA28F6313ADAAD4A9056B697BDB (PIN for the card) | 594DAD4E767AAE68 (MAC)
        var out = hsm.pinChangeScript(SecurityModule.Cvn.VISA_10, smi, smc, imk, PAN, "00", ATC, ISOUtil.hex2byte("D9ABDDB9BE215B12"),
                ISOUtil.hex2byte("8424000218"), SecurityModule.pinBlock("1E1B70C3FAA8AEB5", PAN), zpk);
        assertEquals("ED5FEFA28F6313ADAAD4A9056B697BDB", ISOUtil.hexString(out.getValue0().getPINBlock()));
        assertEquals("594DAD4E767AAE68", ISOUtil.hexString(out.getValue1()));
    }

    @Test
    void visaCvn22MatchesPyemv() throws Exception {
        SecureDESKey smi = hsm.keyFromComponents(SMAdapter.TYPE_MK_SMI, KEY);
        byte[] arqc = ISOUtil.hex2byte("729036126D3F8532");
        // pyemv VisaCVN22: ARQC 729036126D3F8532, ARPC (CSU 00000000) 83EA9433, script MAC (841E000004) B59095156E296B96
        assertArrayEquals(ISOUtil.hex2byte("83EA9433"), hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.VISA_22, imk, PAN, "00", arqc, ATC, UPN,
                ISOUtil.hex2byte(TXN + "1F42010103A00000"), ISOUtil.hex2byte("00000000")));
        assertArrayEquals(ISOUtil.hex2byte("B59095156E296B96"), hsm.scriptMac(SecurityModule.Cvn.VISA_22, smi, PAN, "00", ATC, arqc,
                ISOUtil.hex2byte("841E000004")));
    }

    static final String REF_DUKPT_UNDER_ZPK = "EE8E9B1F429DEA0F";
}
