package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.util.HexFormat;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** AES extensions against psec (TR-31 D, ISO 9564 format 4), NIST SP 800-38B CMAC vectors, and pyemv (Visa CVN 22). */
class AesTest {
    static final HexFormat H = HexFormat.of().withUpperCase();
    static final String PAN = "4375510000000001";
    static SecurityModule hsm;

    @BeforeAll
    static void setUp() throws Exception {
        hsm = SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
    }

    @Test
    void tr31VersionDInteroperatesWithPsec() {
        byte[] kbpk = H.parseHex("88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6");
        byte[] key = H.parseHex("00112233445566778899AABBCCDDEEFF");
        // psec.tr31.wrap(kbpk, "D0000P0AE00E0000", key)
        String psec = "D0144P0AE00E00004F9FFD9084BC8DFFCDB28C04798B4B3E213EF8C5BC006AB4C354A60874AA5A23B8E00B42EEEB13382D4D226E83B243D5DBEDE430E6C27B3D3467BBFEDB2C130E";
        Tr31.Unwrapped u = Tr31.unwrap(kbpk, psec);
        assertArrayEquals(key, u.key());
        assertEquals("D0144P0AE00E0000", u.header());
        String ours = Tr31.wrap(kbpk, "D0000P0AE00E0000", key);
        assertEquals(144, ours.length());
        assertArrayEquals(key, Tr31.unwrap(kbpk, ours).key());
        char[] t = psec.toCharArray();
        t[40] = t[40] == '0' ? '1' : '0';
        assertThrows(IllegalArgumentException.class, () -> Tr31.unwrap(kbpk, new String(t)), "tampered block");
    }

    @Test
    void iso4PinBlocksInteroperateWithPsecAndTranslateToZpk() throws Exception {
        String pinKey = hsm.aesKeyFromComponents("P0", "00112233445566778899AABBCCDDEEFF");
        SecureDESKey zpk = hsm.keyFromComponents(SMAdapter.TYPE_ZPK, "1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A");
        // psec.pinblock.encipher_pinblock_iso_4(key, "1234", PAN) (random fill: any valid block)
        String iso0 = hsm.translateIso4ToZpk(H.parseHex("BCE34C548E471902740621E5DC1C6101"), PAN, pinKey, zpk);
        assertEquals("EAEF33E33F471DA9", iso0); // the same PIN as ISO 0 under the ZPK (PinAndChipTest, psec)
        byte[] back = hsm.translateZpkToIso4(SecurityModule.pinBlock(iso0, PAN), PAN, zpk, pinKey);
        assertEquals("1234", Iso4.decipher(H.parseHex("00112233445566778899AABBCCDDEEFF"), back, PAN));
        assertThrows(SMException.class, () -> hsm.translateIso4ToZpk(H.parseHex("BCE34C548E471902740621E5DC1C6101"), "4375510000000019", pinKey, zpk),
                "another PAN");
        String macKey = hsm.aesKeyFromComponents("M7", "00112233445566778899AABBCCDDEEFF");
        assertThrows(SMException.class, () -> hsm.translateIso4ToZpk(new byte[16], PAN, macKey, zpk), "MAC key used as PIN key");
    }

    @Test
    void cmacMatchesNistVectors() throws Exception {
        String k = hsm.aesKeyFromComponents("M7", "2B7E151628AED2A6ABF7158809CF4F3C");
        assertEquals("BB1D6929E95937287FA37D129B756746", H.formatHex(hsm.aesCmac(k, new byte[0])));
        assertEquals("070A16B46B4D4144F79BDD9DD04A287C", H.formatHex(hsm.aesCmac(k, H.parseHex("6BC1BEE22E409F96E93D7E117393172A"))));
    }
}
