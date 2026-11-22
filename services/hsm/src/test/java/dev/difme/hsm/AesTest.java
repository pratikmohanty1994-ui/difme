package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
    void tr31VersionBInteroperatesWithPsec() {
        byte[] kbpk = H.parseHex("0123456789ABCDEFFEDCBA9876543210"), key = H.parseHex("1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A");
        // psec.tr31.wrap(kbpk, "B0000P0TE00N0000", key)
        String psec = "B0096P0TE00N0000F53F51138D51E3317E7DC30C00C05633C21B0FFA3E1339C503D4D4FF81E1FD8E541DAC634C5DC2B2";
        assertArrayEquals(key, Tr31.unwrap(kbpk, psec).key());
        String ours = Tr31.wrap(kbpk, "B0000P0TE00N0000", key);
        assertEquals(96, ours.length());
        assertArrayEquals(key, Tr31.unwrap(kbpk, ours).key());
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
    void cardVaultEncryption() throws Exception {
        String k = hsm.generateAesKey("D0", 32);
        byte[] pan = "4375510000000001".getBytes(), aad = "card-1".getBytes();
        byte[] ct = hsm.aesGcm(k, true, pan, aad);
        assertArrayEquals(pan, hsm.aesGcm(k, false, ct, aad));
        assertThrows(SMException.class, () -> hsm.aesGcm(k, false, ct, "card-2".getBytes()), "other record");
        ct[20] ^= 1;
        assertThrows(SMException.class, () -> hsm.aesGcm(k, false, ct, aad), "tampered");
        assertThrows(SMException.class, () -> hsm.aesGcm(hsm.generateAesKey("M7", 32), true, pan, aad), "MAC key used for data");
    }

    @Test
    void rsaOaepKeyUnwrapForJwe() throws Exception {
        String[] kp = hsm.generateRsaEncryptionKey();
        java.security.PublicKey pub = java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(kp[1])));
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, pub, new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT));
        byte[] cek = H.parseHex("00112233445566778899AABBCCDDEEFF");
        assertArrayEquals(cek, hsm.rsaOaepDecrypt(kp[0], c.doFinal(cek)));
        assertThrows(SMException.class, () -> hsm.rsaOaepDecrypt(hsm.generateRsaSigningKey("x")[0], new byte[256]), "signing key used to decrypt");
    }

    @Test
    void weakPinsAreRefusedAndNeverGenerated() throws Exception {
        for (String w : new String[] {"1111", "1234", "4321", "7890", "0987", "2580", "123456", "999999"})
            assertTrue(DifmeSecurityModule.weakPin(w), w);
        for (String ok : new String[] {"2468x".substring(0, 0) + "3917", "8264", "590173"}) assertFalse(DifmeSecurityModule.weakPin(ok), ok);
        String key = "00112233445566778899AABBCCDDEEFF", pinKey = hsm.aesKeyFromComponents("P0", key);
        SecureDESKey zpk = hsm.keyFromComponents(SMAdapter.TYPE_ZPK, "1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A");
        byte[] weak = Iso4.encipher(H.parseHex(key), "1234", PAN);
        assertThrows(DifmeSecurityModule.WeakPin.class, () -> hsm.translateIso4ToZpkRejectWeak(weak, PAN, pinKey, zpk));
        assertEquals("EAEF33E33F471DA9", hsm.translateIso4ToZpk(weak, PAN, pinKey, zpk)); // without the check (network PINs)
        for (int i = 0; i < 20; i++) {
            String[] g = hsm.generatePin(PAN, 4, zpk, pinKey);
            String pin = Iso4.decipher(H.parseHex(key), H.parseHex(g[1]), PAN);
            assertFalse(DifmeSecurityModule.weakPin(pin), pin);
            // both forms carry the same PIN: the ZPK block re-enciphered for the app gives it back
            assertEquals(pin, Iso4.decipher(H.parseHex(key), hsm.translateZpkToIso4(SecurityModule.pinBlock(g[0], PAN), PAN, zpk, pinKey), PAN));
        }
    }

    @Test
    void cmacMatchesNistVectors() throws Exception {
        String k = hsm.aesKeyFromComponents("M7", "2B7E151628AED2A6ABF7158809CF4F3C");
        assertEquals("BB1D6929E95937287FA37D129B756746", H.formatHex(hsm.aesCmac(k, new byte[0])));
        assertEquals("070A16B46B4D4144F79BDD9DD04A287C", H.formatHex(hsm.aesCmac(k, H.parseHex("6BC1BEE22E409F96E93D7E117393172A"))));
    }
}
