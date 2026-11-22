package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.util.HexFormat;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * AES DUKPT (ANSI X9.24-3-2017) against an independent implementation: github.com/moov-io/dukpt v1.2.0 (Apache-2.0),
 * package pkg/aes. Values were computed with a throw-away Go program calling DerivationOfInitialKey,
 * DeriveCurrentTransactionKey and EncryptPin (ISO 9564 format 4 via moov-io/pinblock; random fill, so any valid
 * block) and DecryptPin to confirm. The AES-128 BDK, Initial Key ID and the Initial Key / counter 1 and 2
 * transaction keys are the X9.24-3-2017 Annex B.1 sample vectors (also in moov-io's aes_test.go). The AES-256 BDK is
 * an arbitrary test value. All keys here are public test values.
 */
class AesDukptTest {
    static final HexFormat H = HexFormat.of().withUpperCase();
    static final String PAN = "4375510000000001";
    static final String BDK128 = "FEDCBA9876543210F1F1F1F1F1F1F1F1"; // X9.24-3-2017 B.1
    static final String BDK256 = "FEDCBA9876543210F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1FEDCBA9876543210";
    static final String KSN1 = "123456789012345600000001", KSN2 = "123456789012345600000002", KSN_A5F31 = "1234567890123456000A5F31";
    // moov-io EncryptPin("1234", PAN) under BDK128 / KSN1, BDK128 / KSN_A5F31, BDK256 / KSN1
    static final String ISO4_128_1 = "21D817F973BBA46207CEFB526BDD1BFF", ISO4_128_A5F31 = "5F600DE064F3C5CD43B38A4F4F4BD53D",
            ISO4_256_1 = "9D7D6EEEB3D7C05C4E1AA5A0393E52E2";
    // moov-io EncryptPin("987654", PAN) under BDK256 / KSN_A5F31
    static final String ISO4_256_A5F31_987654 = "894C08BB9E55230E55496FA80088DA22";
    // PIN 1234 for PAN 4375510000000001 as ISO format 0 under the ZPK 1C1C…2A2A (psec, as in PinAndChipTest/AesTest)
    static final String ISO0_1234 = "EAEF33E33F471DA9";

    static SecurityModule hsm;
    static SecureDESKey zpk;

    @BeforeAll
    static void setUp() throws Exception {
        hsm = SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
        zpk = hsm.keyFromComponents(SMAdapter.TYPE_ZPK, PinAndChipTest.ZPK);
    }

    @Test
    void keyDerivationMatchesX924Part3Vectors() {
        byte[] bdk = H.parseHex(BDK128), ksn1 = H.parseHex(KSN1);
        byte[] ik = AesDukpt.initialKey(bdk, ksn1);
        assertEquals("1273671EA26AC29AFA4D1084127652A1", H.formatHex(ik));
        assertEquals("4F21B565BAD9835E112B6465635EAE44", H.formatHex(AesDukpt.transactionKey(ik, ksn1)));
        assertEquals("2F34D68DE10F68D38091A73B9E7C437C", H.formatHex(AesDukpt.transactionKey(ik, H.parseHex(KSN2))));
        assertEquals("E1EAC864084E5897C7A903C8BC5AC616", H.formatHex(AesDukpt.transactionKey(ik, H.parseHex(KSN_A5F31))));

        byte[] ik256 = AesDukpt.initialKey(H.parseHex(BDK256), ksn1);
        assertEquals("46F2EAFA83D46AD5C1799CF20115E75A173298509ABFB935E44D9E7AA9E1F1C3", H.formatHex(ik256));
        assertEquals("8FC190A00BA915730C2530958E33054567AFC548B334F08EF1CADF9604F9D145", H.formatHex(AesDukpt.transactionKey(ik256, ksn1)));
        assertEquals("8FD865A0F17AD26360C299CF73E8A417E1E029DC1127E4B9C3DA5283576A2E6B",
                H.formatHex(AesDukpt.transactionKey(ik256, H.parseHex(KSN_A5F31))));

        assertEquals("987654", Iso4.decipher(AesDukpt.pinKey(H.parseHex(BDK256), H.parseHex(KSN_A5F31)), H.parseHex(ISO4_256_A5F31_987654), PAN));
    }

    @Test
    void terminalPinBlocksTranslateToZpk() throws Exception {
        String bdk128 = hsm.aesKeyFromComponents("B0", BDK128), bdk256 = hsm.aesKeyFromComponents("B0", BDK256);
        assertEquals(ISO0_1234, hsm.translateDukptAesToZpk(H.parseHex(ISO4_128_1), PAN, H.parseHex(KSN1), bdk128, zpk));
        assertEquals(ISO0_1234, hsm.translateDukptAesToZpk(H.parseHex(ISO4_128_A5F31), PAN, H.parseHex(KSN_A5F31), bdk128, zpk));
        assertEquals(ISO0_1234, hsm.translateDukptAesToZpk(H.parseHex(ISO4_256_1), PAN, H.parseHex(KSN1), bdk256, zpk));
    }

    @Test
    void refusesWrongCounterWrongBdkTamperedBlockAndBadKeys() throws Exception {
        String bdk = hsm.aesKeyFromComponents("B0", BDK128);
        byte[] block = H.parseHex(ISO4_128_1), ksn1 = H.parseHex(KSN1);
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, H.parseHex(KSN2), bdk, zpk), "another counter");
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, H.parseHex("123456789012345700000001"), bdk, zpk),
                "another device (derivation ID)");
        String otherBdk = hsm.aesKeyFromComponents("B0", "0123456789ABCDEFFEDCBA9876543210");
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, ksn1, otherBdk, zpk), "another BDK");
        byte[] tampered = block.clone();
        tampered[5] ^= 0x01;
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(tampered, PAN, ksn1, bdk, zpk), "tampered block");
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, "4375510000000019", ksn1, bdk, zpk), "another PAN");
        // counters a device never uses: zero (would be the Initial Key itself), more than 16 bits set; KSN length
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, H.parseHex("123456789012345600000000"), bdk, zpk));
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, H.parseHex("12345678901234560001FFFF"), bdk, zpk));
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, H.parseHex("FFFF9876543210E00001"), bdk, zpk));
        // only a BDK key block ("B0") is accepted as a BDK
        String pinKey = hsm.aesKeyFromComponents("P0", BDK128);
        assertThrows(SMException.class, () -> hsm.translateDukptAesToZpk(block, PAN, ksn1, pinKey, zpk), "PIN key used as BDK");
    }
}
