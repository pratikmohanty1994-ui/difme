package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.jpos.security.SecureDESKey;
import org.jpos.iso.ISOUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * jPOS's software security module against independent references: the published Visa CVV test vector, and values
 * computed with psec 1.x (MIT, {@code psec.cvv.generate_cvv}) for the same keys (ADR-026 requires every function to be
 * cross-checked). The LMK is random per run, so the keys below exist in clear only as test components.
 */
class SecurityModuleTest {
    // CVK 0123456789ABCDEF FEDCBA9876543210 split into two components (XOR), as at a key ceremony.
    static final String C1 = "1111111111111111FFFFFFFFFFFFFFFF", C2 = "1032547698BADCFE0123456789ABCDEF";
    static SecurityModule hsm;
    static SecureDESKey cvk;

    @BeforeAll
    static void setUp() throws Exception {
        Path dir = Files.createTempDirectory("hsm");
        hsm = SecurityModule.software(dir.resolve("lmk"), true);
        cvk = hsm.cvkFromComponents(C1, C2);
    }

    @Test
    void theKeyIsHeldOnlyUnderTheLmk() {
        String underLmk = ISOUtil.hexString(cvk.getKeyBytes());
        assertNotEquals("0123456789ABCDEFFEDCBA9876543210", underLmk);
        assertEquals(16, cvk.getKeyBytes().length);
    }

    @Test
    void publishedVisaCvvVector() throws Exception {
        assertEquals("561", hsm.cvv("4123456789012345", "8701", "101", cvk));
    }

    @ParameterizedTest
    @CsvSource({ "4375510000000001,3012,523", "5413330089020011,2705,748", "4895370000000013,3101,713" })
    void cvv2MatchesPsec(String pan, String expiry, String want) throws Exception {
        assertEquals(want, hsm.cvv2(pan, expiry, cvk));
        assertTrue(hsm.verifyCvv2(pan, expiry, cvk, want));
    }

    @Test
    void cvv2Rejections() throws Exception {
        assertFalse(hsm.verifyCvv2("4375510000000001", "3012", cvk, "524"), "wrong CVV2");
        assertFalse(hsm.verifyCvv2("4375510000000001", "3011", cvk, "523"), "wrong expiry");
        SecureDESKey other = hsm.cvkFromComponents("0123456789ABCDEF0123456789ABCDEF");
        assertFalse(hsm.verifyCvv2("4375510000000001", "3012", other, "523"), "another issuer's key");
    }

    @Test
    void magstripeCvvWithServiceCode() throws Exception {
        assertEquals("295", hsm.cvv("4375510000000019", "2911", "101", cvk));
    }

    @ParameterizedTest
    @CsvSource({ "4375510000000001,1234,0,00,675", "4895370000000013,9876,7,15,062" })
    void cavvMatchesPsec(String pan, String upn, String authrc, String sfarc, String want) throws Exception {
        assertEquals(want, hsm.cavv(pan, cvk, upn, authrc, sfarc));
        assertTrue(hsm.verifyCavv(pan, cvk, want, upn, authrc, sfarc));
        assertFalse(hsm.verifyCavv(pan, cvk, want, "0000", authrc, sfarc), "another unpredictable number");
    }

    @Test
    void theSameLmkFileReloads() throws Exception {
        Path dir = Files.createTempDirectory("hsm2");
        SecurityModule a = SecurityModule.software(dir.resolve("lmk"), true);
        SecureDESKey k = a.cvkFromComponents(C1, C2);
        SecurityModule b = SecurityModule.software(dir.resolve("lmk"), false);
        assertEquals("523", b.cvv2("4375510000000001", "3012", k));
    }
}
