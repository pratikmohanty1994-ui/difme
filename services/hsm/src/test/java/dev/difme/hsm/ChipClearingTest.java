package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Files;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * TC / AAC verification at clearing with the ARQC function: the cryptograms were generated with pyemv 1.5
 * ({@code VisaCVN10/18}, {@code MasterCardCVN16/21} {@code .generate_ac}, IMK 0123…3210) for the transaction data a
 * clearing record carries in field 55. The same vectors drive card-issuer's field 55 parser test (chip_test.go).
 */
class ChipClearingTest {
    static SecurityModule hsm;
    static SecureDESKey imk;

    @BeforeAll
    static void setUp() throws Exception {
        hsm = SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
        imk = hsm.keyFromComponents(SMAdapter.TYPE_MK_AC, PinAndChipTest.KEY);
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource({
        "VISA_10, TC, 4375510000000001, 00, 0007, A1B2C3D4, 00000001250000000000000003560000000000035626112300A1B2C3D41800000703600000, FF42664AA283A57E, 3030",
        "VISA_18, TC, 4375510000000001, 00, 0012, 0BADF00D, 000000004999000000000000035600000080000356261123000BADF00D1800001206011203600000, C68C301A5BED545E, 00000000",
        "VISA_18, AAC, 4375510000000001, 00, 0013, 0BADF00E, 000000004999000000000000035680000480000356261123000BADF00E1800001306011203900000, 754FAC2DA51CD9CA, 00000000",
        "MASTERCARD_16, TC, 5413330089020011, 01, 002A, 12345679, 00000002000000000000000003560000000000035626112300123456791800002A600002000000, 98D4C3A7EB6ECDD4, 3030",
        "MASTERCARD_21, TC, 5413330089020011, 01, 002B, 1234567A, 000000020000000000000000035600000000000356261123001234567A1800002B6000020000000102030405060708, E41040D34850E815, 3030" })
    void clearingCryptogramsMatchPyemv(SecurityModule.Cvn cvn, String kind, String pan, String psn, String atc, String un, String txn, String ac,
            String arc) throws Exception {
        assertNotNull(hsm.verifyArqcGenerateArpc(cvn, imk, pan, psn, ISOUtil.hex2byte(ac), ISOUtil.hex2byte(atc), ISOUtil.hex2byte(un),
                ISOUtil.hex2byte(txn), ISOUtil.hex2byte(arc)), kind);
        // negatives: another amount in the clearing record, another ATC, another card sequence number
        String otherAmount = txn.substring(0, 11) + (txn.charAt(11) == '0' ? '1' : '0') + txn.substring(12);
        assertNull(hsm.verifyArqcGenerateArpc(cvn, imk, pan, psn, ISOUtil.hex2byte(ac), ISOUtil.hex2byte(atc), ISOUtil.hex2byte(un),
                ISOUtil.hex2byte(otherAmount), ISOUtil.hex2byte(arc)));
        // the ATC sits in the transaction data at hex offset 62 (CVN 10 uses it only there: no ATC session key)
        assertNull(hsm.verifyArqcGenerateArpc(cvn, imk, pan, psn, ISOUtil.hex2byte(ac), ISOUtil.hex2byte("0FFF"), ISOUtil.hex2byte(un),
                ISOUtil.hex2byte(txn.substring(0, 62) + "0FFF" + txn.substring(66)), ISOUtil.hex2byte(arc)));
        assertNull(hsm.verifyArqcGenerateArpc(cvn, imk, pan, psn.equals("00") ? "01" : "00", ISOUtil.hex2byte(ac), ISOUtil.hex2byte(atc),
                ISOUtil.hex2byte(un), ISOUtil.hex2byte(txn), ISOUtil.hex2byte(arc)));
    }
}
