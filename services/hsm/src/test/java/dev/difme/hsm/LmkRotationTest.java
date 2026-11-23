package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * LMK rotation drill over a whole key store (KeyRelease.rotate, as the attested-release rotation runs it): after the
 * rotation every key gives the same results as before, checked against the independent references the other tests use
 * (psec CVV2 / PVV / retail MAC / ISO 4, pyemv ARQC/ARPC, NIST CMAC), the key check values are unchanged and every
 * stored value is different. Negatives: keys under the old LMK do not work under the new one, the old LMK is erased,
 * a tampered key block, the wrong old LMK or the wrong old KBPK stop the rotation.
 */
class LmkRotationTest {
    static final String PAN = "4375510000000001";
    static final String SPEC = "cvk=CVK:" + SecurityModuleTest.C1 + "," + SecurityModuleTest.C2 + ";zpk=ZPK:" + PinAndChipTest.ZPK + ";pvk=PVK:"
            + PinAndChipTest.KEY + ";imk-ac=MK-AC:" + PinAndChipTest.KEY + ";tak=TAK:" + PinAndChipTest.KEY
            + ";aes-mac=AES/M7:2B7E151628AED2A6ABF7158809CF4F3C;aes-pin=AES/P0:00112233445566778899AABBCCDDEEFF;acs-sign=RSA;dcvv2=CVK";
    static Path dir;
    static SecurityModule old;
    static HsmServer.KeyStore oldKeys;
    static byte[] oldLmk, oldKbpk;
    static KeyRelease.Rotated r;

    @BeforeAll
    static void rotate() throws Exception {
        dir = Files.createTempDirectory("rotate");
        old = SecurityModule.software(dir.resolve("lmk"), true);
        oldKeys = HsmServer.KeyStore.ceremony(old, SPEC);
        oldLmk = Files.readAllBytes(dir.resolve("lmk"));
        oldKbpk = HexFormat.of().parseHex(Files.readString(dir.resolve("lmk.aes")).trim());
        r = KeyRelease.rotate(oldLmk, oldKbpk, oldKeys.toJson(), dir);
    }

    static void sameResults(SecurityModule hsm, HsmServer.KeyStore ks) throws Exception {
        assertEquals("523", hsm.cvv2(PAN, "3012", ks.des("cvk", SMAdapter.TYPE_CVK))); // psec
        assertEquals("0582", hsm.pvv(PinAndChipTest.pin1234(), ks.des("zpk", SMAdapter.TYPE_ZPK), ks.des("pvk", SMAdapter.TYPE_PVK), 1)); // psec
        assertEquals("D098DBA429F16895", ISOUtil.hexString(hsm.retailMac(ks.des("tak", SMAdapter.TYPE_TAK), "0200 DIFME ISO8583 MESSAGE".getBytes()))); // psec
        assertArrayEquals(ISOUtil.hex2byte("C8FF4574A0EAB961"), hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.VISA_10, ks.des("imk-ac", SMAdapter.TYPE_MK_AC),
                PAN, "00", ISOUtil.hex2byte("D9ABDDB9BE215B12"), PinAndChipTest.ATC, PinAndChipTest.UPN, ISOUtil.hex2byte(PinAndChipTest.TXN + "03A00000"),
                ISOUtil.hex2byte("3030"))); // pyemv
        assertEquals("070A16B46B4D4144F79BDD9DD04A287C", ISOUtil.hexString(hsm.aesCmac(ks.aes("aes-mac"), ISOUtil.hex2byte("6BC1BEE22E409F96E93D7E117393172A")))); // NIST
        assertEquals("EAEF33E33F471DA9", hsm.translateIso4ToZpk(ISOUtil.hex2byte("BCE34C548E471902740621E5DC1C6101"), PAN, ks.aes("aes-pin"),
                ks.des("zpk", SMAdapter.TYPE_ZPK))); // psec
        // the RSA signing key still matches its certificate
        var cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(java.util.Base64.getDecoder().decode(ks.certs.get("acs-sign"))));
        java.security.Signature v = java.security.Signature.getInstance("RSASSA-PSS");
        v.setParameter(new java.security.spec.PSSParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
        v.initVerify(cert.getPublicKey());
        v.update("jws".getBytes());
        assertTrue(v.verify(hsm.signPs256(ks.rsa("acs-sign"), "jws".getBytes())));
    }

    @Test
    void everyKeyGivesTheSameResultsAfterRotation() throws Exception {
        sameResults(old, oldKeys);
        sameResults(r.hsm(), r.keys());
        assertEquals(oldKeys.des.keySet(), r.keys().des.keySet());
        assertEquals(oldKeys.aes.keySet(), r.keys().aes.keySet());
        for (String l : oldKeys.des.keySet()) {
            SecureDESKey a = oldKeys.des.get(l), b = r.keys().des.get(l);
            assertEquals(old.checkValue(a), r.hsm().checkValue(b), l + " check value");
            assertEquals(a.getKeyType(), b.getKeyType());
            assertFalse(java.util.Arrays.equals(a.getKeyBytes(), b.getKeyBytes()), l + " re-encrypted");
        }
        for (String l : oldKeys.aes.keySet()) assertNotEquals(oldKeys.aes.get(l), r.keys().aes.get(l), l + " re-wrapped");
        assertNotEquals(oldKeys.rsa.get("acs-sign"), r.keys().rsa.get("acs-sign"));
        assertFalse(java.util.Arrays.equals(oldLmk, r.lmk()), "a new LMK");
        assertFalse(java.util.Arrays.equals(oldKbpk, r.kbpk()), "a new KBPK");
    }

    @Test
    void theNewGenerationReloadsAsAfterARestart() throws Exception {
        // what the next start reads from the new generation in the key release store
        SecurityModule restarted = KeyRelease.load(r.lmk(), r.kbpk(), dir);
        sameResults(restarted, HsmServer.KeyStore.load(r.keys().toJson()));
    }

    @Test
    void oldValuesDoNotWorkUnderTheNewLmkAndTheOldLmkIsErased() throws Exception {
        SecureDESKey cvkUnderOld = oldKeys.des("cvk", SMAdapter.TYPE_CVK);
        // decrypted under the wrong LMK the key fails jPOS's DES parity check
        assertThrows(Exception.class, () -> r.hsm().cvv2(PAN, "3012", cvkUnderOld), "a key under the old LMK used with the new");
        assertThrows(SMException.class, () -> r.hsm().aesCmac(oldKeys.aes("aes-mac"), new byte[16]), "a block under the old KBPK");
        assertThrows(SMException.class, () -> r.hsm().translateKeyFromOldLmk(cvkUnderOld), "old LMK erased after the rotation");
        assertThrows(SMException.class, () -> r.hsm().translateFromOldKbpk(oldKeys.aes("aes-mac")), "old KBPK erased");
    }

    @Test
    void aTamperedKeyBlockStopsTheRotation() throws Exception {
        String json = oldKeys.toJson();
        String block = oldKeys.aes.get("aes-pin");
        char[] t = block.toCharArray();
        t[40] = t[40] == '0' ? '1' : '0';
        assertThrows(SMException.class, () -> KeyRelease.rotate(oldLmk, oldKbpk, json.replace(block, new String(t)), dir));
    }

    @Test
    void theWrongOldLmkOrKbpkStopsTheRotation() throws Exception {
        Path other = Files.createTempDirectory("other");
        SecurityModule.software(other.resolve("lmk"), true);
        // keys decrypted under another LMK fail the DES parity check; blocks under another KBPK fail their MAC
        assertThrows(Exception.class, () -> KeyRelease.rotate(Files.readAllBytes(other.resolve("lmk")), oldKbpk, oldKeys.toJson(), dir));
        assertThrows(SMException.class, () -> KeyRelease.rotate(oldLmk, new byte[32], oldKeys.toJson(), dir));
    }

    @Test
    void generationsNameTheResourcesUnderTheCreateOnlyPolicy() {
        assertEquals("", KeyRelease.suffix(KeyRelease.generation(java.util.Map.of())));
        assertEquals("-g2", KeyRelease.suffix(KeyRelease.generation(java.util.Map.of("HSM_KEY_GENERATION", "2"))));
        assertEquals("", KeyRelease.suffix(1));
        assertThrows(IllegalArgumentException.class, () -> KeyRelease.generation(java.util.Map.of("HSM_KEY_GENERATION", "0")));
    }
}
