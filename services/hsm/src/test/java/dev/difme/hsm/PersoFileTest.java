package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.jpos.security.EMVICCPublicKey;
import org.jpos.security.EMVIssuerPublicKey;
import org.jpos.security.SMAdapter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Issuer RSA key held in the module and the DIFME-PERSO/1 file, round trip: the file from /v1/perso/batch is parsed
 * and every item checked against an independent reference: ICC master keys against pyemv derive_icc_mk_a (TR-31 B
 * blocks unwrapped by psec.tr31 as well as here), iCVV against psec generate_cvv(…, "999"), the issuer and ICC
 * certificates by jPOS's EMV Book 2 recovery, the ICC private key against the certified public key.
 */
class PersoFileTest {
    static final String KEK = "1C1C1C1C1C1C1C1C2A2A2A2A2A2A2A2A";
    static HttpServer http;
    static String base;
    static SecurityModule hsm;
    static HsmServer.KeyStore keys;
    static EmvPerso.Certificate issuerCert;
    static Path dir;

    @BeforeAll
    static void setUp() throws Exception {
        dir = Files.createTempDirectory("perso");
        hsm = SecurityModule.software(dir.resolve("lmk"), true);
        keys = HsmServer.KeyStore.ceremony(hsm, "imk-ac=MK-AC:" + PinAndChipTest.KEY + ";imk-smi=MK-SMI:" + PinAndChipTest.KEY + ";imk-smc=MK-SMC:"
                + PinAndChipTest.KEY + ";cvk=CVK:" + SecurityModuleTest.C1 + "," + SecurityModuleTest.C2 + ";perso-kek=ZMK:" + KEK + ";zpk=ZPK:" + KEK
                + ";issuer-rsa=RSA-EMV/1408");
        // the scheme CA certifies the issuer public key (the private issuer key stays a TR-31 block under the KBPK)
        assertTrue(keys.rsa("issuer-rsa").startsWith("D") && keys.rsa("issuer-rsa").substring(5, 8).equals("S0R"));
        RSAPublicKey issuerPub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(keys.certs.get("issuer-rsa"))));
        assertEquals(1408, issuerPub.getModulus().bitLength());
        java.security.KeyPair ca = EmvPersoTest.rsa(1408);
        issuerCert = EmvPerso.issuerCertificate((java.security.interfaces.RSAPrivateKey) ca.getPrivate(), issuerPub, "437551",
                HexFormat.of().parseHex("1231"), HexFormat.of().parseHex("000007"));
        caKey = new org.jpos.security.EMVCAPublicKey(HexFormat.of().parseHex("A000000003"), (byte) 0x92,
                EmvPerso.unsigned(((RSAPublicKey) ca.getPublic()).getModulus(), 176), HexFormat.of().parseHex("010001"), (byte) 1, (byte) 1);
        jpos = new org.jpos.security.jceadapter.JCESecurityModule(); // independent of DIFME's code: jPOS's own Book 2 recovery
        java.util.Properties p = new java.util.Properties();
        p.setProperty("lmk", dir.resolve("lmk-jpos").toString());
        p.setProperty("rebuildlmk", "true");
        jpos.setConfiguration(new org.jpos.core.SimpleConfiguration(p));
        http = HsmServer.serve(new HsmServer(hsm, keys), "127.0.0.1:0");
        base = "http://127.0.0.1:" + http.getAddress().getPort();
    }

    @AfterAll
    static void stop() { http.stop(0); }

    static HttpResponse<String> batch(Map<String, String> extra) throws Exception {
        Map<String, String> m = new java.util.LinkedHashMap<>(Map.of("issuer", "437551", "cards", "4375510000000001:00:3012;4375510000000019:01:2911",
                "caIndex", "92", "issuerCert", HexFormat.of().formatHex(issuerCert.certificate()), "issuerRemainder", HexFormat.of().formatHex(issuerCert.remainder()),
                "issuerExponent", HexFormat.of().formatHex(issuerCert.exponent())));
        m.putAll(extra);
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(base + "/v1/perso/batch")).POST(HttpRequest.BodyPublishers.ofString(HsmServer.toJson(m))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    static String file() throws Exception {
        HttpResponse<String> r = batch(Map.of());
        assertEquals(200, r.statusCode(), r.body());
        return new String(Base64.getDecoder().decode(HsmServer.parse(r.body()).get("file")), StandardCharsets.UTF_8);
    }

    /** psec.tr31.unwrap with the clear KEK; null when Python/psec are absent. */
    static String psecUnwrap(String block) throws Exception {
        Path py = dir.resolve("unwrap.py");
        Files.writeString(py, "import sys, psec.tr31 as t\nh, k = t.unwrap(bytes.fromhex(sys.argv[1]), sys.argv[2])\nprint(h.key_usage, k.hex().upper())\n");
        try {
            Process p = new ProcessBuilder(List.of("python3", "-I", "-W", "ignore", py.toString(), KEK, block)).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            p.waitFor();
            return out.contains("No module named") ? null : out;
        } catch (java.io.IOException e) {
            return null;
        }
    }

    @Test
    void persoFileRoundTrip() throws Exception {
        String f = file();
        List<PersoFile.Record> recs = PersoFile.parse(f);
        PersoFile.Record hdr = recs.get(0);
        assertEquals(PersoFile.FORMAT, hdr.get("FORMAT"));
        assertEquals(hsm.checkValue(keys.des("perso-kek", SMAdapter.TYPE_ZMK)), hdr.get("KEK_KCV"));
        assertEquals("B292", hdr.get("KEK_KCV").substring(0, 4)); // psec generate_kcv(KEK)
        assertEquals(3, recs.size());
        String[][] ref = { // PAN, PSN, expiry, pyemv derive_icc_mk_a(KEY, PAN, PSN), psec generate_cvv(CVK, PAN, expiry, "999")
            {"4375510000000001", "00", "3012", "A440D0DFAB570D623780D573012626F7", "172"},
            {"4375510000000019", "01", "2911", "9B86B51A19768A91ABD36D52924FFDAB", "048"}};
        byte[] kek = HexFormat.of().parseHex(KEK);
        EMVIssuerPublicKey ipk = jpos.recoverIssuerPublicKey(caKeyFor(), HexFormat.of().parseHex(hdr.get("ISSUER_CERT")),
                HexFormat.of().parseHex(hdr.get("ISSUER_REM")), HexFormat.of().parseHex(hdr.get("ISSUER_EXP")), ref[0][0]);
        for (int i = 0; i < ref.length; i++) {
            PersoFile.Record c = recs.get(i + 1);
            assertEquals(ref[i][0], c.get("PAN"));
            assertEquals(ref[i][1], c.get("PSN"));
            assertEquals(ref[i][4], c.get("ICVV"), "iCVV (psec)");
            for (String[] mk : new String[][] {{"MK_AC", "E0"}, {"MK_SMI", "E2"}, {"MK_SMC", "E1"}}) {
                Tr31.Unwrapped u = Tr31.unwrap(kek, c.get(mk[0]));
                assertEquals(mk[1], u.header().substring(5, 7));
                assertEquals(ref[i][3], HexFormat.of().withUpperCase().formatHex(u.key()), mk[0] + " (pyemv)");
            }
            String psec = psecUnwrap(c.get("MK_AC"));
            if (psec != null) assertEquals("E0 " + ref[i][3], psec, "psec reads the TR-31 B block");
            // the ICC certificate recovers with jPOS and certifies the public half of ICC_KEY
            byte[] sad = HexFormat.of().parseHex(c.get("SAD"));
            assertArrayEquals(SecurityModule.staticApplicationData(ref[i][0], ref[i][1], ref[i][2]), sad);
            EMVICCPublicKey icc = jpos.recoverICCPublicKey(ipk, HexFormat.of().parseHex(c.get("ICC_CERT")), HexFormat.of().parseHex(c.get("ICC_REM")),
                    HexFormat.of().parseHex(c.get("ICC_EXP")), sad, ref[i][0]);
            Tr31.Unwrapped k = Tr31.unwrap(kek, c.get("ICC_KEY"));
            assertEquals("S0R", k.header().substring(5, 8));
            RSAPrivateCrtKey priv = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(k.key()));
            assertArrayEquals(EmvPerso.unsigned(priv.getModulus(), 128), icc.modulus());
            String psecIcc = psecUnwrap(c.get("ICC_KEY"));
            if (psecIcc != null) assertEquals("S0 " + HexFormat.of().withUpperCase().formatHex(k.key()), psecIcc, "psec reads the RSA key block");
        }
        if (psecUnwrap(recs.get(1).get("MK_AC")) == null) Assumptions.abort("psec not available for the TR-31 cross-check");
    }

    static org.jpos.security.EMVCAPublicKey caKeyFor() { return caKey; }

    static org.jpos.security.EMVCAPublicKey caKey;
    static org.jpos.security.jceadapter.JCESecurityModule jpos;

    @Test
    void refusalsAndIntegrity() throws Exception {
        String f = file();
        // tampered, truncated, reordered, trailer removed: refused
        assertThrows(IllegalArgumentException.class, () -> PersoFile.parse(f.replace("ICVV=172", "ICVV=173")));
        assertThrows(IllegalArgumentException.class, () -> PersoFile.parse(f.substring(0, f.length() - 10)));
        String[] l = f.split("\n");
        assertThrows(IllegalArgumentException.class, () -> PersoFile.parse(l[0] + "\n" + l[2] + "\n" + l[1] + "\n" + l[3] + "\n"));
        assertThrows(IllegalArgumentException.class, () -> PersoFile.parse(l[0] + "\n" + l[1] + "\n" + l[2] + "\n"));
        // another KEK cannot open the keys
        PersoFile.Record c = PersoFile.parse(f).get(1);
        assertThrows(IllegalArgumentException.class, () -> Tr31.unwrap(HexFormat.of().parseHex(PinAndChipTest.KEY), c.get("MK_AC")));
        // a non-ZMK as transport key, a bad card entry, a non-RSA issuer key: refused, no file
        assertEquals(400, batch(Map.of("kek", "zpk")).statusCode());
        assertEquals(400, batch(Map.of("cards", "4375510000000001:0:3012")).statusCode());
        assertEquals(400, batch(Map.of("issuerKey", "nope")).statusCode());
        assertEquals(400, batch(Map.of("iccBits", "4096")).statusCode());
        // the issuer key length is checked: 1984 max, multiple of 8
        assertThrows(IllegalArgumentException.class, () -> hsm.generateIssuerRsaKey(2048));
    }
}
