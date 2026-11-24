package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.Map;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMAdapter;
import org.jpos.security.SecureDESKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The HTTP interface: CAVV and CVV2 values as in SecurityModuleTest (psec), validation, no key material out. */
class HsmServerTest {
    static final String ILP_KEY = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    static HttpServer http;
    static String base;
    static final HttpClient C = HttpClient.newHttpClient();

    @BeforeAll
    static void start() throws Exception {
        SecurityModule hsm = SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
        SecureDESKey formed = hsm.cvkFromComponents(SecurityModuleTest.C1, SecurityModuleTest.C2);
        // as deployed: the CVK arrives as its LMK encryption in hex
        SecureDESKey cvk = SecurityModule.cvkUnderLmk(ISOUtil.hexString(formed.getKeyBytes()));
        assertEquals(hsm.checkValue(formed), hsm.checkValue(cvk));
        HsmServer.KeyStore keys = new HsmServer.KeyStore().put("cvk", cvk)
                .put("zpk", hsm.keyFromComponents(SMAdapter.TYPE_ZPK, PinAndChipTest.ZPK))
                .put("pvk", hsm.keyFromComponents(SMAdapter.TYPE_PVK, PinAndChipTest.KEY))
                .put("imk-ac", hsm.keyFromComponents(SMAdapter.TYPE_MK_AC, PinAndChipTest.KEY))
                .putAes("aes-pin", hsm.aesKeyFromComponents("P0", "00112233445566778899AABBCCDDEEFF"))
                .putAes("bdk-aes", hsm.aesKeyFromComponents("B0", AesDukptTest.BDK128))
                .put("tak", hsm.keyFromComponents(SMAdapter.TYPE_TAK, PinAndChipTest.KEY))
                .putAes("aes-mac", hsm.aesKeyFromComponents("M7", "2B7E151628AED2A6ABF7158809CF4F3C"))
                .putAes("ilp-difme", hsm.aesKeyFromComponents("M7", ILP_KEY));
        String[] ca = hsm.generateRsaCaKey("DIFME Card Scheme Root CA");
        String[] acs = hsm.generateRsaSigningKey("DIFME acs-sign (dev)");
        keys.putRsa("scheme-ca", ca[0], ca[1]).putRsa("acs-sign", acs[0], acs[1]);
        http = HsmServer.serve(new HsmServer(hsm, keys), "127.0.0.1:0");
        base = "http://127.0.0.1:" + http.getAddress().getPort();
    }

    @AfterAll
    static void stop() { http.stop(0); }

    static HttpResponse<String> post(String path, Map<String, String> body) throws Exception {
        return C.send(HttpRequest.newBuilder(URI.create(base + path)).POST(HttpRequest.BodyPublishers.ofString(HsmServer.toJson(body))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void cavvGenerateAndVerify() throws Exception {
        var r = post("/v1/cavv", Map.of("pan", "4375510000000001", "upn", "1234", "authrc", "0", "sfarc", "00"));
        assertEquals("{\"cavv\":\"675\"}", r.body());
        assertEquals("{\"valid\":\"true\"}", post("/v1/cavv/verify", Map.of("pan", "4375510000000001", "cavv", "675", "upn", "1234", "authrc", "0", "sfarc", "00")).body());
        assertEquals("{\"valid\":\"false\"}", post("/v1/cavv/verify", Map.of("pan", "4375510000000001", "cavv", "675", "upn", "1235", "authrc", "0", "sfarc", "00")).body());
    }

    @Test
    void cvv2Verify() throws Exception {
        assertEquals("{\"valid\":\"true\"}", post("/v1/cvv2/verify", Map.of("pan", "4375510000000001", "expiry", "3012", "cvv2", "523")).body());
        assertEquals("{\"valid\":\"false\"}", post("/v1/cvv2/verify", Map.of("pan", "4375510000000001", "expiry", "3012", "cvv2", "524")).body());
    }

    @Test
    void pinAndChipOverHttp() throws Exception {
        // PVV of PIN 1234 (psec: 0582), PIN block under the ZPK from psec
        assertEquals("{\"valid\":\"true\"}", post("/v1/pin/verify-pvv", Map.of("pan", "4375510000000001", "pinBlock", "EAEF33E33F471DA9",
                "pvki", "1", "pvv", "0582")).body());
        assertEquals("{\"pinBlock\":\"EAEF33E33F471DA9\"}", post("/v1/pin/iso4-to-zpk", Map.of("pan", "4375510000000001",
                "pinBlock", "BCE34C548E471902740621E5DC1C6101")).body());
        // Visa CVN 10 ARQC/ARPC (pyemv)
        assertEquals("{\"valid\":\"true\",\"arpc\":\"C8FF4574A0EAB961\"}", post("/v1/arqc/verify", Map.of("cvn", "VISA_10",
                "pan", "4375510000000001", "psn", "00", "arqc", "D9ABDDB9BE215B12", "atc", "0001", "upn", "12345678",
                "txnData", PinAndChipTest.TXN + "03A00000", "arc", "3030")).body());
        assertEquals("{\"valid\":\"false\"}", post("/v1/arqc/verify", Map.of("cvn", "VISA_10", "pan", "4375510000000001", "psn", "00",
                "arqc", "D9ABDDB9BE215B13", "atc", "0001", "upn", "12345678", "txnData", PinAndChipTest.TXN + "03A00000", "arc", "3030")).body());
        // a key of the wrong type by label is refused
        assertEquals(400, post("/v1/pin/verify-pvv", Map.of("pan", "4375510000000001", "pinBlock", "EAEF33E33F471DA9", "pvk", "zpk",
                "pvki", "1", "pvv", "0582")).statusCode());
    }

    @Test
    void aesDukptPinOverHttp() throws Exception {
        // terminal PIN block from moov-io/dukpt (AesDukptTest), to ISO 0 under the ZPK (psec value)
        assertEquals("{\"pinBlock\":\"" + AesDukptTest.ISO0_1234 + "\"}", post("/v1/pin/dukpt-aes-to-zpk", Map.of("pan", "4375510000000001",
                "ksn", AesDukptTest.KSN_A5F31, "pinBlock", AesDukptTest.ISO4_128_A5F31)).body());
        // the wrong counter: the block does not decipher (no detail returned)
        var r = post("/v1/pin/dukpt-aes-to-zpk", Map.of("pan", "4375510000000001", "ksn", AesDukptTest.KSN2, "pinBlock", AesDukptTest.ISO4_128_1));
        assertEquals(500, r.statusCode());
        assertEquals("{\"error\":\"security module error\"}", r.body());
        // a KSN a device never sends (counter 0), a short KSN, a non-BDK key by label
        assertEquals(400, post("/v1/pin/dukpt-aes-to-zpk", Map.of("pan", "4375510000000001", "ksn", "123456789012345600000000",
                "pinBlock", AesDukptTest.ISO4_128_1)).statusCode());
        assertEquals(400, post("/v1/pin/dukpt-aes-to-zpk", Map.of("pan", "4375510000000001", "ksn", "FFFF9876543210E00001",
                "pinBlock", AesDukptTest.ISO4_128_1)).statusCode());
        assertEquals(500, post("/v1/pin/dukpt-aes-to-zpk", Map.of("pan", "4375510000000001", "ksn", AesDukptTest.KSN1, "bdk", "aes-pin",
                "pinBlock", AesDukptTest.ISO4_128_1)).statusCode());
    }

    static final String ISO_MSG = "0200723A00010880800016437551000000000100000000000012500001";

    @Test
    void retailMacVerify() throws Exception {
        // psec generate_retail_mac(KEY[:8], KEY[8:], msg, 2) = D1C4FBBCC5C5BCF5, pyemv mac_iso9797_3 the same
        assertEquals("{\"mac\":\"D1C4FBBCC5C5BCF5\"}", post("/v1/mac/retail", Map.of("data", ISO_MSG)).body());
        assertEquals("{\"valid\":\"true\"}", post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "D1C4FBBCC5C5BCF5")).body());
        assertEquals("{\"valid\":\"true\"}", post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "d1c4fbbc")).body(), "leftmost 4 bytes");
        // negatives: one bit off in the MAC, one byte of the message changed, another key
        assertEquals("{\"valid\":\"false\"}", post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "D1C4FBBCC5C5BCF4")).body());
        assertEquals("{\"valid\":\"false\"}", post("/v1/mac/retail/verify", Map.of("data", ISO_MSG.replace("0200", "0210"), "mac", "D1C4FBBCC5C5BCF5")).body());
        // "0200 DIFME ISO8583 MESSAGE" (psec D098DBA429F16895) with the ZPK slot as key: refused by type, then a valid MAC of other data
        assertEquals(400, post("/v1/mac/retail/verify", Map.of("key", "zpk", "data", ISO_MSG, "mac", "D1C4FBBCC5C5BCF5")).statusCode());
        assertEquals("{\"valid\":\"false\"}", post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "D098DBA429F16895")).body());
        // a MAC shorter than 4 or longer than 8 bytes is not a retail MAC
        assertEquals(400, post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "D1C4FB")).statusCode());
        assertEquals(400, post("/v1/mac/retail/verify", Map.of("data", ISO_MSG, "mac", "D1C4FBBCC5C5BCF500")).statusCode());
    }

    @Test
    void cmacVerify() throws Exception {
        // NIST SP 800-38B appendix D.1, AES-128 example 3 (40-byte message): DFA66747DE9AE63030CA32611497C827
        String m = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411";
        assertEquals("{\"valid\":\"true\"}", post("/v1/mac/cmac/verify", Map.of("data", m, "mac", "DFA66747DE9AE63030CA32611497C827")).body());
        assertEquals("{\"valid\":\"true\"}", post("/v1/mac/cmac/verify", Map.of("data", m, "mac", "DFA66747DE9AE630")).body(), "leftmost 8 bytes");
        assertEquals("{\"valid\":\"false\"}", post("/v1/mac/cmac/verify", Map.of("data", m, "mac", "DFA66747DE9AE63030CA32611497C826")).body());
        // NIST example 2 (16 bytes, 070A16B46B4D4144F79BDD9DD04A287C) does not verify for the 40-byte message
        assertEquals("{\"valid\":\"false\"}", post("/v1/mac/cmac/verify", Map.of("data", m, "mac", "070A16B46B4D4144F79BDD9DD04A287C")).body());
        assertEquals("{\"valid\":\"true\"}", post("/v1/mac/cmac/verify", Map.of("data", "6BC1BEE22E409F96E93D7E117393172A",
                "mac", "070A16B46B4D4144F79BDD9DD04A287C")).body());
        assertEquals(400, post("/v1/mac/cmac/verify", Map.of("data", m, "mac", "DFA66747")).statusCode(), "shorter than 8 bytes");
        assertEquals(400, post("/v1/mac/cmac/verify", Map.of("data", m, "aesKey", "nope", "mac", "DFA66747DE9AE630")).statusCode());
        // a key block of another usage (PIN key) is refused inside the module
        assertEquals(500, post("/v1/mac/cmac/verify", Map.of("data", m, "aesKey", "aes-pin", "mac", "DFA66747DE9AE630")).statusCode());
    }

    @Test
    void pinRevealOverHttp() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        String app = ISOUtil.hexString(g.generateKeyPair().getPublic().getEncoded());
        // psec encipher_pinblock_iso_4(AES, "1234", PAN) (as in pinAndChipOverHttp)
        var r = post("/v1/pin/reveal", Map.of("pan", "4375510000000001", "pinBlock", "BCE34C548E471902740621E5DC1C6101", "appKey", app));
        assertEquals(200, r.statusCode());
        org.junit.jupiter.api.Assertions.assertTrue(r.body().matches("\\{\"jwe\":\"[A-Za-z0-9_-]+\\.\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\"}"), r.body());
        assertEquals(400, post("/v1/pin/reveal", Map.of("pan", "4375510000000001", "pinBlock", "BCE34C548E471902740621E5DC1C6101", "appKey", "3000")).statusCode());
        assertEquals(500, post("/v1/pin/reveal", Map.of("pan", "4375510000000019", "pinBlock", "BCE34C548E471902740621E5DC1C6101", "appKey", app)).statusCode());
    }

    @Test
    void rejectsBadInputAndUnknownPaths() throws Exception {
        assertEquals(400, post("/v1/cavv", Map.of("pan", "43755100000000x1", "upn", "1234", "authrc", "0", "sfarc", "00")).statusCode());
        assertEquals(400, post("/v1/cavv", Map.of("pan", "4375510000000001")).statusCode());
        assertEquals(404, post("/v1/keys", Map.of()).statusCode());
    }

    @Test
    void ilpFulfilmentHmacWithTheInstitutionsOwnKey() throws Exception {
        String packet = "AYIBgQAAAAAAAASwNGxldmVsb25lLmRmc3AxLm1lci45T2RTOF81MDdqUUZERmZlakgyOVc4bXFmNEpLMHlGTFGCAUBQU0svMS4wCk5vbmNlOiB1SXlweUYzY3pYSXBFdzVVc05TYWh3CkVuY3J5cHRpb246IG5vbmUKUGF5bWVudC1JZDogMTMyMzZhM2ItOGZhOC00MTYzLTg0NDctNGMzZWQzZGE5OGE3";
        byte[] data = packet.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(ISOUtil.hex2byte(ILP_KEY), "HmacSHA256"));
        String expected = ISOUtil.hexString(mac.doFinal(data));
        assertEquals("{\"mac\":\"" + expected + "\"}", post("/v1/ilp/difme/hmac", Map.of("data", ISOUtil.hexString(data))).body());
        // another institution's key: not here; the generic HMAC endpoint can't reach ILP keys
        assertEquals(400, post("/v1/ilp/payeefsp/hmac", Map.of("data", "00")).statusCode());
        assertEquals(400, post("/v1/hmac", Map.of("key", "ilp-difme", "data", "00")).statusCode());
        assertEquals(404, post("/v1/ilp/Bad_Name/hmac", Map.of("data", "00")).statusCode());
    }

    @Test
    void schemeCaIssuesFromACsrSignedInTheModule() throws Exception {
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        var caCert = (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(java.util.Base64.getDecoder().decode(
                C.send(HttpRequest.newBuilder(URI.create(base + "/v1/certs/scheme-ca")).GET().build(), HttpResponse.BodyHandlers.ofString())
                        .body().replaceAll(".*\"x5c\":\"([^\"]+)\".*", "$1"))));
        assertEquals(1, caCert.getBasicConstraints(), "a CA certificate (path length 1)");
        // CSR for acs-sign, signed inside the module: proof of possession verifies with the key's public key
        String csrB64 = post("/v1/csr/acs-sign", Map.of("cn", "DIFME ACS")).body().replaceAll(".*\"csr\":\"([^\"]+)\".*", "$1");
        var csr = new org.bouncycastle.pkcs.PKCS10CertificationRequest(java.util.Base64.getDecoder().decode(csrB64));
        assertTrue(csr.isSignatureValid(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())));
        assertEquals("CN=DIFME ACS", csr.getSubject().toString());
        // the CA signs a digest (what the scheme's CA software sends); verifies with the CA certificate's key
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest("tbs".getBytes());
        String sig = post("/v1/ca/scheme-ca/sign-digest", Map.of("digest", ISOUtil.hexString(digest))).body().replaceAll(".*\"signature\":\"([0-9A-F]+)\".*", "$1");
        var v = java.security.Signature.getInstance("SHA256withRSA");
        v.initVerify(caCert.getPublicKey());
        v.update("tbs".getBytes());
        assertTrue(v.verify(ISOUtil.hex2byte(sig)));
        // CA keys: not through the generic signing path, no CSR for them; names are checked
        assertEquals(400, post("/v1/sign/ps256", Map.of("key", "scheme-ca", "data", "00")).statusCode());
        assertEquals(400, post("/v1/csr/scheme-ca", Map.of("cn", "x")).statusCode());
        assertEquals(400, post("/v1/csr/acs-sign", Map.of("cn", "a,O=evil")).statusCode());
        assertEquals(404, post("/v1/ca/acs-sign/sign-digest", Map.of("digest", ISOUtil.hexString(digest))).statusCode());
    }
}
