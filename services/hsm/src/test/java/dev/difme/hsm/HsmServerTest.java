package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
                .putAes("bdk-aes", hsm.aesKeyFromComponents("B0", AesDukptTest.BDK128));
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

    @Test
    void rejectsBadInputAndUnknownPaths() throws Exception {
        assertEquals(400, post("/v1/cavv", Map.of("pan", "43755100000000x1", "upn", "1234", "authrc", "0", "sfarc", "00")).statusCode());
        assertEquals(400, post("/v1/cavv", Map.of("pan", "4375510000000001")).statusCode());
        assertEquals(404, post("/v1/keys", Map.of()).statusCode());
    }
}
