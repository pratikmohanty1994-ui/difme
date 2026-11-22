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
        http = HsmServer.serve(new HsmServer(hsm, cvk), "127.0.0.1:0");
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
    void rejectsBadInputAndUnknownPaths() throws Exception {
        assertEquals(400, post("/v1/cavv", Map.of("pan", "43755100000000x1", "upn", "1234", "authrc", "0", "sfarc", "00")).statusCode());
        assertEquals(400, post("/v1/cavv", Map.of("pan", "4375510000000001")).statusCode());
        assertEquals(404, post("/v1/keys", Map.of()).statusCode());
    }
}
