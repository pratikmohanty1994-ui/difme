package dev.difme.hsm;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jpos.security.SecureDESKey;

/**
 * The security module's HTTP interface (ADR-026), for the ACS and the authorisation switch. Function-level only:
 * no endpoint returns a key, clear or encrypted. Bodies are flat JSON objects of strings. In the cluster it sits
 * behind the mesh with mTLS and an authorisation policy naming its callers; here it binds to HSM_ADDR.
 *
 * Keys: HSM_LMK (LMK file, written by the attested key release); HSM_CVK_UNDER_LMK (the CVK encrypted under the LMK,
 * hex, from the key ceremony). Dev only: HSM_DEV_REBUILD_LMK=true and HSM_DEV_CVK_COMPONENTS (comma-separated clear
 * components) run a ceremony at start-up.
 */
public final class HsmServer {
    private final SecurityModule hsm;
    private final SecureDESKey cvk;

    HsmServer(SecurityModule hsm, SecureDESKey cvk) { this.hsm = hsm; this.cvk = cvk; }

    public static void main(String[] args) throws Exception {
        String env;
        boolean rebuild = Boolean.parseBoolean(System.getenv().getOrDefault("HSM_DEV_REBUILD_LMK", "false"));
        Path lmk = Path.of(System.getenv().getOrDefault("HSM_LMK", rebuild ? Files.createTempDirectory("lmk") + "/lmk" : "/run/hsm/lmk"));
        SecurityModule hsm = SecurityModule.software(lmk, rebuild);
        SecureDESKey cvk;
        if ((env = System.getenv("HSM_DEV_CVK_COMPONENTS")) != null && rebuild) {
            cvk = hsm.cvkFromComponents(env.split(","));
        } else {
            cvk = SecurityModule.cvkUnderLmk(System.getenv("HSM_CVK_UNDER_LMK"));
        }
        System.out.println("hsm: CVK check value " + hsm.checkValue(cvk));
        serve(new HsmServer(hsm, cvk), System.getenv().getOrDefault("HSM_ADDR", "127.0.0.1:8700"));
    }

    static HttpServer serve(HsmServer s, String addr) throws IOException {
        String[] hp = addr.split(":");
        HttpServer http = HttpServer.create(new InetSocketAddress(hp[0], Integer.parseInt(hp[1])), 0);
        http.createContext("/", s::handle);
        http.start();
        return http;
    }

    private void handle(HttpExchange x) throws IOException {
        int status = 200;
        Map<String, String> out = new LinkedHashMap<>();
        try {
            String path = x.getRequestURI().getPath();
            if (path.equals("/healthz")) {
                out.put("status", "ok");
            } else if (!"POST".equals(x.getRequestMethod())) {
                status = 405;
            } else {
                Map<String, String> in = parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                switch (path) {
                    case "/v1/cavv" -> out.put("cavv", hsm.cavv(req(in, "pan"), cvk, req(in, "upn"), req(in, "authrc"), req(in, "sfarc")));
                    case "/v1/cavv/verify" -> out.put("valid", Boolean.toString(
                            hsm.verifyCavv(req(in, "pan"), cvk, req(in, "cavv"), req(in, "upn"), req(in, "authrc"), req(in, "sfarc"))));
                    case "/v1/cvv2/verify" -> out.put("valid", Boolean.toString(
                            hsm.verifyCvv2(req(in, "pan"), req(in, "expiry"), cvk, req(in, "cvv2"))));
                    default -> status = 404;
                }
            }
        } catch (IllegalArgumentException e) {
            status = 400;
            out.put("error", e.getMessage());
        } catch (Exception e) {
            status = 500;
            out.put("error", "security module error"); // no detail: may concern key material
        }
        byte[] b = toJson(out).getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("content-type", "application/json");
        x.sendResponseHeaders(status, b.length);
        x.getResponseBody().write(b);
        x.close();
    }

    private static final Pattern DIGITS = Pattern.compile("[0-9]{1,19}");

    private static String req(Map<String, String> in, String k) {
        String v = in.get(k);
        if (v == null || !DIGITS.matcher(v).matches()) throw new IllegalArgumentException(k + " must be digits");
        return v;
    }

    static final Pattern PAIR = Pattern.compile("\"([a-z0-9]+)\"\\s*:\\s*\"([^\"\\\\]*)\"");

    static Map<String, String> parse(String json) {
        Map<String, String> m = new LinkedHashMap<>();
        Matcher mt = PAIR.matcher(json);
        while (mt.find()) m.put(mt.group(1), mt.group(2));
        return m;
    }

    static String toJson(Map<String, String> m) {
        StringBuilder b = new StringBuilder("{");
        m.forEach((k, v) -> b.append(b.length() > 1 ? "," : "").append('"').append(k).append("\":\"").append(v).append('"'));
        return b.append('}').toString();
    }
}
