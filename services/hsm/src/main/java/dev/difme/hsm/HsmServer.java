package dev.difme.hsm;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMAdapter;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;

/**
 * The security module's HTTP interface (ADR-026) for the ACS, the authorisation switch and card management.
 * Function-level only: no endpoint returns a key, clear or encrypted; callers name keys by label. Bodies are flat JSON
 * objects of strings (binary values in hex). In the cluster it sits behind the mesh with mTLS and an
 * AuthorizationPolicy per path naming its callers; it binds to HSM_ADDR.
 *
 * <p>Keys ({@link KeyStore}): in a cluster only through attested key release ({@link KeyRelease}: HSM_KBS_URL,
 * HSM_TEE_SVN; first start HSM_BOOTSTRAP_OPENBAO + HSM_BOOTSTRAP_KEYS). Local tests only, with HSM_DEV_INSECURE=true:
 * HSM_LMK/HSM_KEYS files, or HSM_DEV_REBUILD_LMK=true with HSM_DEV_KEYS ("label=TYPE:component,…;…") or
 * HSM_DEV_CVK_COMPONENTS.
 */
public final class HsmServer {
    private final SecurityModule hsm;
    private final KeyStore keys;

    HsmServer(SecurityModule hsm, KeyStore keys) { this.hsm = hsm; this.keys = keys; }

    /** Keys by label: DES keys under the LMK, AES keys as TR-31 blocks under the KBPK. */
    public static final class KeyStore {
        final Map<String, SecureDESKey> des = new LinkedHashMap<>();
        final Map<String, String> aes = new LinkedHashMap<>();
        final Map<String, String> rsa = new LinkedHashMap<>();   // signing keys as TR-31 D "S0" blocks
        final Map<String, String> certs = new LinkedHashMap<>(); // their certificates (base64 DER)

        public KeyStore put(String label, SecureDESKey k) { des.put(label, k); return this; }

        public KeyStore putRsa(String label, String block, String certB64) { rsa.put(label, block); certs.put(label, certB64); return this; }

        String rsa(String label) {
            String k = rsa.get(label);
            if (k == null) throw new IllegalArgumentException("no signing key '" + label + "'");
            return k;
        }

        /** The key list as stored in the key release store: values are encrypted (under the LMK / KBPK) or public. */
        String toJson() {
            Map<String, String> m = new LinkedHashMap<>();
            des.forEach((l, k) -> m.put(l, k.getKeyType() + ":" + ISOUtil.hexString(k.getKeyBytes())));
            aes.forEach((l, b) -> m.put(l, "AES:" + b));
            rsa.forEach((l, b) -> m.put(l, "RSA:" + b));
            certs.forEach((l, c) -> m.put(l + ".cert", "CERT:" + c));
            return HsmServer.toJson(m);
        }

        public KeyStore putAes(String label, String block) { aes.put(label, block); return this; }

        SecureDESKey des(String label, String type) {
            SecureDESKey k = des.get(label);
            if (k == null || !k.getKeyType().equals(type)) throw new IllegalArgumentException("no " + type + " key '" + label + "'");
            return k;
        }

        String aes(String label) {
            String k = aes.get(label);
            if (k == null) throw new IllegalArgumentException("no AES key '" + label + "'");
            return k;
        }

        static KeyStore load(String json) {
            KeyStore ks = new KeyStore();
            parse(json).forEach((label, v) -> {
                int c = v.indexOf(':');
                String type = v.substring(0, c), val = v.substring(c + 1);
                if (type.equals("AES")) ks.putAes(label, val);
                else if (type.equals("RSA")) ks.rsa.put(label, val);
                else if (type.equals("CERT")) ks.certs.put(label.replaceFirst("\\.cert$", ""), val);
                else ks.put(label, new SecureDESKey(SMAdapter.LENGTH_DES3_2KEY, type, ISOUtil.hex2byte(val), null));
            });
            return ks;
        }

        static KeyStore ceremony(SecurityModule hsm, String spec) throws SMException {
            KeyStore ks = new KeyStore();
            for (String entry : spec.split(";")) {
                if (entry.isBlank()) continue;
                String[] lv = entry.trim().split("=", 2), tc = lv[1].split(":", 2);
                if (tc.length == 1) { // type only: generated inside the module
                    HsmServer.KeyStore g = KeyRelease.generate(hsm, entry.trim());
                    ks.des.putAll(g.des); ks.aes.putAll(g.aes); ks.rsa.putAll(g.rsa); ks.certs.putAll(g.certs);
                    continue;
                }
                String[] comps = tc[1].split(",");
                if (tc[0].startsWith("AES/")) ks.putAes(lv[0], hsm.aesKeyFromComponents(tc[0].substring(4), comps));
                else ks.put(lv[0], hsm.keyFromComponents(tc[0], comps));
            }
            return ks;
        }
    }

    public static void main(String[] args) throws Exception {
        var env = System.getenv();
        if (env.get("HSM_KBS_URL") != null) { // the only mode for clusters: keys through attested release (ADR-026)
            KeyRelease.Loaded l = KeyRelease.start(env);
            System.out.println("hsm: keys released by attestation" + (l.bootstrapped() ? " (first start: generated in the module, stored create-only)" : ""));
            report(l.hsm(), l.keys());
            serve(new HsmServer(l.hsm(), l.keys()), env.getOrDefault("HSM_ADDR", "127.0.0.1:8700"));
            return;
        }
        // Local development and tests only: clear test keys / a throw-away LMK. Refused unless explicitly asked for.
        if (!"true".equals(env.get("HSM_DEV_INSECURE"))) {
            System.err.println("hsm: HSM_KBS_URL not set; refusing to start without attested key release (HSM_DEV_INSECURE=true for local tests)");
            System.exit(2);
        }
        boolean rebuild = Boolean.parseBoolean(env.getOrDefault("HSM_DEV_REBUILD_LMK", "false"));
        Path lmk = Path.of(env.getOrDefault("HSM_LMK", rebuild ? Files.createTempDirectory("lmk") + "/lmk" : "/run/hsm/lmk"));
        SecurityModule hsm = SecurityModule.software(lmk, rebuild);
        KeyStore keys;
        if (rebuild && env.get("HSM_DEV_KEYS") != null) {
            keys = KeyStore.ceremony(hsm, env.get("HSM_DEV_KEYS"));
        } else if (rebuild && env.get("HSM_DEV_CVK_COMPONENTS") != null) {
            keys = new KeyStore().put("cvk", hsm.cvkFromComponents(env.get("HSM_DEV_CVK_COMPONENTS").split(",")));
        } else if (env.get("HSM_KEYS") != null) {
            keys = KeyStore.load(Files.readString(Path.of(env.get("HSM_KEYS"))));
        } else {
            keys = new KeyStore().put("cvk", SecurityModule.cvkUnderLmk(env.get("HSM_CVK_UNDER_LMK")));
        }
        report(hsm, keys);
        serve(new HsmServer(hsm, keys), env.getOrDefault("HSM_ADDR", "127.0.0.1:8700"));
    }

    static void report(SecurityModule hsm, KeyStore keys) throws SMException {
        for (var e : keys.des.entrySet()) System.out.println("hsm: key " + e.getKey() + " " + e.getValue().getKeyType() + " check value " + hsm.checkValue(e.getValue()));
        for (String l : keys.aes.keySet()) System.out.println("hsm: AES key " + l);
        for (String l : keys.rsa.keySet()) System.out.println("hsm: signing key " + l);
        System.out.flush();
    }

    static HttpServer serve(HsmServer s, String addr) throws IOException {
        String[] hp = addr.split(":");
        HttpServer http = HttpServer.create(new InetSocketAddress(hp[0], Integer.parseInt(hp[1])), 0);
        http.createContext("/", s::handle);
        http.start();
        return http;
    }

    /** dCVV2 time step: 5 minutes. */
    static final long DCVV2_STEP_SECONDS = 300;

    private Map<String, String> call(String path, Map<String, String> in) throws SMException {
        Map<String, String> out = new LinkedHashMap<>();
        switch (path) {
            case "/v1/cavv" -> out.put("cavv", hsm.cavv(d(in, "pan"), cvk(in), d(in, "upn"), d(in, "authrc"), d(in, "sfarc")));
            case "/v1/cavv/verify" -> valid(out, hsm.verifyCavv(d(in, "pan"), cvk(in), d(in, "cavv"), d(in, "upn"), d(in, "authrc"), d(in, "sfarc")));
            case "/v1/cvv2" -> out.put("cvv2", hsm.cvv2(d(in, "pan"), d(in, "expiry"), cvk(in))); // card issuance (card-issuer only)
            case "/v1/cvv2/verify" -> valid(out, hsm.verifyCvv2(d(in, "pan"), d(in, "expiry"), cvk(in), d(in, "cvv2")));
            case "/v1/cvv/verify" -> valid(out, hsm.cvv(d(in, "pan"), d(in, "expiry"), d(in, "serviceCode"), cvk(in)).equals(d(in, "cvv")));
            case "/v1/dcvv2" -> out.put("code", hsm.dcvv2(key(in, "key", "dcvv2", SMAdapter.TYPE_CVK), d(in, "pan"), step()));
            case "/v1/dcvv2/verify" -> valid(out, hsm.verifyDcvv2(key(in, "key", "dcvv2", SMAdapter.TYPE_CVK), d(in, "pan"), step(), 1, d(in, "code")));
            case "/v1/dcvv/verify" -> valid(out, hsm.verifyDcvv(key(in, "key", "imk-dcvv", SMAdapter.TYPE_MK_AC), d(in, "pan"), d(in, "dcvv"),
                    d(in, "expiry"), d(in, "serviceCode"), h(in, "atc")));
            case "/v1/cvc3/verify" -> valid(out, hsm.verifyCvc3(key(in, "key", "imk-cvc3", SMAdapter.TYPE_MK_CVC3), d(in, "pan"), d(in, "psn"),
                    h(in, "atc"), h(in, "upn"), h(in, "track"), d(in, "cvc3")));
            case "/v1/pin/verify-pvv" -> valid(out, hsm.verifyPvv(SecurityModule.pinBlock(hx(in, "pinBlock"), d(in, "pan")),
                    key(in, "zpk", "zpk", SMAdapter.TYPE_ZPK), key(in, "pvk", "pvk", SMAdapter.TYPE_PVK), Integer.parseInt(d(in, "pvki")), d(in, "pvv")));
            case "/v1/pin/pvv" -> out.put("pvv", hsm.pvv(SecurityModule.pinBlock(hx(in, "pinBlock"), d(in, "pan")),
                    key(in, "zpk", "zpk", SMAdapter.TYPE_ZPK), key(in, "pvk", "pvk", SMAdapter.TYPE_PVK), Integer.parseInt(d(in, "pvki"))));
            case "/v1/pin/translate" -> out.put("pinBlock", hsm.translatePin(SecurityModule.pinBlock(hx(in, "pinBlock"), d(in, "pan")),
                    key(in, "from", null, SMAdapter.TYPE_ZPK), key(in, "to", null, SMAdapter.TYPE_ZPK)));
            case "/v1/pin/iso4-to-zpk" -> out.put("pinBlock", hsm.translateIso4ToZpk(h(in, "pinBlock"), d(in, "pan"),
                    keys.aes(in.getOrDefault("aesKey", "aes-pin")), key(in, "zpk", "zpk", SMAdapter.TYPE_ZPK)));
            case "/v1/arqc/verify" -> {
                byte[] arpc = hsm.verifyArqcGenerateArpc(SecurityModule.Cvn.valueOf(in.getOrDefault("cvn", "")),
                        key(in, "key", "imk-ac", SMAdapter.TYPE_MK_AC), d(in, "pan"), d(in, "psn"), h(in, "arqc"), h(in, "atc"), h(in, "upn"),
                        h(in, "txnData"), h(in, "arc"));
                valid(out, arpc != null);
                if (arpc != null) out.put("arpc", ISOUtil.hexString(arpc));
            }
            case "/v1/script/mac" -> out.put("mac", ISOUtil.hexString(hsm.scriptMac(SecurityModule.Cvn.valueOf(in.getOrDefault("cvn", "")),
                    key(in, "key", "imk-smi", SMAdapter.TYPE_MK_SMI), d(in, "pan"), d(in, "psn"), h(in, "atc"), h(in, "arqc"), h(in, "command"))));
            case "/v1/mac/retail" -> out.put("mac", ISOUtil.hexString(hsm.retailMac(key(in, "key", "tak", SMAdapter.TYPE_TAK), h(in, "data"))));
            case "/v1/sign/ps256" -> out.put("signature", ISOUtil.hexString(hsm.signPs256(keys.rsa(in.getOrDefault("key", "acs-sign")), h(in, "data"))));
            case "/v1/data/encrypt" -> out.put("ciphertext", ISOUtil.hexString(hsm.aesGcm(keys.aes(in.getOrDefault("key", "card-vault")), true,
                    h(in, "data"), in.containsKey("aad") ? h(in, "aad") : null)));
            case "/v1/data/decrypt" -> out.put("data", ISOUtil.hexString(hsm.aesGcm(keys.aes(in.getOrDefault("key", "card-vault")), false,
                    h(in, "ciphertext"), in.containsKey("aad") ? h(in, "aad") : null)));
            case "/v1/hmac" -> out.put("mac", ISOUtil.hexString(hsm.hmacSha256(keys.aes(in.getOrDefault("key", "acs-hmac")), h(in, "data"))));
            case "/v1/mac/cmac" -> out.put("mac", ISOUtil.hexString(hsm.aesCmac(keys.aes(in.getOrDefault("aesKey", "aes-mac")), h(in, "data"))));
            default -> { return null; }
        }
        return out;
    }

    private static long step() { return Instant.now().getEpochSecond() / DCVV2_STEP_SECONDS; }

    private SecureDESKey cvk(Map<String, String> in) { return key(in, "key", "cvk", SMAdapter.TYPE_CVK); }

    private SecureDESKey key(Map<String, String> in, String field, String dflt, String type) {
        String label = in.getOrDefault(field, dflt);
        if (label == null) throw new IllegalArgumentException(field + " (key label) required");
        return keys.des(label, type);
    }

    private static void valid(Map<String, String> out, boolean v) { out.put("valid", Boolean.toString(v)); }

    private void handle(HttpExchange x) throws IOException {
        int status = 200;
        Map<String, String> out = new LinkedHashMap<>();
        try {
            String path = x.getRequestURI().getPath();
            if (path.equals("/healthz")) {
                out.put("status", "ok");
            } else if (path.startsWith("/v1/certs/") && "GET".equals(x.getRequestMethod())) {
                String c = keys.certs.get(path.substring("/v1/certs/".length()));
                if (c == null) status = 404; else out.put("x5c", c);
            } else if (!"POST".equals(x.getRequestMethod())) {
                status = 405;
            } else {
                Map<String, String> r = call(path, parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
                if (r == null) status = 404; else out = r;
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

    private static final Pattern DIGITS = Pattern.compile("[0-9]{1,19}"), HEX = Pattern.compile("([0-9A-Fa-f]{2}){1,8192}");

    private static String d(Map<String, String> in, String k) {
        String v = in.get(k);
        if (v == null || !DIGITS.matcher(v).matches()) throw new IllegalArgumentException(k + " must be digits");
        return v;
    }

    private static String hx(Map<String, String> in, String k) {
        String v = in.get(k);
        if (v == null || !HEX.matcher(v).matches()) throw new IllegalArgumentException(k + " must be hex");
        return v.toUpperCase();
    }

    private static byte[] h(Map<String, String> in, String k) { return ISOUtil.hex2byte(hx(in, k)); }

    static final Pattern PAIR = Pattern.compile("\"([A-Za-z0-9_.-]+)\"\\s*:\\s*\"([^\"\\\\]*)\"");

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
