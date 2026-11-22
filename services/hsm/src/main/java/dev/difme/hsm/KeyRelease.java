package dev.difme.hsm;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jpos.iso.ISOUtil;
import org.jpos.security.SMException;
import org.jpos.security.SecureDESKey;

/**
 * The security module's start-up in a TEE (ADR-026): all key material arrives through attested key release, never
 * from Kubernetes Secrets, environment variables or disk.
 *
 * <ol>
 *   <li>Attest to Trustee's KBS and fetch {@code <prefix>/lmk} (jPOS LMK), {@code <prefix>/kbpk} (AES key block
 *       protection key) and {@code <prefix>/keys} (the key list: DES keys under the LMK, AES/RSA keys as TR-31 blocks,
 *       certificates). Each is base64 text in OpenBao (KV v1 mount "kbs"), released as JWE to the TEE's key.</li>
 *   <li>First start only (resource not found, attestation affirming): generate what is missing inside the module and
 *       store it in OpenBao through a create-only role (cannot read or overwrite), then use it. The key list names
 *       labels and types only (HSM_BOOTSTRAP_KEYS); key values are generated here.</li>
 * </ol>
 * The LMK passes through a file only because jPOS loads it from one: a memory-backed path inside the TEE, deleted
 * right after loading.
 */
public final class KeyRelease {
    public record Loaded(SecurityModule hsm, HsmServer.KeyStore keys, boolean bootstrapped) {}

    private KeyRelease() {}

    public static Loaded start(Map<String, String> env) throws Exception {
        String prefix = env.getOrDefault("HSM_KBS_PREFIX", "difme/hsm");
        KbsClient kbs = new KbsClient(env.get("HSM_KBS_URL"), env.getOrDefault("HSM_TEE_SVN", "1"));
        Path tmp = Path.of(env.getOrDefault("HSM_TMPFS", "/run/hsm"));
        byte[] lmk = fetch(kbs, prefix + "/lmk"), kbpk = fetch(kbs, prefix + "/kbpk"), keys = fetch(kbs, prefix + "/keys");
        OpenBao bao = null;
        boolean bootstrapped = false;
        if ((lmk == null || kbpk == null || keys == null)) {
            if (env.get("HSM_BOOTSTRAP_OPENBAO") == null)
                throw new IllegalStateException("key material missing in the key release store and bootstrap not enabled");
            bao = OpenBao.login(env.get("HSM_BOOTSTRAP_OPENBAO"), env.getOrDefault("HSM_BOOTSTRAP_ROLE", "hsm-bootstrap"),
                    Files.readString(Path.of(env.getOrDefault("HSM_BOOTSTRAP_JWT", "/var/run/secrets/openbao/token"))).trim());
            bootstrapped = true;
        }
        if (lmk == null) {
            if (kbpk != null || keys != null) throw new IllegalStateException("LMK missing while keys exist: refusing to generate a new LMK");
            Path f = tmp.resolve("lmk-new");
            SecurityModule.software(f, true); // jPOS writes a fresh random LMK
            lmk = Files.readAllBytes(f);
            Files.deleteIfExists(f);
            Files.deleteIfExists(Path.of(f + ".aes"));
            bao.create("kbs/" + prefix + "/lmk", lmk);
        }
        if (kbpk == null) {
            kbpk = new byte[32];
            new java.security.SecureRandom().nextBytes(kbpk);
            bao.create("kbs/" + prefix + "/kbpk", kbpk);
        }
        SecurityModule hsm = load(lmk, kbpk, tmp);
        HsmServer.KeyStore ks;
        if (keys == null) {
            ks = generate(hsm, env.getOrDefault("HSM_BOOTSTRAP_KEYS", ""));
            bao.create("kbs/" + prefix + "/keys", ks.toJson().getBytes(StandardCharsets.UTF_8));
        } else {
            ks = HsmServer.KeyStore.load(new String(keys, StandardCharsets.UTF_8));
        }
        java.util.Arrays.fill(lmk, (byte) 0);
        java.util.Arrays.fill(kbpk, (byte) 0);
        return new Loaded(hsm, ks, bootstrapped);
    }

    /** null when the resource does not exist yet; any other refusal (attestation not affirming) is fatal. */
    static byte[] fetch(KbsClient kbs, String path) throws IOException, InterruptedException {
        try {
            return Base64.getDecoder().decode(new String(kbs.resource(path), StandardCharsets.US_ASCII).trim());
        } catch (KbsClient.Refused e) {
            if (e.status == 404) return null;
            throw e;
        }
    }

    static SecurityModule load(byte[] lmk, byte[] kbpk, Path tmp) throws Exception {
        Path f = Files.createTempFile(tmp, "lmk", "");
        try {
            Files.write(f, lmk);
            SecurityModule hsm = SecurityModule.software(f, false);
            hsm.setKbpk(kbpk);
            return hsm;
        } finally {
            Files.deleteIfExists(f);
        }
    }

    /** Generates the bootstrap key list: "label=TYPE;…", TYPE a jPOS key type, AES/&lt;usage&gt; or RSA (signing key + certificate). */
    static HsmServer.KeyStore generate(SecurityModule hsm, String spec) throws SMException {
        HsmServer.KeyStore ks = new HsmServer.KeyStore();
        for (String e : spec.split(";")) {
            if (e.isBlank()) continue;
            String[] lt = e.trim().split("=", 2);
            if (lt[1].equals("RSA")) {
                String[] kc = hsm.generateRsaSigningKey("DIFME " + lt[0] + " (dev)");
                ks.putRsa(lt[0], kc[0], kc[1]);
            } else if (lt[1].startsWith("AES/")) {
                ks.putAes(lt[0], hsm.generateAesKey(lt[1].substring(4), 32));
            } else {
                ks.put(lt[0], hsm.generateKey(lt[1]));
            }
        }
        return ks;
    }

    /** OpenBao client for the create-only bootstrap role (Kubernetes auth). */
    static final class OpenBao {
        final String addr, token;
        final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

        private OpenBao(String addr, String token) { this.addr = addr; this.token = token; }

        static OpenBao login(String addr, String role, String jwt) throws IOException, InterruptedException {
            HttpClient h = HttpClient.newHttpClient();
            HttpResponse<String> r = h.send(HttpRequest.newBuilder(URI.create(addr + "/v1/auth/kubernetes/login"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"role\":\"" + role + "\",\"jwt\":\"" + jwt + "\"}")).build(),
                    HttpResponse.BodyHandlers.ofString());
            var m = java.util.regex.Pattern.compile("\"client_token\"\\s*:\\s*\"([^\"]+)\"").matcher(r.body());
            if (r.statusCode() != 200 || !m.find()) throw new IOException("OpenBao login (" + role + "): HTTP " + r.statusCode());
            return new OpenBao(addr, m.group(1));
        }

        /** Creates a KV v1 entry {data: base64}; the policy allows create only, so an existing entry is never replaced. */
        void create(String path, byte[] value) throws IOException, InterruptedException {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(addr + "/v1/" + path)).header("X-Vault-Token", token)
                    .POST(HttpRequest.BodyPublishers.ofString("{\"data\":\"" + Base64.getEncoder().encodeToString(value) + "\"}")).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 204 && r.statusCode() != 200) throw new IOException("OpenBao create " + path + ": HTTP " + r.statusCode());
        }
    }

    static String hex(SecureDESKey k) { return ISOUtil.hexString(k.getKeyBytes()); }

    static Map<String, String> empty() { return new LinkedHashMap<>(); }
}
