package dev.difme.hsm;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Attested key release (ADR-026): the security module's own client for Trustee's Key Broker Service (KBS attestation
 * protocol 0.4.0, Request-Challenge-Attestation-Response). It generates an ephemeral RSA key inside the TEE, binds it
 * into the TEE evidence (report data = SHA-384 of the RFC 8785 canonical runtime data), and fetches resources, which
 * the KBS returns only after an affirming appraisal, as JWE (RSA-OAEP-256 + A256GCM) encrypted to that key. Resources
 * are decrypted in memory and never written anywhere by this class.
 *
 * <p>TEE: in development Trustee's emulated "sample" TEE, whose {@code svn} stands in for the module's measurement
 * (HSM_TEE_SVN). On SEV-SNP/TDX nodes the evidence comes from the hardware (Confidential Containers attestation agent);
 * only {@link #evidence} changes.
 */
public final class KbsClient {
    public static final String PROTOCOL = "0.4.0";

    /** The KBS refused (attestation not affirming, resource policy denied) or the resource does not exist. */
    public static final class Refused extends IOException {
        public final int status;

        Refused(String what, int status, String body) {
            super(what + ": HTTP " + status + " " + (body.length() > 200 ? body.substring(0, 200) : body));
            this.status = status;
        }
    }

    private final String base;
    private final String svn;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private KeyPair teeKey;
    private String cookie;

    public KbsClient(String baseUrl, String sampleSvn) {
        this.base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.svn = sampleSvn;
    }

    private static final Base64.Encoder B64U = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64UD = Base64.getUrlDecoder();

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b[0] == 0) b = java.util.Arrays.copyOfRange(b, 1, b.length);
        return B64U.encodeToString(b);
    }

    /** Runs the attestation (auth + attest); keeps the session cookie for resource requests. */
    public void attest() throws IOException, InterruptedException {
        HttpResponse<String> auth = http.send(HttpRequest.newBuilder(URI.create(base + "/kbs/v0/auth")).timeout(Duration.ofSeconds(10))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"version\":\"" + PROTOCOL + "\",\"tee\":\"sample\",\"extra-params\":{}}")).build(),
                HttpResponse.BodyHandlers.ofString());
        if (auth.statusCode() != 200) throw new Refused("KBS auth", auth.statusCode(), auth.body());
        String nonce = field(auth.body(), "nonce");
        cookie = auth.headers().firstValue("set-cookie").map(c -> c.split(";", 2)[0]).orElseThrow(() -> new IOException("KBS sent no session cookie"));
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(3072);
            teeKey = g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        RSAPublicKey pub = (RSAPublicKey) teeKey.getPublic();
        // RFC 8785 canonical form of the runtime data the KBS hashes: keys sorted, no whitespace (all values are
        // base64/base64url strings, so no escaping is needed).
        String teePubkey = "{\"alg\":\"RSA-OAEP-256\",\"e\":\"" + unsigned(pub.getPublicExponent()) + "\",\"kty\":\"RSA\",\"n\":\""
                + unsigned(pub.getModulus()) + "\"}";
        String additional = "";
        String runtime = "{\"additional-evidence\":\"" + additional + "\",\"nonce\":\"" + nonce + "\",\"tee-pubkey\":" + teePubkey + "}";
        byte[] reportData;
        try {
            reportData = MessageDigest.getInstance("SHA-384").digest(runtime.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        String body = "{\"runtime-data\":{\"nonce\":\"" + nonce + "\",\"tee-pubkey\":" + teePubkey + "},\"tee-evidence\":{\"primary_evidence\":"
                + evidence(reportData) + ",\"additional_evidence\":\"" + additional + "\"}}";
        HttpResponse<String> att = http.send(HttpRequest.newBuilder(URI.create(base + "/kbs/v0/attest")).timeout(Duration.ofSeconds(30))
                .header("content-type", "application/json").header("cookie", cookie)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        if (att.statusCode() != 200) throw new Refused("KBS attest", att.statusCode(), att.body());
    }

    /** The emulated TEE's evidence: svn (stand-in measurement) and the report data binding nonce and key. */
    private String evidence(byte[] reportData) {
        return "{\"svn\":\"" + svn + "\",\"report_data\":\"" + Base64.getEncoder().encodeToString(reportData) + "\"}";
    }

    /** A resource ("repository/type/tag", e.g. difme/hsm/lmk), decrypted in memory. */
    public byte[] resource(String path) throws IOException, InterruptedException {
        if (cookie == null) attest();
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + "/kbs/v0/resource/" + path)).timeout(Duration.ofSeconds(10))
                .header("cookie", cookie).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new Refused("KBS resource " + path, r.statusCode(), r.body());
        return decrypt(r.body());
    }

    private byte[] decrypt(String jwe) throws IOException {
        String prot = field(jwe, "protected"), ek = field(jwe, "encrypted_key"), iv = field(jwe, "iv"), ct = field(jwe, "ciphertext"),
                tag = field(jwe, "tag");
        if (prot == null || ek == null || iv == null || ct == null || tag == null) throw new IOException("KBS response is not a flattened JWE");
        String header = new String(B64UD.decode(prot), StandardCharsets.UTF_8);
        if (!header.replace(" ", "").contains("\"alg\":\"RSA-OAEP-256\"") || !header.replace(" ", "").contains("\"enc\":\"A256GCM\""))
            throw new IOException("unexpected JWE algorithms: " + header);
        try {
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, teeKey.getPrivate(),
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] cek = rsa.doFinal(B64UD.decode(ek));
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, B64UD.decode(iv)));
            String aadField = field(jwe, "aad");
            gcm.updateAAD((aadField != null && !aadField.isEmpty() ? new String(B64UD.decode(aadField), StandardCharsets.US_ASCII) : prot)
                    .getBytes(StandardCharsets.US_ASCII));
            byte[] ctb = B64UD.decode(ct), tg = B64UD.decode(tag);
            byte[] all = java.util.Arrays.copyOf(ctb, ctb.length + tg.length);
            System.arraycopy(tg, 0, all, ctb.length, tg.length);
            return gcm.doFinal(all);
        } catch (GeneralSecurityException e) {
            throw new IOException("JWE decryption failed", e);
        }
    }
}
