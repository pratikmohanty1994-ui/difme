package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.jpos.security.SMException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * App PIN reveal: the JWE the module produces is decrypted by an independent implementation, jwcrypto (LGPL, used
 * here only as a test oracle), with the app's private key; another key and a tampered token are refused by it.
 */
class AppPinRevealTest {
    static final String PAN = "4375510000000001", AES = "00112233445566778899AABBCCDDEEFF";
    static SecurityModule hsm;
    static String pinKey;
    static Path dir;

    @BeforeAll
    static void setUp() throws Exception {
        dir = Files.createTempDirectory("reveal");
        hsm = SecurityModule.software(dir.resolve("lmk"), true);
        pinKey = hsm.aesKeyFromComponents("P0", AES);
    }

    static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    static final String ORACLE = """
            import sys
            from jwcrypto import jwe, jwk
            key = jwk.JWK.from_pem(open(sys.argv[1], 'rb').read())
            t = jwe.JWE()
            try:
                t.deserialize(open(sys.argv[2]).read(), key=key)
            except Exception as e:
                print('REFUSED', type(e).__name__); sys.exit(0)
            print('PIN', t.payload.decode(), t.jose_header['alg'], t.jose_header['enc'], t.jose_header['kid'])
            """;

    /** Decrypts {@code jwe} with jwcrypto and the private key of {@code kp}; skipped when Python/jwcrypto are absent. */
    static String jwcrypto(KeyPair kp, String jwe) throws Exception {
        Path key = dir.resolve("app.pem"), tok = dir.resolve("token"), py = dir.resolve("oracle.py");
        Files.writeString(key, "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n");
        Files.writeString(tok, jwe);
        Files.writeString(py, ORACLE);
        Process p;
        try {
            p = new ProcessBuilder(List.of("python3", "-I", py.toString(), key.toString(), tok.toString())).redirectErrorStream(true).start();
        } catch (java.io.IOException e) {
            Assumptions.abort("python3 not available");
            return null;
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor();
        Assumptions.assumeFalse(out.contains("No module named"), "jwcrypto not installed");
        return out;
    }

    @Test
    void rsaOaep256RevealDecryptsWithJwcrypto() throws Exception {
        KeyPair app = rsa(2048);
        byte[] block = Iso4.encipher(HexFormat.of().parseHex(AES), "3917", PAN);
        String jwe = hsm.revealPinToApp(block, PAN, pinKey, app.getPublic().getEncoded());
        assertEquals(5, jwe.split("\\.", -1).length);
        assertTrue(!jwe.contains("3917") && !new String(Base64.getUrlDecoder().decode(jwe.split("\\.")[0])).contains("3917"));
        assertEquals("PIN 3917 RSA-OAEP-256 A256GCM 0001", jwcrypto(app, jwe));
        assertTrue(jwcrypto(rsa(2048), jwe).startsWith("REFUSED"), "another app's key");
        String[] p = jwe.split("\\.");
        p[3] = p[3].substring(0, p[3].length() - 1) + (p[3].endsWith("A") ? "B" : "A");
        assertTrue(jwcrypto(app, String.join(".", p)).startsWith("REFUSED"), "tampered ciphertext");
    }

    @Test
    void ecdhEsRevealDecryptsWithJwcrypto() throws Exception {
        KeyPair app = ec("secp256r1");
        byte[] block = Iso4.encipher(HexFormat.of().parseHex(AES), "590173", PAN);
        String a = hsm.revealPinToApp(block, PAN, pinKey, app.getPublic().getEncoded());
        String b = hsm.revealPinToApp(block, PAN, pinKey, app.getPublic().getEncoded());
        assertNotEquals(a, b, "fresh ephemeral key and IV per reveal");
        assertEquals("PIN 590173 ECDH-ES A256GCM 0001", jwcrypto(app, a));
        assertTrue(jwcrypto(ec("secp256r1"), a).startsWith("REFUSED"), "another app's key");
        String[] p = a.split("\\.");
        p[0] = Base64.getUrlEncoder().withoutPadding().encodeToString(new String(Base64.getUrlDecoder().decode(p[0])).replace("0001", "0002").getBytes());
        assertTrue(jwcrypto(app, String.join(".", p)).startsWith("REFUSED"), "header changed (it is the GCM associated data)");
    }

    @Test
    void refusals() throws Exception {
        byte[] block = Iso4.encipher(HexFormat.of().parseHex(AES), "3917", PAN);
        assertThrows(IllegalArgumentException.class, () -> hsm.revealPinToApp(block, PAN, pinKey, rsa(1024).getPublic().getEncoded()), "short RSA key");
        assertThrows(IllegalArgumentException.class, () -> hsm.revealPinToApp(block, PAN, pinKey, ec("secp384r1").getPublic().getEncoded()), "P-384");
        assertThrows(IllegalArgumentException.class, () -> hsm.revealPinToApp(block, PAN, pinKey, new byte[] {0x30, 0x00}), "not a key");
        byte[] app = ec("secp256r1").getPublic().getEncoded();
        assertThrows(SMException.class, () -> hsm.revealPinToApp(block, "4375510000000019", pinKey, app), "block for another card");
        assertThrows(SMException.class, () -> hsm.revealPinToApp(block, PAN, hsm.aesKeyFromComponents("M7", AES), app), "MAC key as PIN key");
    }

    @Test
    void concatKdfMatchesRfc7518AppendixC() throws Exception {
        // the shared secret Z of RFC 7518 appendix C, with this profile's OtherInfo (AlgorithmID "A256GCM", empty
        // PartyUInfo/PartyVInfo, 256 bits) through pyca/cryptography's ConcatKDFHash (NIST SP 800-56A)
        byte[] z = HexFormat.of().parseHex("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
        String ours = HexFormat.of().formatHex(AppPinReveal.concatKdf(z, "A256GCM", 256));
        Path py = dir.resolve("kdf.py");
        Files.writeString(py, """
                from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
                from cryptography.hazmat.primitives import hashes
                import struct
                other = struct.pack('>I', 7) + b'A256GCM' + struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 256)
                print(ConcatKDFHash(hashes.SHA256(), 32, other).derive(bytes.fromhex('9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4')).hex())
                """);
        Process p;
        try {
            p = new ProcessBuilder(List.of("python3", "-I", py.toString())).redirectErrorStream(true).start();
        } catch (java.io.IOException e) {
            Assumptions.abort("python3 not available");
            return;
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        Assumptions.assumeFalse(out.contains("No module named"), "cryptography not installed");
        assertEquals(out, ours);
    }
}
