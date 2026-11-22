package dev.difme.hsm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;
import org.jpos.security.EMVCAPublicKey;
import org.jpos.security.EMVICCPublicKey;
import org.jpos.security.EMVIssuerPublicKey;
import org.jpos.security.SMException;
import org.jpos.security.jceadapter.JCESecurityModule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Personalisation certificates checked by an independent implementation: jPOS's EMV Book 2 recovery, which validates
 * header, format, trailer, lengths, SHA-1 hash, expiry, issuer identifier and PAN. Key sizes make both certificates
 * carry a modulus remainder.
 */
class EmvPersoTest {
    static final String PAN = "4375510000000001";
    static KeyPair ca, issuer, icc;
    static JCESecurityModule jpos;

    static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new java.security.spec.RSAKeyGenParameterSpec(bits, java.security.spec.RSAKeyGenParameterSpec.F4));
        return g.generateKeyPair();
    }

    @BeforeAll
    static void setUp() throws Exception {
        ca = rsa(1408);
        issuer = rsa(1408); // longer than the room in the CA certificate: remainder
        icc = rsa(1152);
        SecurityModule.software(Files.createTempDirectory("hsm").resolve("lmk"), true);
        jpos = new JCESecurityModule();
        jpos.setConfiguration(new org.jpos.core.SimpleConfiguration(new java.util.Properties() {{
            setProperty("lmk", Files.createTempDirectory("hsm2").resolve("lmk").toString());
            setProperty("rebuildlmk", "true");
        }}));
    }

    static EMVCAPublicKey caKey() {
        RSAPublicKey p = (RSAPublicKey) ca.getPublic();
        return new EMVCAPublicKey(HexFormat.of().parseHex("A000000003"), (byte) 0x92, EmvPerso.unsigned(p.getModulus(), 176),
                HexFormat.of().parseHex("010001"), (byte) 1, (byte) 1);
    }

    @Test
    void issuerAndIccCertificatesRecoverWithJpos() throws Exception {
        byte[] expiry = HexFormat.of().parseHex("1230"), sad = HexFormat.of().parseHex("5A0843755100000000015F24033012315F25032611017C00");
        var ic = EmvPerso.issuerCertificate((RSAPrivateKey) ca.getPrivate(), (RSAPublicKey) issuer.getPublic(), "437551", expiry,
                HexFormat.of().parseHex("000001"));
        assertTrue(ic.remainder().length > 0);
        EMVIssuerPublicKey ipk = jpos.recoverIssuerPublicKey(caKey(), ic.certificate(), ic.remainder(), ic.exponent(), PAN);
        assertArrayEquals(EmvPerso.unsigned(((RSAPublicKey) issuer.getPublic()).getModulus(), 176), ipk.modulus());

        var cc = EmvPerso.iccCertificate((RSAPrivateKey) issuer.getPrivate(), (RSAPublicKey) icc.getPublic(), PAN, expiry,
                HexFormat.of().parseHex("000002"), sad);
        EMVICCPublicKey ik = jpos.recoverICCPublicKey(ipk, cc.certificate(), cc.remainder(), cc.exponent(), sad, PAN);
        assertArrayEquals(EmvPerso.unsigned(((RSAPublicKey) icc.getPublic()).getModulus(), 144), ik.modulus());

        // other records than were certified, or another card: refused
        byte[] other = sad.clone();
        other[other.length - 1] ^= 1;
        assertThrows(SMException.class, () -> jpos.recoverICCPublicKey(ipk, cc.certificate(), cc.remainder(), cc.exponent(), other, PAN));
        assertThrows(SMException.class, () -> jpos.recoverICCPublicKey(ipk, cc.certificate(), cc.remainder(), cc.exponent(), sad, "4375510000000019"));
        assertThrows(SMException.class, () -> jpos.recoverIssuerPublicKey(caKey(), ic.certificate(), ic.remainder(), ic.exponent(), "5413330089020011"));
    }
}
