package dev.difme.hsm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A self-signed certificate for a key generated in the module (development; production uses scheme-issued certs). */
final class SelfSigned {
    private SelfSigned() {}

    /**
     * A self-signed CA certificate (basic constraints CA, key usage keyCertSign + cRLSign) for a CA key generated in the
     * module: the card scheme's root (key scheme-ca), which issues the ACS signing certificate and other scheme
     * certificates. Ten years, as scheme roots are long-lived.
     */
    static byte[] caCertificate(KeyPair kp, String cn) throws java.security.GeneralSecurityException {
        try {
            X500Name name = new X500Name("CN=" + cn + ",O=DIFME Card Scheme (simulated)");
            long now = System.currentTimeMillis();
            var b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), new Date(now - 3_600_000L), new Date(now + 3650L * 86_400_000L), name,
                    kp.getPublic());
            b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(1));
            b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                    new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.keyCertSign | org.bouncycastle.asn1.x509.KeyUsage.cRLSign));
            return b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())).getEncoded();
        } catch (Exception e) {
            throw new java.security.GeneralSecurityException(e);
        }
    }

    /** A PKCS#10 request for a key in the module, signed with it (proof of possession for the scheme CA). */
    static byte[] csr(java.security.PrivateKey key, java.security.PublicKey pub, String cn) throws java.security.GeneralSecurityException {
        try {
            var b = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + cn), pub);
            return b.build(new JcaContentSignerBuilder("SHA256withRSA").build(key)).getEncoded();
        } catch (Exception e) {
            throw new java.security.GeneralSecurityException(e);
        }
    }

    static byte[] certificate(KeyPair kp, String cn) throws java.security.GeneralSecurityException {
        try {
            X500Name name = new X500Name("CN=" + cn);
            long now = System.currentTimeMillis();
            var b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), new Date(now - 3_600_000L), new Date(now + 365L * 86_400_000L), name,
                    kp.getPublic());
            return b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())).getEncoded();
        } catch (Exception e) {
            throw new java.security.GeneralSecurityException(e);
        }
    }
}
