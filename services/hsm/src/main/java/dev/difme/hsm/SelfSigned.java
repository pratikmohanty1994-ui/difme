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
