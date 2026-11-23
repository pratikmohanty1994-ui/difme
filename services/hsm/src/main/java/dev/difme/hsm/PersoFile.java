package dev.difme.hsm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DIFME card personalisation file, format "DIFME-PERSO/1": what a card bureau needs to personalise EMV chip cards,
 * with every secret under the transport key (KEK) agreed with the bureau. Plain text, one line per record, fields
 * separated by '|', each field {@code NAME=value} after the record type; values are digits, hex or TR-31 blocks.
 *
 * <pre>
 * HDR|FORMAT=DIFME-PERSO/1|ISSUER=&lt;BIN&gt;|CREATED=&lt;ISO-8601 UTC&gt;|KEK_KCV=&lt;6 hex&gt;|CA_INDEX=&lt;8F&gt;|ISSUER_CERT=&lt;90&gt;|ISSUER_REM=&lt;92&gt;|ISSUER_EXP=&lt;9F32&gt;
 * CARD|SEQ=1|PAN=…|PSN=00|EXP=YYMM|SVC=201|ICVV=…|MK_AC=&lt;TR-31 B&gt;|MK_SMI=&lt;TR-31 B&gt;|MK_SMC=&lt;TR-31 B&gt;|ICC_KEY=&lt;TR-31 B&gt;|ICC_CERT=&lt;9F46&gt;|ICC_EXP=&lt;9F47&gt;|ICC_REM=&lt;9F48&gt;|SAD=&lt;hex&gt;
 * …
 * TRL|COUNT=&lt;n&gt;|SHA256=&lt;hex of every preceding line, each with its LF&gt;
 * </pre>
 *
 * <ul>
 *   <li>MK_AC / MK_SMI / MK_SMC: the card's ICC master keys (EMV option A from the issuer master keys, PAN and PSN) as
 *       TR-31 version B blocks under the KEK, usages E0 / E2 / E1 (application cryptograms, secure-messaging integrity,
 *       confidentiality). Standard TR-31: the bureau's HSM imports them directly (psec reads them, tests).</li>
 *   <li>ICC_KEY: the card's RSA private key (PKCS#8 DER) as a TR-31 version B block, usage S0, algorithm R.</li>
 *   <li>ICC_CERT / ICC_EXP / ICC_REM: the ICC public key certificate (tag 9F46, EMV Book 2 format 04, signed by the
 *       issuer key inside the security module), exponent (9F47) and modulus remainder (9F48), over SAD, the static
 *       application data the bureau must write exactly as given.</li>
 *   <li>ICVV: the iCVV for track-2-equivalent data (CVV with service code 999). HDR carries the issuer public key
 *       certificate the scheme CA signed (8F, 90, 92, 9F32), the same for every card.</li>
 *   <li>The trailer's SHA-256 detects truncation and corruption; authenticity and confidentiality of the PAN come from
 *       the transfer channel (SFTP with PGP to the bureau), the keys are protected by the KEK.</li>
 * </ul>
 */
public final class PersoFile {
    public static final String FORMAT = "DIFME-PERSO/1";

    private PersoFile() {}

    /** One record: type (HDR, CARD, TRL) and its fields in order. */
    public record Record(String type, Map<String, String> fields) {
        public String get(String k) {
            String v = fields.get(k);
            if (v == null) throw new IllegalArgumentException(type + ": field " + k + " missing");
            return v;
        }

        String line() {
            StringBuilder b = new StringBuilder(type);
            fields.forEach((k, v) -> {
                if (v.indexOf('|') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('=') >= 0) throw new IllegalArgumentException("field " + k + ": bad value");
                b.append('|').append(k).append('=').append(v);
            });
            return b.append('\n').toString();
        }
    }

    public static Record record(String type, String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return new Record(type, m);
    }

    /** Writes header, cards and the trailer. */
    public static String write(Record header, List<Record> cards) {
        StringBuilder b = new StringBuilder(header.line());
        for (Record c : cards) b.append(c.line());
        String body = b.toString();
        return body + record("TRL", "COUNT", Integer.toString(cards.size()), "SHA256", sha256(body)).line();
    }

    /** Parses and checks a file: format, record types, count and digest. Returns header first, then the cards. */
    public static List<Record> parse(String file) {
        if (!file.endsWith("\n")) throw new IllegalArgumentException("truncated file");
        String[] lines = file.substring(0, file.length() - 1).split("\n", -1);
        List<Record> out = new ArrayList<>();
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String[] f = lines[i].split("\\|", -1);
            Map<String, String> m = new LinkedHashMap<>();
            for (int k = 1; k < f.length; k++) {
                int e = f[k].indexOf('=');
                if (e <= 0) throw new IllegalArgumentException("line " + (i + 1) + ": field without a name");
                m.put(f[k].substring(0, e), f[k].substring(e + 1));
            }
            Record r = new Record(f[0], m);
            boolean last = i == lines.length - 1;
            if (i == 0 && !(r.type().equals("HDR") && FORMAT.equals(m.get("FORMAT")))) throw new IllegalArgumentException("not a " + FORMAT + " file");
            if (last) {
                if (!r.type().equals("TRL")) throw new IllegalArgumentException("no trailer");
                if (Integer.parseInt(r.get("COUNT")) != out.size() - 1) throw new IllegalArgumentException("record count mismatch");
                if (!MessageDigest.isEqual(sha256(body.toString()).getBytes(StandardCharsets.US_ASCII), r.get("SHA256").getBytes(StandardCharsets.US_ASCII)))
                    throw new IllegalArgumentException("digest mismatch");
                return out;
            }
            if (i > 0 && !r.type().equals("CARD")) throw new IllegalArgumentException("line " + (i + 1) + ": unexpected " + r.type());
            body.append(lines[i]).append('\n');
            out.add(r);
        }
        throw new IllegalArgumentException("empty file");
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
