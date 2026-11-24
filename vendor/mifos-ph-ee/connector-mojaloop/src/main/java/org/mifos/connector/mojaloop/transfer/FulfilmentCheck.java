package org.mifos.connector.mojaloop.transfer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DIFME (D4): the payer checks the payee's ILP fulfilment at commit. FSPIOP: condition = base64url(SHA-256(fulfilment
 * bytes)), and only the payee, who issued the condition from its own secret, can produce the matching fulfilment. The
 * central switch normally checks this; DIFME's dev switch (Mojaloop Testing Toolkit in hub mode) does not, so without
 * this check a COMMITTED callback with any fulfilment would have the payer book the funds.
 *
 * The condition is remembered when the transfer is sent (transaction id -> condition, until the transfer's expiry) and
 * looked up when the payee's PUT /transfers/{id} arrives. Not persisted: after a connector restart between send and
 * callback the fulfilment can't be checked and the transfer is treated as failed (fail closed; the operator reconciles).
 */
public final class FulfilmentCheck {
    private record Pending(String condition, Instant expires) {}

    private static final int MAX = 100_000;
    private static final Map<String, Pending> PENDING = new ConcurrentHashMap<>();

    private FulfilmentCheck() {}

    /** Called when the transfer request goes to the switch. */
    public static void remember(String transactionId, String condition, Instant expires) {
        if (transactionId == null || condition == null) return;
        if (PENDING.size() >= MAX) prune(Instant.now());
        PENDING.put(transactionId, new Pending(condition, expires == null ? Instant.now().plusSeconds(3600) : expires));
    }

    /** null when the fulfilment proves the transfer; otherwise why it doesn't (the transfer must not be booked). */
    public static String verify(String transactionId, String fulfilment) {
        Pending p = transactionId == null ? null : PENDING.remove(transactionId);
        if (p == null) return "no condition on record for transfer " + transactionId + " (connector restarted?): fulfilment not verified";
        if (fulfilment == null || fulfilment.isBlank()) return "COMMITTED without a fulfilment";
        return matches(fulfilment, p.condition()) ? null : "fulfilment does not match the transfer's condition";
    }

    /** condition == base64url(SHA-256(base64url-decoded fulfilment)), both 32 bytes. */
    static boolean matches(String fulfilment, String condition) {
        try {
            byte[] f = decode(fulfilment), c = decode(condition);
            if (f.length != 32 || c.length != 32) return false;
            return MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(f), c);
        } catch (IllegalArgumentException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] decode(String s) {
        return Base64.getUrlDecoder().decode(s.trim().replace('+', '-').replace('/', '_').replace("=", ""));
    }

    private static void prune(Instant now) {
        for (Iterator<Map.Entry<String, Pending>> it = PENDING.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue().expires().isBefore(now)) it.remove();
        }
    }

    static void clear() { PENDING.clear(); }
}
