package dev.difme.railsworker;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cards on file by reference ("ref:PAN:MMYY", comma-separated; "*" = the card for references without their own). PH-EE's
 * card flows carry only the reference, so card numbers stay in this worker's configuration (a Secret) and the PSP, never
 * in Fluxnova's process variables or history.
 */
final class CardsOnFile {
    private final Map<String, Hyperswitch.Card> cards = new LinkedHashMap<>();

    CardsOnFile(String spec) {
        if (spec == null) return;
        for (String e : spec.split(",")) {
            if (e.isBlank()) continue;
            String[] f = e.strip().split(":");
            if (f.length != 3 || !f[1].matches("\\d{12,19}") || !f[2].matches("\\d{4}")) {
                throw new IllegalArgumentException("cards on file: expected ref:PAN:MMYY, got an entry for " + (f.length > 0 ? f[0] : "?"));
            }
            // The PSP refuses a PAN that fails the Luhn check (cluster run 25); say so at start, not at the first charge.
            if (!luhn(f[1])) throw new IllegalArgumentException("cards on file: the PAN for " + f[0] + " fails the Luhn check");
            cards.put(f[0], new Hyperswitch.Card(f[1], f[2].substring(0, 2), "20" + f[2].substring(2), "123", "DIFME partner " + f[0]));
        }
    }

    static boolean luhn(String pan) {
        int sum = 0;
        for (int i = 0; i < pan.length(); i++) {
            int d = pan.charAt(pan.length() - 1 - i) - '0';
            if (i % 2 == 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
            sum += d;
        }
        return sum % 10 == 0;
    }

    /** The card for a reference, or the "*" card, or null. */
    Hyperswitch.Card card(String ref) {
        Hyperswitch.Card c = cards.get(ref);
        return c != null ? c : cards.get("*");
    }
}
