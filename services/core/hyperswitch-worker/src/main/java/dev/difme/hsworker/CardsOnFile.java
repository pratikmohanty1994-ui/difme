package dev.difme.hsworker;

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
            cards.put(f[0], new Hyperswitch.Card(f[1], f[2].substring(0, 2), "20" + f[2].substring(2), "123", "DIFME partner " + f[0]));
        }
    }

    /** The card for a reference, or the "*" card, or null. */
    Hyperswitch.Card card(String ref) {
        Hyperswitch.Card c = cards.get(ref);
        return c != null ? c : cards.get("*");
    }
}
