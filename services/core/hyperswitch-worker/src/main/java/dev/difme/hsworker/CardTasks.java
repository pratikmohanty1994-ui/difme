package dev.difme.hsworker;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The work of PH-EE's card flows: hyperswitch-charge (DifmeCardCheckout) and hyperswitch-refund (DifmeCardRefund).
 * A decline is an answer (completed with chargeStatus=declined), not a failure; only an unreachable PSP or Fluxnova is a
 * failure, retried by Fluxnova.
 */
final class CardTasks {
    static final String CHARGE = "hyperswitch-charge", REFUND = "hyperswitch-refund";

    private final Hyperswitch psp;
    private final CardsOnFile cards;

    CardTasks(Hyperswitch psp, CardsOnFile cards) {
        this.psp = psp;
        this.cards = cards;
    }

    Map<String, Object> handle(Fluxnova.Task t) {
        return switch (t.topic()) {
            case CHARGE -> charge(t);
            case REFUND -> refund(t);
            default -> throw new IllegalArgumentException("unknown topic " + t.topic());
        };
    }

    private Map<String, Object> charge(Fluxnova.Task t) {
        Map<String, Object> out = new LinkedHashMap<>();
        Hyperswitch.Card card = cards.card(t.str("cardRef"));
        if (card == null) {
            out.put("chargeStatus", "declined");
            out.put("declineCode", "14");
            out.put("declineMessage", "no card on file for reference " + t.str("cardRef"));
            return out;
        }
        String currency = t.str("currency") == null ? "INR" : t.str("currency");
        Hyperswitch.Outcome o = psp.charge(t.str("paymentId"), t.num("amountMinor"), currency, card, t.str("description"));
        out.put("pspPaymentId", o.id());
        if (o.succeeded()) {
            out.put("chargeStatus", "succeeded");
        } else {
            out.put("chargeStatus", "declined");
            // The scheme's response code when the acquirer passed it through ("51: ..."), else a generic decline.
            String msg = o.errorMessage() == null ? o.status() : o.errorMessage();
            out.put("declineCode", msg != null && msg.length() >= 2 && Character.isDigit(msg.charAt(0)) && Character.isDigit(msg.charAt(1)) ? msg.substring(0, 2) : "05");
            out.put("declineMessage", msg);
        }
        return out;
    }

    private Map<String, Object> refund(Fluxnova.Task t) {
        Map<String, Object> out = new LinkedHashMap<>();
        Hyperswitch.Outcome o = psp.refund(t.str("refundId"), t.str("paymentId"), t.num("amountMinor"), t.str("reason"));
        boolean ok = "succeeded".equals(o.status()) || "pending".equals(o.status());
        out.put("refundStatus", ok ? "succeeded" : "failed");
        out.put("refundMessage", o.errorMessage() == null ? o.status() : o.errorMessage());
        return out;
    }
}
