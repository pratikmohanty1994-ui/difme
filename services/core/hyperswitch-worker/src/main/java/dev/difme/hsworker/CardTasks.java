package dev.difme.hsworker;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The work of PH-EE's card flows. DifmeCardCheckout: hyperswitch-charge (authorise only), tazama-check (fraud check
 * before capture, ADR-023), then hyperswitch-capture or hyperswitch-cancel. DifmeCardRefund: hyperswitch-refund.
 * A decline is an answer (completed with chargeStatus=declined), not a failure; only an unreachable PSP or Fluxnova is a
 * failure, retried by Fluxnova.
 */
final class CardTasks {
    static final String CHARGE = "hyperswitch-charge", FRAUD = "tazama-check", CAPTURE = "hyperswitch-capture",
            CANCEL = "hyperswitch-cancel", REFUND = "hyperswitch-refund";
    static final java.util.List<String> TOPICS = java.util.List.of(CHARGE, FRAUD, CAPTURE, CANCEL, REFUND);

    /** The fraud check (Tazama.evaluate); null when the fraud profile isn't installed: every payment is captured. */
    interface Fraud {
        Tazama.Evaluation evaluate(String paymentId, String payer, String merchant, long amountMinor, String currency);
    }

    private final Hyperswitch psp;
    private final CardsOnFile cards;
    private final Fraud fraud;
    private final boolean failOpen;

    CardTasks(Hyperswitch psp, CardsOnFile cards) {
        this(psp, cards, null, false);
    }

    CardTasks(Hyperswitch psp, CardsOnFile cards, Fraud fraud, boolean failOpen) {
        this.psp = psp;
        this.cards = cards;
        this.fraud = fraud;
        this.failOpen = failOpen;
    }

    Map<String, Object> handle(Fluxnova.Task t) {
        return switch (t.topic()) {
            case CHARGE -> charge(t);
            case FRAUD -> fraudCheck(t);
            case CAPTURE -> capture(t);
            case CANCEL -> cancel(t);
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
        // Authorise only: money is taken at capture, after the fraud check. A retry with the same paymentId returns the
        // first result from Hyperswitch, so a retried task never authorises twice.
        Hyperswitch.Outcome o = psp.charge(t.str("paymentId"), t.num("amountMinor"), currency, card, t.str("description"), true);
        out.put("pspPaymentId", o.id());
        if (o.authorised() || o.succeeded()) {
            out.put("chargeStatus", o.succeeded() ? "succeeded" : "authorised");
        } else {
            out.put("chargeStatus", "declined");
            // The scheme's response code when the acquirer passed it through ("51: ..."), else a generic decline.
            String msg = o.errorMessage() == null ? o.status() : o.errorMessage();
            out.put("declineCode", msg != null && msg.length() >= 2 && Character.isDigit(msg.charAt(0)) && Character.isDigit(msg.charAt(1)) ? msg.substring(0, 2) : "05");
            out.put("declineMessage", msg);
        }
        return out;
    }

    /** fraudAction: capture (no alert, or no fraud profile), review (alert; no verdict unless failOpen), cancel (interdiction). */
    private Map<String, Object> fraudCheck(Fluxnova.Task t) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (fraud == null) {
            out.put("fraudVerdict", "OFF");
            out.put("fraudDetail", "no fraud check configured");
            out.put("fraudAction", "capture");
            return out;
        }
        String payer = t.str("payer") == null || t.str("payer").isBlank() ? "unknown-payer" : t.str("payer");
        Tazama.Evaluation e = fraud.evaluate(t.str("paymentId"), payer, t.str("merchant"), t.num("amountMinor"),
                t.str("currency") == null ? "INR" : t.str("currency"));
        String action = switch (e.verdict()) {
            case NO_ALERT -> "capture";
            case INTERDICT -> "cancel";
            case ALERT -> "review";
            case UNKNOWN -> failOpen ? "capture" : "review";
        };
        out.put("fraudVerdict", e.verdict().name());
        out.put("fraudDetail", e.detail());
        out.put("fraudAction", action);
        if ("review".equals(action)) {
            out.put("chargeStatus", "review");
            out.put("declineMessage", (e.verdict() == Tazama.Verdict.ALERT ? "fraud alert: " : "no fraud verdict: ") + e.detail());
        }
        return out;
    }

    private Map<String, Object> capture(Fluxnova.Task t) {
        Map<String, Object> out = new LinkedHashMap<>();
        Hyperswitch.Outcome o = psp.capture(t.str("paymentId"));
        out.put("chargeStatus", o.succeeded() ? "succeeded" : "failed");
        if (!o.succeeded()) out.put("declineMessage", "capture: " + o.status() + " " + o.errorMessage());
        return out;
    }

    private Map<String, Object> cancel(Fluxnova.Task t) {
        Map<String, Object> out = new LinkedHashMap<>();
        Hyperswitch.Outcome o = psp.cancel(t.str("paymentId"), "fraud");
        out.put("chargeStatus", "declined");
        out.put("declineCode", "59");   // ISO 8583: suspected fraud
        out.put("declineMessage", "FRAUD: " + t.str("fraudDetail") + " (authorisation " + o.status() + ")");
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
