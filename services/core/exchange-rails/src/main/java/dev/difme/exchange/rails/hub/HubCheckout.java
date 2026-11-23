package dev.difme.exchange.rails.hub;

import dev.difme.exchange.rails.Iso8583;
import dev.difme.exchange.rails.MerchantCheckoutPort;
import dev.difme.exchange.rails.PaymentHub;
import dev.difme.exchange.rails.sim.SimAgentCredential;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Merchant checkout over the real rails: the agent token is redeemed as before, then the winning partner's card on
 * file is charged through the payment hub (PSP → acquirer → card network → issuer). The network's response code is
 * what the exchange's failover sees, so 51 / 05 / 54 behave exactly as with the simulator.
 */
public final class HubCheckout implements MerchantCheckoutPort {
    private record Paid(String paymentId, String merchant, long amountMinor) {}

    /** Card map key for the default card of partners without their own ("*" in the configuration; simulator setups). */
    public static final long ANY_PARTNER = -1L;

    private final SimAgentCredential credentials;
    private final PaymentHub hub;
    private final Map<Long, PaymentHub.CardOnFile> cards;
    private final Map<String, Response> byStan = new ConcurrentHashMap<>();
    private final Map<String, Paid> paid = new ConcurrentHashMap<>();

    public HubCheckout(SimAgentCredential credentials, PaymentHub hub, Map<Long, PaymentHub.CardOnFile> cards) {
        this.credentials = credentials;
        this.hub = hub;
        this.cards = Map.copyOf(cards);
    }

    @Override
    public Response authorize(Authorization a, long nowMs) {
        Response known = byStan.get(a.stan());
        if (known != null) return known;            // duplicate 0100: the original answer
        Response r = decide(a, nowMs);
        byStan.put(a.stan(), r);
        if (byStan.size() > 100_000) byStan.clear();
        return r;
    }

    private Response decide(Authorization a, long nowMs) {
        var instruction = credentials.instructionOf(a.token()).orElse(null);
        if (instruction == null) return new Response(a.stan(), Iso8583.DO_NOT_HONOUR, null, null);
        PaymentHub.CardOnFile card = cards.getOrDefault(instruction.partnerId(), cards.get(ANY_PARTNER));
        if (card == null) return new Response(a.stan(), "14", null, null);        // no card on file for this partner
        if (!credentials.redeem(a.token(), a.merchantId(), a.amountMinor(), nowMs)) {
            return new Response(a.stan(), Iso8583.DO_NOT_HONOUR, null, null);
        }
        String paymentId = "auc" + instruction.mandateId().getMostSignificantBits() + "-p" + instruction.partnerId() + "-" + a.stan();
        String merchant = merchantName(a.merchantId());
        PaymentHub.Outcome o;
        try {
            o = hub.payCard(paymentId, merchant, a.amountMinor(), card);
        } catch (RuntimeException e) {
            return new Response(a.stan(), "91", null, null);                       // rails unreachable: issuer unavailable
        }
        switch (o.status()) {
            case "SETTLED" -> {
                paid.put(paymentId, new Paid(paymentId, merchant, a.amountMinor()));
                return new Response(a.stan(), Iso8583.APPROVED, approvalCode(paymentId), paymentId);
            }
            case "DECLINED" -> {
                String d = o.detail() == null ? "" : o.detail();
                String code = d.length() >= 2 && Character.isDigit(d.charAt(0)) && Character.isDigit(d.charAt(1)) ? d.substring(0, 2) : "05";
                return new Response(a.stan(), code, null, null);
            }
            default -> {
                return new Response(a.stan(), "96", null, null);                   // charged but not settled (refunded): system error
            }
        }
    }

    /** Reverses an approved payment: a full card refund through the hub (idempotent by the payment id). */
    @Override
    public void reverse(String rrn) {
        Paid p = paid.get(rrn);
        if (p == null) return;
        PaymentHub.Outcome o = hub.refundCard("rev-" + p.paymentId(), p.paymentId(), p.merchant(), p.amountMinor(), "reversal");
        if ("REFUNDED".equals(o.status())) paid.remove(rrn);
        else throw new IllegalStateException("reversal of " + rrn + " not done: " + o.status() + " " + o.detail());
    }

    /** Hub account names are lower-case letters, digits and dashes. */
    static String merchantName(String merchantId) {
        String m = merchantId.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9-]", "-");
        return m.length() > 40 ? m.substring(0, 40) : m;
    }

    private static String approvalCode(String paymentId) {
        return String.format("%06d", Math.floorMod(paymentId.hashCode(), 1_000_000));
    }
}
