package dev.difme.exchange.svc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.difme.exchange.rails.PaymentHub;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Escrow money movements through Mifos PH-EE instead of the interim hub (ADR-022, D3). A movement is an on-us transfer:
 * the channel ({@code POST /channel/transfer}, payee in the same FSP) starts DifmeOnUsTransfer (patch ph-ee-channel/0002),
 * which quotes, blocks, credits and books inside Fineract. Money arriving from outside DIFME's books (a deposit) is a
 * transfer from the card settlement account, which may go below zero like the hub's settlement accounts.
 *
 * <p>Status: PH-EE's operations app is not deployed, so the outcome is read from Fluxnova's history. The instance carries
 * {@code clientCorrelationId} = the movement id (X-CorrelationID); its end event says how it ended (done, failed, or
 * operator: funds blocked, an operator must look). Idempotency: before starting, the movement id is looked up, so a retry
 * after a lost answer never starts a second transfer. An unfinished transfer throws (the caller retries later).
 *
 * <p>Card payments: PH-EE's DifmeCardCheckout flow (one task, answered by services/core/hyperswitch-worker through
 * Hyperswitch), started directly in Fluxnova with business key = the payment id, then the merchant is credited with an
 * on-us transfer from the card settlement account; if that is refused the card is refunded (DifmeCardRefund). Refunds:
 * the merchant is debited back to the settlement account first, then the card is refunded; a refused card refund undoes
 * the debit. The flows carry only the card's reference (CardOnFile.ref), never its number. Without {@code cardFlows},
 * card payments stay on the hub ({@code cards}).
 */
final class PhEePaymentHub implements PaymentHub {
    static final String TENANT = "default";
    static final String FLOW = "DifmeOnUsTransfer-" + TENANT;
    static final String CHECKOUT = "DifmeCardCheckout-" + TENANT, REFUND = "DifmeCardRefund-" + TENANT;
    static final String OPEN_ACCOUNT = "DifmeOpenAccount-" + TENANT;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final PaymentHub cards;
    private final URI channel, fluxnova;
    private final Supplier<String> channelAuth, fluxnovaAuth;
    private final String settlementAccount;
    private final Duration wait;
    private final boolean cardFlows;
    private volatile boolean openAccounts;
    /** Accounts known to be open in Fineract with their ACCOUNT_ID (this process; a restart asks the flow history again). */
    private final java.util.Set<String> open = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    PhEePaymentHub(PaymentHub cards, String channelUrl, Supplier<String> channelAuth, String fluxnovaEngineUrl,
                   Supplier<String> fluxnovaAuth, String settlementAccount, Duration wait) {
        this(cards, channelUrl, channelAuth, fluxnovaEngineUrl, fluxnovaAuth, settlementAccount, wait, false);
    }

    PhEePaymentHub(PaymentHub cards, String channelUrl, Supplier<String> channelAuth, String fluxnovaEngineUrl,
                   Supplier<String> fluxnovaAuth, String settlementAccount, Duration wait, boolean cardFlows) {
        this.cardFlows = cardFlows;
        this.cards = cards;
        this.channel = URI.create(slash(channelUrl));
        this.fluxnova = URI.create(slash(fluxnovaEngineUrl));
        this.channelAuth = channelAuth;
        this.fluxnovaAuth = fluxnovaAuth;
        this.settlementAccount = settlementAccount;
        this.wait = wait;
    }

    /**
     * With account opening on, every account is opened through PH-EE's DifmeOpenAccount flow (rails-worker → Fineract:
     * client + savings account + interop identifier ACCOUNT_ID) before its first transfer, as the interim hub did on
     * first use. Business key "open-<name>": a second run for the same account finds the first one.
     */
    PhEePaymentHub openAccounts(boolean on) {
        this.openAccounts = on;
        return this;
    }

    /** Opens the account if this process hasn't seen it open; a rejected name refuses the movement. */
    Outcome ensureOpen(String account) {
        if (!openAccounts || open.contains(account)) return null;
        Map<String, String> r = runFlow(OPEN_ACCOUNT, "open-" + account, Map.of("accountName", account));
        if (!"open".equals(r.get("accountStatus"))) {
            return new Outcome("REJECTED", "account " + account + " can't be opened: " + r.getOrDefault("accountMessage", r.get("accountStatus")));
        }
        open.add(account);
        return null;
    }

    @Override
    public Outcome deposit(String id, String account, long amountMinor) {
        return transfer(id, settlementAccount, account, amountMinor, "deposit " + id);
    }

    @Override
    public Outcome transfer(String id, String from, String to, long amountMinor, String note) {
        if (amountMinor <= 0) return new Outcome("REJECTED", "amount must be positive");
        for (String a : new String[] {from, to}) {
            Outcome refused = ensureOpen(a);
            if (refused != null) return refused;
        }
        Outcome known = outcome(id);
        if (known == null) {
            start(id, from, to, amountMinor, note);
            long until = System.nanoTime() + wait.toNanos();
            while (known == null && System.nanoTime() < until) {
                sleep(250);
                known = outcome(id);
            }
        }
        if (known == null) throw new IllegalStateException("PH-EE transfer " + id + " not finished yet");   // retried later
        return known;
    }

    @Override
    public Outcome payCard(String paymentId, String merchant, long amountMinor, CardOnFile card) {
        if (!cardFlows) return cards.payCard(paymentId, merchant, amountMinor, card);
        if (card.ref() == null) return new Outcome("DECLINED", "14: card has no reference for the PSP worker");
        Map<String, Object> vars = new LinkedHashMap<>();
        vars.put("paymentId", paymentId); vars.put("merchant", merchant); vars.put("amountMinor", amountMinor);
        vars.put("currency", "INR"); vars.put("cardRef", card.ref());
        vars.put("payer", "*".equals(card.ref()) ? "partner-default" : "partner-" + card.ref());   // Tazama's payer id, never the card
        vars.put("description", "DIFME card payment " + paymentId);
        Map<String, String> r = runFlow(CHECKOUT, paymentId, vars);
        String charge = r.getOrDefault("chargeStatus", "");
        // Fraud alert (or no verdict, failing closed): authorised, held for review, no money taken (ADR-023).
        if ("review".equals(charge)) return new Outcome("REVIEW", r.getOrDefault("declineMessage", "held for review"));
        if ("failed".equals(charge)) return new Outcome("FAILED", r.getOrDefault("declineMessage", "capture failed"));
        if (!"succeeded".equals(charge)) {
            return new Outcome("DECLINED", r.getOrDefault("declineCode", "05") + ": " + r.getOrDefault("declineMessage", "declined"));
        }
        String account = "merchant-" + merchant;
        Outcome credit = transfer(paymentId + ":settle", settlementAccount, account, amountMinor, "card payment " + paymentId);
        if ("DONE".equals(credit.status())) return new Outcome("SETTLED", account + " credited");
        // The merchant can't be credited: give the cardholder the money back rather than leave it in limbo.
        Map<String, String> back = runFlow(REFUND, paymentId + "-unwind",
                refundVars(paymentId + "-unwind", paymentId, amountMinor, "settlement failed"));
        return "succeeded".equals(back.get("refundStatus"))
                ? new Outcome("REFUNDED", "merchant credit failed (" + credit.detail() + "); card refunded")
                : new Outcome("FAILED", "merchant credit failed (" + credit.detail() + ") and the refund was refused: needs an operator");
    }

    @Override
    public Outcome refundCard(String refundId, String paymentId, String merchant, long amountMinor, String reason) {
        if (!cardFlows) return cards.refundCard(refundId, paymentId, merchant, amountMinor, reason);
        String account = "merchant-" + merchant;
        Outcome debit = transfer(refundId + ":debit", account, settlementAccount, amountMinor, "refund " + refundId);
        if (!"DONE".equals(debit.status())) return debit;
        Map<String, String> r = runFlow(REFUND, refundId, refundVars(refundId, paymentId, amountMinor, reason));
        if ("succeeded".equals(r.get("refundStatus"))) return new Outcome("REFUNDED", "card refund " + r.getOrDefault("refundMessage", ""));
        transfer(refundId + ":undo", settlementAccount, account, amountMinor, "refund " + refundId + " undone");
        return new Outcome("FAILED", "card refund refused (" + r.get("refundMessage") + "); merchant debit undone");
    }

    private static Map<String, Object> refundVars(String refundId, String paymentId, long amountMinor, String reason) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("refundId", refundId); v.put("paymentId", paymentId); v.put("amountMinor", amountMinor); v.put("reason", reason);
        return v;
    }

    // ── card flows in Fluxnova ──────────────────────────────────────────────────────────────────────────────────────

    /** Runs a card flow once per business key (a retry finds the earlier instance) and returns its final variables. */
    Map<String, String> runFlow(String definition, String businessKey, Map<String, Object> vars) {
        String id = instance(definition, businessKey);
        if (id == null) id = startFlow(definition, businessKey, vars);
        long until = System.nanoTime() + wait.toNanos();
        while (true) {
            JsonNode p = get("history/process-instance/" + enc(id));
            String state = p == null ? "" : p.path("state").asText();
            if ("COMPLETED".equals(state)) break;
            if (state.contains("TERMINATED")) throw new IllegalStateException(definition + " " + businessKey + " " + state);
            if (System.nanoTime() > until) throw new IllegalStateException(definition + " " + businessKey + " not finished yet");
            sleep(250);
        }
        Map<String, String> out = new LinkedHashMap<>();
        JsonNode all = get("history/variable-instance?processInstanceId=" + enc(id));
        if (all != null) for (JsonNode v : all) out.put(v.path("name").asText(), v.path("value").isNull() ? null : v.path("value").asText());
        return out;
    }

    private String instance(String definition, String businessKey) {
        JsonNode l = get("history/process-instance?processDefinitionKey=" + enc(definition) + "&processInstanceBusinessKey=" + enc(businessKey));
        return l != null && l.isArray() && !l.isEmpty() ? l.get(0).path("id").asText() : null;
    }

    private String startFlow(String definition, String businessKey, Map<String, Object> vars) {
        ObjectNode b = JSON.createObjectNode().put("businessKey", businessKey);
        ObjectNode v = b.putObject("variables");
        vars.forEach((k, val) -> {
            ObjectNode e = v.putObject(k);
            if (val instanceof Long l) e.put("value", l).put("type", "Long");
            else e.put("value", String.valueOf(val)).put("type", "String");
        });
        HttpResponse<String> r = send(HttpRequest.newBuilder(fluxnova.resolve("process-definition/key/" + enc(definition) + "/start"))
                .timeout(Duration.ofSeconds(15)).header("Content-Type", "application/json").header("Authorization", fluxnovaAuth.get())
                .POST(HttpRequest.BodyPublishers.ofString(b.toString())).build(), "Fluxnova");
        if (r.statusCode() / 100 != 2) throw new IllegalStateException("Fluxnova start " + definition + ": HTTP " + r.statusCode() + " " + head(r.body()));
        try {
            return JSON.readTree(r.body()).path("id").asText();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Fluxnova start answered without JSON");
        }
    }

    // ── PH-EE channel ───────────────────────────────────────────────────────────────────────────────────────────────

    private void start(String id, String from, String to, long amountMinor, String note) {
        ObjectNode b = JSON.createObjectNode();
        b.putObject("payer").putObject("partyIdInfo").put("partyIdType", "ACCOUNT_ID").put("partyIdentifier", from);
        b.putObject("payee").putObject("partyIdInfo").put("partyIdType", "ACCOUNT_ID").put("partyIdentifier", to).put("fspId", TENANT);
        b.putObject("amount").put("amount", java.math.BigDecimal.valueOf(amountMinor).movePointLeft(2).toPlainString()).put("currency", "INR");
        b.put("note", note);
        HttpResponse<String> r = send(HttpRequest.newBuilder(channel.resolve("channel/transfer")).timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json").header("Platform-TenantId", TENANT).header("X-CorrelationID", id)
                .header("Authorization", channelAuth.get()).POST(HttpRequest.BodyPublishers.ofString(b.toString())).build(), "channel");
        if (r.statusCode() / 100 != 2) throw new IllegalStateException("PH-EE channel HTTP " + r.statusCode() + ": " + head(r.body()));
    }

    // ── Fluxnova history ────────────────────────────────────────────────────────────────────────────────────────────

    /** The movement's outcome, or null when no instance for it has finished (or none exists yet). */
    Outcome outcome(String id) {
        JsonNode instances = get("history/process-instance?processDefinitionKey=" + enc(FLOW)
                + "&variables=" + enc("clientCorrelationId_eq_" + id) + "&sortBy=startTime&sortOrder=desc");
        if (instances == null || !instances.isArray() || instances.isEmpty()) return null;
        JsonNode p = instances.get(0);
        String state = p.path("state").asText();
        if (!"COMPLETED".equals(state)) {
            return state.startsWith("EXTERNALLY_TERMINATED") || state.startsWith("INTERNALLY_TERMINATED")
                    ? new Outcome("FAILED", "transfer instance " + p.path("id").asText() + " " + state) : null;
        }
        JsonNode ends = get("history/activity-instance?processInstanceId=" + enc(p.path("id").asText()) + "&activityType=noneEndEvent");
        String end = ends != null && ends.isArray() && !ends.isEmpty() ? ends.get(0).path("activityId").asText() : "";
        return switch (end) {
            case "done" -> new Outcome("DONE", p.path("id").asText());
            case "failed" -> new Outcome("REJECTED", "refused by the core banking system (DifmeOnUsTransfer failed)");
            default -> new Outcome("FAILED", "transfer ended at '" + end + "': funds may be blocked, an operator must look");
        };
    }

    private JsonNode get(String path) {
        HttpResponse<String> r = send(HttpRequest.newBuilder(fluxnova.resolve(path)).timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json").header("Authorization", fluxnovaAuth.get()).GET().build(), "Fluxnova");
        if (r.statusCode() == 404) return null;
        if (r.statusCode() / 100 != 2) throw new IllegalStateException("Fluxnova HTTP " + r.statusCode() + ": " + head(r.body()));
        try {
            return JSON.readTree(r.body());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Fluxnova answered without JSON");
        }
    }

    private HttpResponse<String> send(HttpRequest r, String what) {
        try {
            return http.send(r, HttpResponse.BodyHandlers.ofString());
        } catch (java.io.IOException e) {
            throw new IllegalStateException(what + " unreachable: " + e.getMessage(), e);   // retryable
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static String slash(String u) { return u.endsWith("/") ? u : u + "/"; }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    private static String head(String s) { return s == null ? "" : s.length() > 300 ? s.substring(0, 300) : s; }
}
