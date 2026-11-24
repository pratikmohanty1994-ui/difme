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
 * <p>Card payments and refunds stay on the hub ({@code cards}) until card checkout has its own home.
 */
final class PhEePaymentHub implements PaymentHub {
    static final String TENANT = "default";
    static final String FLOW = "DifmeOnUsTransfer-" + TENANT;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final PaymentHub cards;
    private final URI channel, fluxnova;
    private final Supplier<String> channelAuth, fluxnovaAuth;
    private final String settlementAccount;
    private final Duration wait;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    PhEePaymentHub(PaymentHub cards, String channelUrl, Supplier<String> channelAuth, String fluxnovaEngineUrl,
                   Supplier<String> fluxnovaAuth, String settlementAccount, Duration wait) {
        this.cards = cards;
        this.channel = URI.create(slash(channelUrl));
        this.fluxnova = URI.create(slash(fluxnovaEngineUrl));
        this.channelAuth = channelAuth;
        this.fluxnovaAuth = fluxnovaAuth;
        this.settlementAccount = settlementAccount;
        this.wait = wait;
    }

    @Override
    public Outcome deposit(String id, String account, long amountMinor) {
        return transfer(id, settlementAccount, account, amountMinor, "deposit " + id);
    }

    @Override
    public Outcome transfer(String id, String from, String to, long amountMinor, String note) {
        if (amountMinor <= 0) return new Outcome("REJECTED", "amount must be positive");
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
        return cards.payCard(paymentId, merchant, amountMinor, card);
    }

    @Override
    public Outcome refundCard(String refundId, String paymentId, String merchant, long amountMinor, String reason) {
        return cards.refundCard(refundId, paymentId, merchant, amountMinor, reason);
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
