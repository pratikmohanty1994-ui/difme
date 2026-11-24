package dev.difme.hsworker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;

/**
 * The PSP (Juspay Hyperswitch). DIFME is one merchant account on it ({@link #MERCHANT}), with one card connector: the
 * test processor, whose calls DIFME's acquirer answers over ISO 8583 from the card network. {@link #bootstrap()} sets
 * that up idempotently with the admin key and keeps the merchant API key in memory only.
 */
public final class Hyperswitch {
    public static final String MERCHANT = "difme_marketplace";
    static final String CONNECTOR = "stripe_test";   // Hyperswitch's test processor; its base URL points at our acquirer

    /** The card, only ever passed through to the PSP: never logged, stored or put in a workflow. */
    public record Card(String number, String expiryMonth, String expiryYear, String cvc, String holder) {
        @Override public String toString() { return "Card[****]"; }
    }

    /** Outcome of a charge or refund. errorCode is the card network's response code when it declined. */
    public record Outcome(String id, String status, long amountMinor, String errorCode, String errorMessage, String connectorRef) {
        public boolean succeeded() { return "succeeded".equals(status); }
        /** Authorised, not yet captured (charge with manual capture). */
        public boolean authorised() { return "requires_capture".equals(status); }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final URI base;
    private final String adminKey, acquirerKey;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private volatile String apiKey;

    public Hyperswitch(String baseUrl, String adminKey, String acquirerKey) {
        this.base = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
        this.adminKey = adminKey;
        this.acquirerKey = acquirerKey;
    }

    /** Creates (or finds) the merchant account and its card connector, and issues an API key for this process. */
    public synchronized void bootstrap() {
        if (apiKey != null) return;
        if (call("GET", "accounts/" + MERCHANT, null, adminKey, "admin-api-key").status() == 404) {
            ObjectNode m = JSON.createObjectNode();
            m.put("merchant_id", MERCHANT).put("merchant_name", "DIFME marketplace").put("return_url", "https://difme.local/return");
            ok(call("POST", "accounts", m, adminKey, "admin-api-key"), "create merchant");
        }
        ObjectNode k = JSON.createObjectNode();
        k.put("name", "hyperswitch-worker").put("description", "PH-EE card flows worker").put("expiration", "never");
        apiKey = ok(call("POST", "api_keys/" + MERCHANT, k, adminKey, "admin-api-key"), "create api key").path("api_key").asText();
        JsonNode connectors = ok(call("GET", "account/" + MERCHANT + "/connectors", null, adminKey, "admin-api-key"), "list connectors");
        for (JsonNode c : connectors) if (CONNECTOR.equals(c.path("connector_name").asText())) return;
        ObjectNode c = JSON.createObjectNode();
        c.put("connector_type", "payment_processor").put("connector_name", CONNECTOR).put("test_mode", true).put("disabled", false);
        c.putObject("connector_account_details").put("auth_type", "HeaderKey").put("api_key", acquirerKey);
        var pm = c.putArray("payment_methods_enabled").addObject().put("payment_method", "card").putArray("payment_method_types");
        for (String t : new String[] {"credit", "debit"}) {
            pm.addObject().put("payment_method_type", t).put("minimum_amount", 1).put("maximum_amount", 1_000_000_000)
                    .put("recurring_enabled", false).put("installment_payment_enabled", false);
        }
        ok(call("POST", "account/" + MERCHANT + "/connectors", c, adminKey, "admin-api-key"), "create card connector");
    }

    /** Charges a card (authorise + capture). paymentId is DIFME's id: a retry with the same id returns the first result. */
    public Outcome charge(String paymentId, long amountMinor, String currency, Card card, String description) {
        return charge(paymentId, amountMinor, currency, card, description, false);
    }

    /**
     * Charges a card; with authoriseOnly the payment stops at requires_capture, so a fraud check can run before money
     * is taken (then {@link #capture} or {@link #cancel}).
     */
    public Outcome charge(String paymentId, long amountMinor, String currency, Card card, String description, boolean authoriseOnly) {
        bootstrap();
        ObjectNode p = JSON.createObjectNode();
        p.put("payment_id", paymentId).put("amount", amountMinor).put("currency", currency).put("confirm", true)
                .put("capture_method", authoriseOnly ? "manual" : "automatic").put("payment_method", "card").put("payment_method_type", "credit")
                .put("description", description).put("authentication_type", "no_three_ds");
        p.putObject("payment_method_data").putObject("card").put("card_number", card.number()).put("card_exp_month", card.expiryMonth())
                .put("card_exp_year", card.expiryYear()).put("card_holder_name", card.holder()).put("card_cvc", card.cvc());
        Reply r = call("POST", "payments", p, apiKey, "api-key");
        if (r.status() >= 400 && duplicate(r.body())) return payment(paymentId);
        return payment(ok(r, "charge"));
    }

    /** Captures an authorised payment in full. Idempotent: an already captured payment is returned as it is. */
    public Outcome capture(String paymentId) {
        bootstrap();
        Outcome now = payment(paymentId);
        if (!now.authorised()) return now;
        return payment(ok(call("POST", "payments/" + paymentId + "/capture", JSON.createObjectNode(), apiKey, "api-key"), "capture"));
    }

    /** Releases an authorised payment without taking money (fraud interdiction, rejected review). Idempotent. */
    public Outcome cancel(String paymentId, String reason) {
        bootstrap();
        Outcome now = payment(paymentId);
        if (!now.authorised()) return now;
        ObjectNode b = JSON.createObjectNode().put("cancellation_reason", reason);
        return payment(ok(call("POST", "payments/" + paymentId + "/cancel", b, apiKey, "api-key"), "cancel"));
    }

    public Outcome payment(String paymentId) {
        bootstrap();
        return payment(ok(call("GET", "payments/" + paymentId, null, apiKey, "api-key"), "payment"));
    }

    /** Refunds part or all of a charge; refundId is DIFME's id and makes retries safe. */
    public Outcome refund(String refundId, String paymentId, long amountMinor, String reason) {
        bootstrap();
        ObjectNode b = JSON.createObjectNode();
        b.put("payment_id", paymentId).put("refund_id", refundId).put("amount", amountMinor).put("reason", reason).put("refund_type", "instant");
        Reply r = call("POST", "refunds", b, apiKey, "api-key");
        if (r.status() >= 400 && duplicate(r.body())) r = call("GET", "refunds/" + refundId, null, apiKey, "api-key");
        JsonNode n = ok(r, "refund");
        return new Outcome(n.path("refund_id").asText(refundId), n.path("status").asText(), n.path("amount").asLong(),
                text(n, "error_code"), text(n, "error_message"), text(n, "connector_refund_id"));
    }

    private static Outcome payment(JsonNode n) {
        return new Outcome(n.path("payment_id").asText(), n.path("status").asText(), n.path("amount").asLong(),
                text(n, "error_code"), text(n, "error_message"), text(n, "connector_transaction_id"));
    }

    private static boolean duplicate(JsonNode body) {
        String m = body.path("error").path("message").asText("").toLowerCase(Locale.ROOT);
        return m.contains("already exists") || m.contains("duplicate");
    }

    private static String text(JsonNode n, String f) { return n.hasNonNull(f) ? n.get(f).asText() : null; }

    // ── HTTP ────────────────────────────────────────────────────────────────────────────────────────────────────────

    private record Reply(int status, JsonNode body) {}

    private Reply call(String method, String path, ObjectNode body, String key, String header) {
        HttpRequest.Builder b = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json").header(header, key == null ? "" : key);
        if (body != null) b.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
        else b.method(method, HttpRequest.BodyPublishers.noBody());
        try {
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            JsonNode n = r.body() == null || r.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(r.body());
            return new Reply(r.statusCode(), n);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("PSP unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static JsonNode ok(Reply r, String what) {
        if (r.status() >= 200 && r.status() < 300) return r.body();
        String why = r.body().path("error").path("message").asText("HTTP " + r.status());
        if (r.status() >= 500 || r.status() == 429) throw new IllegalStateException("PSP " + what + ": " + why);   // retryable
        throw new IllegalArgumentException("PSP " + what + " refused: " + why);
    }
}
