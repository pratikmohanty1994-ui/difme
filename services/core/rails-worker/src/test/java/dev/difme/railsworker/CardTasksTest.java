package dev.difme.railsworker;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Fluxnova's external-task API and Hyperswitch faked in one HTTP server. */
class CardTasksTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private HttpServer server;
    private final List<String> pending = new CopyOnWriteArrayList<>();     // task JSON handed out by fetchAndLock
    private final Map<String, JsonNode> completed = new ConcurrentHashMap<>();
    private final Map<String, JsonNode> failed = new ConcurrentHashMap<>();
    private final List<String> charged = new CopyOnWriteArrayList<>();
    private volatile boolean pspDown;
    private volatile boolean merchantCreated;
    private final Map<String, String> state = new ConcurrentHashMap<>();   // Hyperswitch payment status by id
    private final List<String> psp = new CopyOnWriteArrayList<>();         // captures and cancels
    private Fluxnova fx;
    private CardTasks tasks;

    private static void reply(HttpExchange x, int code, String json) throws java.io.IOException {
        byte[] r = json.getBytes();
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(code, r.length == 0 ? -1 : r.length);
        if (r.length > 0) x.getResponseBody().write(r);
        x.close();
    }

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/engine-rest/external-task", x -> {
            String p = x.getRequestURI().getPath();
            JsonNode b = JSON.readTree(x.getRequestBody());
            if (p.endsWith("/fetchAndLock")) {
                String out = "[" + String.join(",", pending) + "]";
                pending.clear();
                reply(x, 200, out);
            } else if (p.endsWith("/complete")) {
                completed.put(p.split("/")[3], b.path("variables"));
                reply(x, 204, "");
            } else if (p.endsWith("/failure")) {
                failed.put(p.split("/")[3], b);
                reply(x, 204, "");
            }
        });
        // Hyperswitch: bootstrap (merchant exists, key, connector present), payments, refunds
        // As the router: GET /accounts/{id} of a merchant that doesn't exist answers 401 (admin auth fails on the route's
        // merchant, then API-key fallback); POST /accounts (admin) creates it.
        server.createContext("/accounts", x -> {
            boolean admin = "admin-api-key=admin".equals(x.getRequestHeaders().getFirst("Authorization"));
            if ("POST".equals(x.getRequestMethod()) && admin) { merchantCreated = true; reply(x, 200, "{}"); return; }
            if (admin && merchantCreated) { reply(x, 200, "{}"); return; }
            reply(x, 401, "{\"error\":{\"message\":\"API key not provided or invalid\"}}");
        });
        // Hyperswitch's admin auth reads "Authorization: admin-api-key=<key>" (router authentication.rs, V2AdminApiAuth);
        // anything else is 401, as the real router answered both "admin-api-key: <key>" and "api-key: <key>" (runs 18, 20).
        server.createContext("/api_keys/", x -> {
            if (!"admin-api-key=admin".equals(x.getRequestHeaders().getFirst("Authorization")) || !merchantCreated) { reply(x, 401, "{\"error\":{\"message\":\"API key not provided or invalid\"}}"); return; }
            reply(x, 200, "{\"api_key\":\"k\"}");
        });
        server.createContext("/account/", x -> reply(x, 200, "[{\"connector_name\":\"stripe_test\"}]"));
        server.createContext("/payments", x -> {
            if (pspDown) { reply(x, 503, "{\"error\":{\"message\":\"down\"}}"); return; }
            String path = x.getRequestURI().getPath();
            if (!path.equals("/payments")) {                       // GET /payments/{id}, POST .../capture, .../cancel
                String[] seg = path.split("/");
                String id = seg[2];
                if (seg.length > 3) { psp.add(seg[3] + " " + id); state.put(id, seg[3].equals("capture") ? "succeeded" : "cancelled"); }
                reply(x, 200, "{\"payment_id\":\"" + id + "\",\"status\":\"" + state.get(id) + "\",\"amount\":1}");
                return;
            }
            JsonNode b = JSON.readTree(x.getRequestBody());
            String pan = b.at("/payment_method_data/card/card_number").asText();
            String id = b.path("payment_id").asText();
            charged.add(id + " " + pan + " " + b.path("amount").asLong() + " " + b.path("capture_method").asText());
            boolean ok = !pan.endsWith("0015");
            state.put(id, ok ? "requires_capture" : "failed");
            reply(x, 200, "{\"payment_id\":\"" + id + "\",\"status\":\"" + state.get(id)
                    + "\",\"amount\":" + b.path("amount").asLong() + (ok ? "" : ",\"error_message\":\"51: Insufficient funds\"") + "}");
        });
        server.createContext("/refunds", x -> {
            JsonNode b = JSON.readTree(x.getRequestBody());
            reply(x, 200, "{\"refund_id\":\"" + b.path("refund_id").asText() + "\",\"status\":\"succeeded\",\"amount\":" + b.path("amount").asLong() + "}");
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        fx = new Fluxnova(base + "/engine-rest", "admin:x", "w1");
        tasks = new CardTasks(new Hyperswitch(base, "admin", "acq"), new CardsOnFile("1:4375510000000007:1230,2:4375510000000015:1230,*:4375510000000007:1230"));
    }

    @AfterEach
    void stop() { server.stop(0); }

    private void task(String id, String topic, Map<String, Object> vars) throws Exception {
        var v = JSON.createObjectNode();
        vars.forEach((k, val) -> v.putObject(k).putPOJO("value", val));
        pending.add(JSON.writeValueAsString(Map.of("id", id, "topicName", topic, "retries", 3, "variables", v)));
    }

    @Test
    void chargesDeclinesAndRefunds() throws Exception {
        task("t1", CardTasks.CHARGE, Map.of("paymentId", "auc1-p1-000001", "amountMinor", 1600000, "currency", "INR", "cardRef", "1", "description", "buy"));
        task("t2", CardTasks.CHARGE, Map.of("paymentId", "auc2-p2-000002", "amountMinor", 500, "cardRef", "2", "description", "buy"));
        task("t3", CardTasks.CHARGE, Map.of("paymentId", "auc3-p1000002-000003", "amountMinor", 700, "cardRef", "1000002", "description", "buy"));
        task("t4", CardTasks.REFUND, Map.of("refundId", "rev-auc1", "paymentId", "auc1-p1-000001", "amountMinor", 1600000, "reason", "reversal"));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("authorised", completed.get("t1").at("/chargeStatus/value").asText());
        assertEquals("auc1-p1-000001", completed.get("t1").at("/pspPaymentId/value").asText());
        assertEquals("declined", completed.get("t2").at("/chargeStatus/value").asText());
        assertEquals("51", completed.get("t2").at("/declineCode/value").asText());
        assertEquals("authorised", completed.get("t3").at("/chargeStatus/value").asText());   // "*" card for a standing mandate
        assertEquals("succeeded", completed.get("t4").at("/refundStatus/value").asText());
        assertEquals(List.of("auc1-p1-000001 4375510000000007 1600000 manual", "auc2-p2-000002 4375510000000015 500 manual",
                "auc3-p1000002-000003 4375510000000007 700 manual"), charged);
        assertTrue(completed.values().stream().noneMatch(v -> v.toString().contains("4375510000")), "no card number in process variables");
    }

    @Test
    void noCardIsADeclineAndAnUnreachablePspIsRetried() throws Exception {
        tasks = new CardTasks(new Hyperswitch("http://127.0.0.1:" + server.getAddress().getPort(), "a", "b"), new CardsOnFile("1:4375510000000007:1230"));
        task("t5", CardTasks.CHARGE, Map.of("paymentId", "p5", "amountMinor", 1, "cardRef", "9"));
        pspDown = true;
        task("t6", CardTasks.CHARGE, Map.of("paymentId", "p6", "amountMinor", 1, "cardRef", "1"));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("14", completed.get("t5").at("/declineCode/value").asText());
        assertEquals(2, failed.get("t6").path("retries").asInt());     // 3 left before, one used
        assertTrue(charged.isEmpty());
    }

    private CardTasks withFraud(Tazama.Verdict v, boolean failOpen) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return new CardTasks(new Hyperswitch(base, "admin", "acq"), new CardsOnFile("*:4375510000000007:1230"),
                (id, payer, m, amt, ccy) -> new Tazama.Evaluation(v, "NALT (difme-901-902@1.0.0=0) payer " + payer), failOpen);
    }

    @Test
    void fraudCheckDecidesCaptureReviewOrCancel() throws Exception {
        task("a", CardTasks.CHARGE, Map.of("paymentId", "pa", "amountMinor", 100, "cardRef", "7", "description", "buy"));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.NO_ALERT, false), 100);
        assertEquals("requires_capture", state.get("pa"));            // authorised, no money taken yet
        task("f1", CardTasks.FRAUD, Map.of("paymentId", "pa", "merchant", "acme", "amountMinor", 100, "payer", "partner-7"));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.NO_ALERT, false), 100);
        assertEquals("capture", completed.get("f1").at("/fraudAction/value").asText());
        assertTrue(completed.get("f1").at("/fraudDetail/value").asText().endsWith("payer partner-7"));
        task("c1", CardTasks.CAPTURE, Map.of("paymentId", "pa"));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("succeeded", completed.get("c1").at("/chargeStatus/value").asText());

        task("f2", CardTasks.FRAUD, Map.of("paymentId", "pb", "merchant", "acme", "amountMinor", 100));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.ALERT, true), 100);
        assertEquals("review", completed.get("f2").at("/fraudAction/value").asText());
        assertEquals("review", completed.get("f2").at("/chargeStatus/value").asText());
        task("f3", CardTasks.FRAUD, Map.of("paymentId", "pc", "merchant", "acme", "amountMinor", 100));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.UNKNOWN, false), 100);
        assertEquals("review", completed.get("f3").at("/fraudAction/value").asText());   // fail closed
        task("f4", CardTasks.FRAUD, Map.of("paymentId", "pd", "merchant", "acme", "amountMinor", 100));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.UNKNOWN, true), 100);
        assertEquals("capture", completed.get("f4").at("/fraudAction/value").asText());  // fail open
        task("f5", CardTasks.FRAUD, Map.of("paymentId", "pe", "merchant", "acme", "amountMinor", 100));
        Worker.runOnce(fx, withFraud(Tazama.Verdict.INTERDICT, false), 100);
        assertEquals("cancel", completed.get("f5").at("/fraudAction/value").asText());

        state.put("pe", "requires_capture");
        task("x1", CardTasks.CANCEL, Map.of("paymentId", "pe", "fraudDetail", "ALRT (difme-fraud-model@1.0.0=1)"));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("declined", completed.get("x1").at("/chargeStatus/value").asText());
        assertEquals("59", completed.get("x1").at("/declineCode/value").asText());
        assertEquals(List.of("capture pa", "cancel pe"), psp);
    }

    @Test
    void withoutTazamaEveryAuthorisedPaymentIsCaptured() throws Exception {
        task("f", CardTasks.FRAUD, Map.of("paymentId", "pz", "merchant", "acme", "amountMinor", 100));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("OFF", completed.get("f").at("/fraudVerdict/value").asText());
        assertEquals("capture", completed.get("f").at("/fraudAction/value").asText());
    }

    @Test
    void cardsOnFileRefuseAPanThatFailsLuhn() {
        assertThrows(IllegalArgumentException.class, () -> new CardsOnFile("1:4375510000000001:1230"));
    }
}
