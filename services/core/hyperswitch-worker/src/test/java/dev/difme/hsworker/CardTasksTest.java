package dev.difme.hsworker;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        server.createContext("/accounts/", x -> reply(x, 200, "{}"));
        server.createContext("/api_keys/", x -> reply(x, 200, "{\"api_key\":\"k\"}"));
        server.createContext("/account/", x -> reply(x, 200, "[{\"connector_name\":\"stripe_test\"}]"));
        server.createContext("/payments", x -> {
            if (pspDown) { reply(x, 503, "{\"error\":{\"message\":\"down\"}}"); return; }
            JsonNode b = JSON.readTree(x.getRequestBody());
            String pan = b.at("/payment_method_data/card/card_number").asText();
            charged.add(b.path("payment_id").asText() + " " + pan + " " + b.path("amount").asLong());
            boolean ok = !pan.endsWith("0019");
            reply(x, 200, "{\"payment_id\":\"" + b.path("payment_id").asText() + "\",\"status\":\"" + (ok ? "succeeded" : "failed")
                    + "\",\"amount\":" + b.path("amount").asLong() + (ok ? "" : ",\"error_message\":\"51: Insufficient funds\"") + "}");
        });
        server.createContext("/refunds", x -> {
            JsonNode b = JSON.readTree(x.getRequestBody());
            reply(x, 200, "{\"refund_id\":\"" + b.path("refund_id").asText() + "\",\"status\":\"succeeded\",\"amount\":" + b.path("amount").asLong() + "}");
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        fx = new Fluxnova(base + "/engine-rest", "admin:x", "w1");
        tasks = new CardTasks(new Hyperswitch(base, "admin", "acq"), new CardsOnFile("1:4375510000000001:1230,2:4375510000000019:1230,*:4375510000000001:1230"));
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
        assertEquals("succeeded", completed.get("t1").at("/chargeStatus/value").asText());
        assertEquals("auc1-p1-000001", completed.get("t1").at("/pspPaymentId/value").asText());
        assertEquals("declined", completed.get("t2").at("/chargeStatus/value").asText());
        assertEquals("51", completed.get("t2").at("/declineCode/value").asText());
        assertEquals("succeeded", completed.get("t3").at("/chargeStatus/value").asText());   // "*" card for a standing mandate
        assertEquals("succeeded", completed.get("t4").at("/refundStatus/value").asText());
        assertEquals(List.of("auc1-p1-000001 4375510000000001 1600000", "auc2-p2-000002 4375510000000019 500",
                "auc3-p1000002-000003 4375510000000001 700"), charged);
        assertTrue(completed.values().stream().noneMatch(v -> v.toString().contains("4375510000")), "no card number in process variables");
    }

    @Test
    void noCardIsADeclineAndAnUnreachablePspIsRetried() throws Exception {
        tasks = new CardTasks(new Hyperswitch("http://127.0.0.1:" + server.getAddress().getPort(), "a", "b"), new CardsOnFile("1:4375510000000001:1230"));
        task("t5", CardTasks.CHARGE, Map.of("paymentId", "p5", "amountMinor", 1, "cardRef", "9"));
        pspDown = true;
        task("t6", CardTasks.CHARGE, Map.of("paymentId", "p6", "amountMinor", 1, "cardRef", "1"));
        Worker.runOnce(fx, tasks, 100);
        assertEquals("14", completed.get("t5").at("/declineCode/value").asText());
        assertEquals(2, failed.get("t6").path("retries").asInt());     // 3 left before, one used
        assertTrue(charged.isEmpty());
    }
}
