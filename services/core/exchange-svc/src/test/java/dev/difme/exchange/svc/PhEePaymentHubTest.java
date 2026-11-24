package dev.difme.exchange.svc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import dev.difme.exchange.rails.PaymentHub;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** PH-EE channel + Fluxnova history faked in one HTTP server: the channel starts an instance, history reports it. */
class PhEePaymentHubTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private HttpServer server;
    private final List<String> started = new CopyOnWriteArrayList<>();
    /** correlation id -> end event the instance finishes at ("" = still running) */
    private final Map<String, String> instances = new ConcurrentHashMap<>();
    private volatile String endEventForNext = "done";
    private PhEePaymentHub hub;
    private final List<String> cardCalls = new CopyOnWriteArrayList<>();
    /** card flows: business key -> final variables (as the hyperswitch-worker leaves them) */
    private final Map<String, Map<String, String>> flows = new ConcurrentHashMap<>();
    private final List<String> flowStarts = new CopyOnWriteArrayList<>();
    private final List<String> payers = new CopyOnWriteArrayList<>();
    private volatile String chargeResult = "succeeded", refundResult = "succeeded";
    private PhEePaymentHub flowHub;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/channel/transfer", x -> {
            var body = JSON.readTree(x.getRequestBody());
            String id = x.getRequestHeaders().getFirst("X-CorrelationID");
            started.add(id + " " + body.at("/payer/partyIdInfo/partyIdentifier").asText() + ">" + body.at("/payee/partyIdInfo/partyIdentifier").asText()
                    + " " + body.at("/amount/amount").asText() + " " + body.at("/payee/partyIdInfo/fspId").asText()
                    + " " + x.getRequestHeaders().getFirst("Platform-TenantId") + " " + x.getRequestHeaders().getFirst("Authorization"));
            instances.put(id, endEventForNext);
            byte[] r = "{\"transactionId\":\"t1\"}".getBytes();
            x.sendResponseHeaders(202, r.length);
            x.getResponseBody().write(r);
            x.close();
        });
        server.createContext("/engine-rest/process-definition/key/", x -> {
            String def = x.getRequestURI().getPath().replaceAll(".*/key/([^/]*)/start", "$1");
            var body = JSON.readTree(x.getRequestBody());
            String bk = body.path("businessKey").asText();
            var vars = body.path("variables");
            flowStarts.add(def + " " + bk + " " + vars.path("cardRef").path("value").asText("") + " "
                    + vars.path("amountMinor").path("value").asText() + "/" + vars.path("amountMinor").path("type").asText());
            assertTrue(!body.toString().contains("4375510000000001"), "the card number never goes into a flow");
            payers.add(vars.path("payer").path("value").asText(""));
            flows.put(bk, def.startsWith("DifmeCardCheckout")
                    ? switch (chargeResult) {
                        case "succeeded" -> Map.of("chargeStatus", "succeeded", "pspPaymentId", "pay_1");
                        case "review" -> Map.of("chargeStatus", "review", "declineMessage", "fraud alert: ALRT");
                        default -> Map.of("chargeStatus", "declined", "declineCode", "51", "declineMessage", "insufficient funds");
                    }
                    : Map.of("refundStatus", refundResult, "refundMessage", refundResult));
            reply(x, "{\"id\":\"ci-" + bk + "\"}");
        });
        server.createContext("/engine-rest/history/variable-instance", x -> {
            String bk = x.getRequestURI().getQuery().replaceAll(".*processInstanceId=ci-([^&]*).*", "$1");
            var arr = JSON.createArrayNode();
            flows.getOrDefault(bk, Map.of()).forEach((k, v) -> arr.addObject().put("name", k).put("value", v));
            reply(x, arr.toString());
        });
        server.createContext("/engine-rest/history/process-instance", x -> {
            String path = x.getRequestURI().getPath();
            if (path.contains("/process-instance/ci-")) { reply(x, "{\"state\":\"COMPLETED\"}"); return; }
            String q = URLDecoder.decode(x.getRequestURI().getRawQuery(), StandardCharsets.UTF_8);
            if (q.contains("processInstanceBusinessKey=")) {
                String bk = q.replaceAll(".*processInstanceBusinessKey=([^&]*).*", "$1");
                reply(x, flows.containsKey(bk) ? "[{\"id\":\"ci-" + bk + "\"}]" : "[]");
                return;
            }
            String id = q.replaceAll(".*clientCorrelationId_eq_([^&]*).*", "$1");
            String end = instances.get(id);
            String json = end == null ? "[]" : "[{\"id\":\"pi-" + id + "\",\"state\":\"" + (end.isEmpty() ? "ACTIVE" : "COMPLETED") + "\"}]";
            reply(x, json);
        });
        server.createContext("/engine-rest/history/activity-instance", x -> {
            String id = x.getRequestURI().getQuery().replaceAll(".*processInstanceId=pi-([^&]*).*", "$1");
            reply(x, "[{\"activityId\":\"" + instances.get(id) + "\"}]");
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        PaymentHub cards = new PaymentHub() {
            public Outcome deposit(String i, String a, long m) { throw new AssertionError("deposits go to PH-EE"); }
            public Outcome transfer(String i, String f, String t, long m, String n) { throw new AssertionError("transfers go to PH-EE"); }
            public Outcome payCard(String i, String m, long a, CardOnFile c) { cardCalls.add("pay " + i); return new Outcome("SETTLED", "ok"); }
            public Outcome refundCard(String i, String p, String m, long a, String r) { cardCalls.add("refund " + i); return new Outcome("REFUNDED", "ok"); }
        };
        hub = new PhEePaymentHub(cards, base, () -> "Bearer tok", base + "/engine-rest", () -> "Basic x", "card-settlement", Duration.ofSeconds(2));
        flowHub = new PhEePaymentHub(cards, base, () -> "Bearer tok", base + "/engine-rest", () -> "Basic x", "card-settlement",
                Duration.ofSeconds(2), true);
    }

    private static void reply(com.sun.net.httpserver.HttpExchange x, String json) throws java.io.IOException {
        byte[] r = json.getBytes();
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(200, r.length);
        x.getResponseBody().write(r);
        x.close();
    }

    @AfterEach
    void stop() { server.stop(0); }

    @Test
    void transferIsAnOnUsTransferAndIsStartedOnce() {
        assertEquals("DONE", hub.transfer("rel-h1-r1", "escrow", "partner-7", 123_45, "release").status());
        assertEquals(List.of("rel-h1-r1 escrow>partner-7 123.45 default default Bearer tok"), started);
        // a retry after a lost answer finds the finished transfer instead of starting a second one
        assertEquals("DONE", hub.transfer("rel-h1-r1", "escrow", "partner-7", 123_45, "release").status());
        assertEquals(1, started.size());
    }

    @Test
    void depositsComeFromTheSettlementAccount() {
        assertEquals("DONE", hub.deposit("hold-h2", "escrow", 50_00).status());
        assertTrue(started.get(0).startsWith("hold-h2 card-settlement>escrow 50.00"));
    }

    @Test
    void refusedAndBlockedTransfersAreReported() {
        endEventForNext = "failed";
        assertEquals("REJECTED", hub.transfer("ref-1", "escrow", "payer-1", 1_00, "refund").status());
        endEventForNext = "operator";
        assertEquals("FAILED", hub.transfer("ref-2", "escrow", "payer-1", 1_00, "refund").status());
    }

    @Test
    void anUnfinishedTransferIsRetriedLater() {
        endEventForNext = "";
        assertThrows(IllegalStateException.class, () -> hub.transfer("rel-slow", "escrow", "p", 1_00, "x"));
        instances.put("rel-slow", "done");   // finishes meanwhile: the retry reports it without a second start
        assertEquals("DONE", hub.transfer("rel-slow", "escrow", "p", 1_00, "x").status());
        assertEquals(1, started.size());
    }

    @Test
    void cardPaymentsStayOnTheHub() {
        assertEquals("SETTLED", hub.payCard("p1", "m", 100, new PaymentHub.CardOnFile("4375510000000001", "12", "2030", "123")).status());
        assertEquals("REFUNDED", hub.refundCard("r1", "p1", "m", 100, "x").status());
        assertEquals(List.of("pay p1", "refund r1"), cardCalls);
        assertTrue(started.isEmpty());
    }

    private static final PaymentHub.CardOnFile CARD = new PaymentHub.CardOnFile("4375510000000001", "12", "2030", "123", "*");

    @Test
    void cardCheckoutRunsTheFlowThenCreditsTheMerchant() {
        assertEquals("SETTLED", flowHub.payCard("p1", "acme", 250_00, CARD).status());
        assertEquals(List.of("DifmeCardCheckout-default p1 * 25000/Long"), flowStarts);
        assertEquals(List.of("p1:settle card-settlement>merchant-acme 250.00 default default Bearer tok"), started);
        // a retry finds the earlier checkout (no second charge) and the finished credit
        assertEquals("SETTLED", flowHub.payCard("p1", "acme", 250_00, CARD).status());
        assertEquals(1, flowStarts.size());
        assertEquals(1, started.size());
        assertTrue(cardCalls.isEmpty());
    }

    @Test
    void aDeclineMovesNoMoney() {
        chargeResult = "declined";
        var o = flowHub.payCard("p2", "acme", 1_00, CARD);
        assertEquals("DECLINED", o.status());
        assertEquals("51: insufficient funds", o.detail());
        assertTrue(started.isEmpty());
    }

    @Test
    void aFraudAlertHoldsThePaymentWithoutMovingMoney() {
        chargeResult = "review";
        assertEquals("REVIEW", flowHub.payCard("p4", "acme", 1_00, new PaymentHub.CardOnFile("4375510000000001", "12", "2030", "123", "7")).status());
        assertEquals(List.of("partner-7"), payers);
        assertTrue(started.isEmpty());
    }

    @Test
    void aRefusedMerchantCreditRefundsTheCard() {
        endEventForNext = "failed";
        assertEquals("REFUNDED", flowHub.payCard("p3", "acme", 1_00, CARD).status());
        assertEquals("DifmeCardRefund-default p3-unwind  100/Long", flowStarts.get(1));
    }

    @Test
    void refundDebitsTheMerchantThenRefundsTheCard() {
        assertEquals("REFUNDED", flowHub.refundCard("r1", "p1", "acme", 1_00, "returned").status());
        assertTrue(started.get(0).startsWith("r1:debit merchant-acme>card-settlement 1.00"));
        assertEquals("DifmeCardRefund-default r1  100/Long", flowStarts.get(0));
        // the PSP refuses: the merchant debit is undone
        refundResult = "failed";
        assertEquals("FAILED", flowHub.refundCard("r2", "p1", "acme", 1_00, "returned").status());
        assertTrue(started.get(2).startsWith("r2:undo card-settlement>merchant-acme 1.00"));
        // the merchant can't cover it: nothing reaches the PSP
        endEventForNext = "failed";
        assertEquals("REJECTED", flowHub.refundCard("r3", "p1", "acme", 1_00, "returned").status());
        assertEquals(2, flowStarts.size());
    }
}
