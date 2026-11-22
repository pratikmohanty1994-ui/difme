package dev.difme.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.difme.hub.flow.FlowImpls;
import dev.difme.hub.flow.Flows;
import dev.difme.hub.flow.Flows.Result;
import dev.difme.hub.frm.Tazama;
import dev.difme.hub.psp.Hyperswitch;
import io.temporal.testing.TestWorkflowEnvironment;
import io.temporal.worker.Worker;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The hub's fraud check before capture (ADR-023), the Tazama replacement for Hyperswitch's FRM: a fake Hyperswitch
 * (merchant bootstrap, payments, capture, cancel) and a fake Tazama (TMS + admin report) on real HTTP, settlement in
 * Temporal's test environment.
 */
class HubFraudCheckTest {
    static final ObjectMapper JSON = new ObjectMapper();
    HttpServer server;
    TestWorkflowEnvironment env;
    final List<String> psp = new CopyOnWriteArrayList<>();          // PSP operations seen
    final List<String> cbs = new CopyOnWriteArrayList<>();          // CBS transfers made by settlement
    final Map<String, ObjectNode> payments = new ConcurrentHashMap<>();
    volatile String report;                                         // Tazama's evaluation (null: none yet)
    String base;

    class Steps implements Flows.Steps {
        public long cbsTransfer(String key, String from, String to, long amount, String note) {
            cbs.add(from + ">" + to + " " + amount);
            return cbs.size();
        }
        public String pspRefund(String refundId, String paymentId, long amount, String reason) { return "succeeded"; }
    }

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        env = TestWorkflowEnvironment.newInstance();
        Worker w = env.newWorker(Flows.TASK_QUEUE);
        w.registerWorkflowImplementationTypes(FlowImpls.CardSettlementImpl.class, FlowImpls.CardRefundImpl.class, FlowImpls.AccountTransferImpl.class);
        w.registerActivitiesImplementations(new Steps());
        env.start();
    }

    @AfterEach
    void tearDown() {
        env.close();
        server.stop(0);
    }

    private void handle(HttpExchange x) throws IOException {
        String path = x.getRequestURI().getPath(), method = x.getRequestMethod();
        JsonNode body = x.getRequestBody().available() >= 0 && "POST".equals(method) ? JSON.readTree(x.getRequestBody()) : null;
        int status = 200;
        Object out = Map.of();
        if (path.startsWith("/v1/evaluate/iso20022/")) {
            out = Map.of("message", "Transaction is valid");
        } else if (path.equals("/v1/admin/reports/getreportbymsgid")) {
            if (report == null) status = 204;
            else out = JSON.readTree("{\"data\":" + report + "}");
        } else if (path.startsWith("/api_keys/")) {
            out = Map.of("api_key", "test-key");
        } else if (path.endsWith("/connectors")) {
            out = "GET".equals(method) ? List.of(Map.of("connector_name", "stripe_test")) : Map.of();
        } else if (path.startsWith("/accounts")) {
            out = Map.of("merchant_id", Hyperswitch.MERCHANT);
        } else if (path.equals("/payments") && "POST".equals(method)) {
            String id = body.path("payment_id").asText();
            boolean manual = "manual".equals(body.path("capture_method").asText());
            psp.add("charge " + id + (manual ? " manual" : " automatic"));
            ObjectNode p = JSON.createObjectNode().put("payment_id", id).put("amount", body.path("amount").asLong())
                    .put("status", manual ? "requires_capture" : "succeeded");
            payments.put(id, p);
            out = p;
        } else if (path.matches("/payments/[^/]+/capture")) {
            String id = path.split("/")[2];
            psp.add("capture " + id);
            out = payments.get(id).put("status", "succeeded");
        } else if (path.matches("/payments/[^/]+/cancel")) {
            String id = path.split("/")[2];
            psp.add("cancel " + id);
            out = payments.get(id).put("status", "cancelled");
        } else if (path.matches("/payments/[^/]+")) {
            out = payments.get(path.split("/")[2]);
        } else {
            status = 404;
        }
        byte[] b = status == 204 ? new byte[0] : JSON.writeValueAsBytes(out);
        x.getResponseHeaders().add("content-type", "application/json");
        x.sendResponseHeaders(status, status == 204 ? -1 : b.length);
        if (status != 204) x.getResponseBody().write(b);
        x.close();
    }

    static String evaluation(String status, double score) {
        return "{\"report\":{\"status\":\"" + status + "\",\"tadpResult\":{\"typologyResult\":[{\"cfg\":\"difme-fraud-model@1.0.0\",\"result\":"
                + score + ",\"workflow\":{\"alertThreshold\":200,\"interdictionThreshold\":400}}]}}}";
    }

    Hub hub(boolean withFraudCheck, boolean failOpen) {
        Hyperswitch hs = new Hyperswitch(base, "admin", "acquirer");
        Tazama t = withFraudCheck ? new Tazama(base, base, Duration.ofMillis(400)) : null;
        return new Hub(env.getWorkflowClient(), null, hs, t, failOpen);
    }

    static final Hyperswitch.Card CARD = new Hyperswitch.Card("4375510000000001", "12", "2030", "123", "Partner One");

    @Test
    void noAlertIsCapturedAndSettled() {
        report = evaluation("NALT", 0);
        Result r = hub(true, false).pay("pay-1", "merchant-1", 852000, "INR", CARD, "partner-1");
        assertEquals("SETTLED", r.status(), r.detail());
        assertEquals(List.of("charge pay-1 manual", "capture pay-1"), psp);
        assertEquals(1, cbs.size());
    }

    @Test
    void anAlertHoldsThePaymentForReviewWithoutTakingMoney() {
        report = evaluation("ALRT", 200);
        Hub hub = hub(true, false);
        Result r = hub.pay("pay-2", "merchant-1", 1000, "INR", CARD, "partner-1");
        assertEquals("REVIEW", r.status());
        assertTrue(r.detail().contains("difme-fraud-model@1.0.0=200"), r.detail());
        assertEquals(List.of("charge pay-2 manual"), psp);
        assertTrue(cbs.isEmpty());

        Result approved = hub.review("pay-2", "merchant-1", true);
        assertEquals("SETTLED", approved.status(), approved.detail());
        assertEquals(List.of("charge pay-2 manual", "capture pay-2"), psp);
        assertEquals(1, cbs.size());
    }

    @Test
    void aRejectedReviewReleasesTheAuthorisation() {
        report = evaluation("ALRT", 200);
        Hub hub = hub(true, false);
        hub.pay("pay-3", "merchant-1", 1000, "INR", CARD, "partner-1");
        Result rejected = hub.review("pay-3", "merchant-1", false);
        assertEquals("DECLINED", rejected.status());
        assertEquals(List.of("charge pay-3 manual", "cancel pay-3"), psp);
        assertTrue(cbs.isEmpty());
    }

    @Test
    void anInterdictionCancelsTheAuthorisation() {
        report = evaluation("ALRT", 400);
        Result r = hub(true, false).pay("pay-4", "merchant-1", 1000, "INR", CARD, "partner-1");
        assertEquals("DECLINED", r.status());
        assertTrue(r.detail().startsWith("FRAUD"), r.detail());
        assertEquals(List.of("charge pay-4 manual", "cancel pay-4"), psp);
        assertTrue(cbs.isEmpty());
    }

    @Test
    void noVerdictHoldsForReviewByDefault() {
        report = null;
        Result r = hub(true, false).pay("pay-5", "merchant-1", 1000, "INR", CARD, "partner-1");
        assertEquals("REVIEW", r.status());
        assertEquals(List.of("charge pay-5 manual"), psp);
    }

    @Test
    void noVerdictIsCapturedWhenFailOpen() {
        report = null;
        Result r = hub(true, true).pay("pay-6", "merchant-1", 1000, "INR", CARD, "partner-1");
        assertEquals("SETTLED", r.status(), r.detail());
        assertEquals(List.of("charge pay-6 manual", "capture pay-6"), psp);
    }

    @Test
    void withoutTazamaTheChargeIsCapturedAtOnceAsBefore() {
        Result r = hub(false, false).pay("pay-7", "merchant-1", 1000, "INR", CARD, null);
        assertEquals("SETTLED", r.status(), r.detail());
        assertEquals(List.of("charge pay-7 automatic"), psp);
    }
}
