package dev.difme.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import dev.difme.hub.frm.Tazama;
import dev.difme.hub.frm.Tazama.Verdict;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The hub's Tazama client against a fake TMS and admin service (real HTTP, real JSON). */
class TazamaTest {
    static final ObjectMapper JSON = new ObjectMapper();
    HttpServer server;
    final List<JsonNode> posted = new CopyOnWriteArrayList<>();
    volatile int tmsStatus = 200;
    volatile int pendingPolls = 0;       // 204 answers before the report is there
    volatile String report;              // the evaluation the admin service returns
    final AtomicInteger polls = new AtomicInteger();
    String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/evaluate/iso20022/", x -> {
            posted.add(JSON.readTree(x.getRequestBody()));
            byte[] b = "{\"message\":\"Transaction is valid\"}".getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(tmsStatus, b.length);
            x.getResponseBody().write(b);
            x.close();
        });
        server.createContext("/v1/admin/reports/getreportbymsgid", x -> {
            if (polls.incrementAndGet() <= pendingPolls || report == null) {
                x.sendResponseHeaders(204, -1);
            } else {
                byte[] b = ("{\"message\":\"Report was found\",\"data\":" + report + "}").getBytes(StandardCharsets.UTF_8);
                x.sendResponseHeaders(200, b.length);
                x.getResponseBody().write(b);
            }
            x.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    static String evaluation(String status, double score, Double interdiction) {
        String wf = interdiction == null ? "{\"alertThreshold\":200}" : "{\"alertThreshold\":200,\"interdictionThreshold\":" + interdiction + "}";
        return "{\"report\":{\"status\":\"" + status + "\",\"tadpResult\":{\"typologyResult\":[{\"cfg\":\"difme-fraud-model@1.0.0\",\"result\":"
                + score + ",\"workflow\":" + wf + "}]}}}";
    }

    Tazama tazama(long budgetMs) {
        return new Tazama(base, base, Duration.ofMillis(budgetMs));
    }

    @Test
    void noAlertAfterAFewPolls() {
        pendingPolls = 2;
        report = evaluation("NALT", 0, 400.0);
        Tazama.Evaluation e = tazama(3000).evaluate("pay-1", "partner-1", "merchant-1", 852000, "INR");
        assertEquals(Verdict.NO_ALERT, e.verdict());
        assertTrue(polls.get() >= 3);
    }

    @Test
    void alertBelowTheInterdictionThresholdIsAnAlert() {
        report = evaluation("ALRT", 200, 400.0);
        Tazama.Evaluation e = tazama(3000).evaluate("pay-2", "partner-1", "merchant-1", 1000, "INR");
        assertEquals(Verdict.ALERT, e.verdict());
        assertTrue(e.detail().contains("difme-fraud-model@1.0.0=200"), e.detail());
    }

    @Test
    void reachingTheInterdictionThresholdInterdicts() {
        report = evaluation("ALRT", 400, 400.0);
        assertEquals(Verdict.INTERDICT, tazama(3000).evaluate("pay-3", "p", "m", 1000, "INR").verdict());
    }

    @Test
    void noVerdictWithinTheBudgetIsUnknown() {
        report = null;
        long t0 = System.nanoTime();
        Tazama.Evaluation e = tazama(400).evaluate("pay-4", "p", "m", 1000, "INR");
        assertEquals(Verdict.UNKNOWN, e.verdict());
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 2000, "returns at the budget, not later");
    }

    @Test
    void aRefusedMessageIsUnknown() {
        tmsStatus = 400;
        Tazama.Evaluation e = tazama(1000).evaluate("pay-5", "p", "m", 1000, "INR");
        assertEquals(Verdict.UNKNOWN, e.verdict());
        assertTrue(e.detail().startsWith("TMS:"), e.detail());
    }

    @Test
    void tazamaDownIsUnknown() {
        server.stop(0);
        assertEquals(Verdict.UNKNOWN, tazama(500).evaluate("pay-6", "p", "m", 1000, "INR").verdict());
    }

    @Test
    void messagesCarryThePaymentPartiesAndAmountButNoCardData() {
        report = evaluation("NALT", 0, 400.0);
        tazama(3000).evaluate("pay-7", "partner-42", "merchant-9", 852050, "INR");
        assertEquals(2, posted.size());
        JsonNode tx = posted.get(0).path("FIToFICstmrCdtTrf").path("CdtTrfTxInf");
        assertEquals("pay-7", tx.path("PmtId").path("EndToEndId").asText());
        assertEquals(8520.50, tx.path("IntrBkSttlmAmt").path("Amt").path("Amt").asDouble());
        assertEquals("INR", tx.path("IntrBkSttlmAmt").path("Amt").path("Ccy").asText());
        assertEquals("partner-42", tx.path("DbtrAcct").path("Id").path("Othr").get(0).path("Id").asText());
        assertEquals("merchant-9", tx.path("CdtrAcct").path("Id").path("Othr").get(0).path("Id").asText());
        JsonNode status = posted.get(1).path("FIToFIPmtSts").path("TxInfAndSts");
        assertEquals("pay-7", status.path("OrgnlEndToEndId").asText());
        assertEquals("ACCC", status.path("TxSts").asText());
        String all = posted.toString();
        assertFalse(all.matches(".*\\b4\\d{15}\\b.*"), "no card number in what goes to Tazama");
    }
}
