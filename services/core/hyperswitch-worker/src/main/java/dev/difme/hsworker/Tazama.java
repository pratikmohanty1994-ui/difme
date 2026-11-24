package dev.difme.hsworker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Fraud and risk check on Tazama (ADR-023), the replacement for Hyperswitch's FRM: after the card network authorised a
 * payment and before it is captured, the hub reports it to Tazama's TMS as an ISO 20022 credit transfer (pacs.008) and
 * its status (pacs.002, accepted), then reads the evaluation from Tazama's admin service. The verdict decides the
 * hub's action, like Hyperswitch's FRM actions: capture (NO_ALERT), hold for review (ALERT), cancel (INTERDICT). No
 * verdict in time is UNKNOWN; what that means is the hub's fail-open/closed setting. Card numbers are never sent: the
 * payer is DIFME's account id for the cardholder.
 */
final class Tazama {
    /** NO_ALERT: capture. ALERT: hold for review. INTERDICT: a typology reached its interdiction threshold. UNKNOWN: no verdict. */
    public enum Verdict { NO_ALERT, ALERT, INTERDICT, UNKNOWN }

    /** The verdict and what produced it (typology scores, or why there is none), for the payment's record. */
    public record Evaluation(Verdict verdict, String detail) {}

    private static final ObjectMapper JSON = new ObjectMapper();
    private final URI tms;
    private final URI admin;
    private final Duration budget;
    private final Duration poll;
    private final HttpClient http;

    public Tazama(String tmsUrl, String adminUrl, Duration budget) {
        this(tmsUrl, adminUrl, budget, Duration.ofMillis(100));
    }

    Tazama(String tmsUrl, String adminUrl, Duration budget, Duration poll) {
        this.tms = URI.create(tmsUrl.endsWith("/") ? tmsUrl : tmsUrl + "/");
        this.admin = URI.create(adminUrl.endsWith("/") ? adminUrl : adminUrl + "/");
        this.budget = budget;
        this.poll = poll;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    /** Configured from TAZAMA_TMS_URL and TAZAMA_ADMIN_URL (budget TAZAMA_BUDGET_MS, default 3000); null when not set. */
    public static Tazama fromEnv() {
        String tms = System.getenv("TAZAMA_TMS_URL"), admin = System.getenv("TAZAMA_ADMIN_URL");
        if (tms == null || tms.isBlank() || admin == null || admin.isBlank()) return null;
        String ms = System.getenv("TAZAMA_BUDGET_MS");
        return new Tazama(tms, admin, Duration.ofMillis(ms == null ? 3000 : Long.parseLong(ms)));
    }

    /** Reports an authorised card payment and waits (within the budget) for Tazama's verdict. Never throws. */
    public Evaluation evaluate(String paymentId, String payer, String merchant, long amountMinor, String currency) {
        Instant deadline = Instant.now().plus(budget);
        String statusMsgId = id();
        try {
            post("v1/evaluate/iso20022/pacs.008.001.10", pacs008(paymentId, payer, merchant, amountMinor, currency));
            post("v1/evaluate/iso20022/pacs.002.001.12", pacs002(paymentId, statusMsgId));
        } catch (IOException | RuntimeException e) {
            return new Evaluation(Verdict.UNKNOWN, "TMS: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Evaluation(Verdict.UNKNOWN, "interrupted");
        }
        while (Instant.now().isBefore(deadline)) {
            try {
                HttpResponse<String> r = http.send(HttpRequest.newBuilder(admin.resolve("v1/admin/reports/getreportbymsgid?msgid=" + statusMsgId))
                        .timeout(Duration.ofSeconds(2)).GET().build(), HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() == 200) return verdict(JSON.readTree(r.body()).path("data"));
                if (r.statusCode() != 204) return new Evaluation(Verdict.UNKNOWN, "admin service: HTTP " + r.statusCode());
                Thread.sleep(poll.toMillis());
            } catch (IOException e) {
                return new Evaluation(Verdict.UNKNOWN, "admin service: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new Evaluation(Verdict.UNKNOWN, "interrupted");
            }
        }
        return new Evaluation(Verdict.UNKNOWN, "no evaluation within " + budget.toMillis() + " ms");
    }

    /** INTERDICT when any typology reached its interdiction threshold; ALERT on Tazama's ALRT; otherwise NO_ALERT. */
    static Evaluation verdict(JsonNode evaluation) {
        JsonNode report = evaluation.has("report") ? evaluation.path("report") : evaluation.path("evaluation").path("report");
        StringBuilder scores = new StringBuilder();
        boolean interdict = false;
        for (JsonNode t : report.path("tadpResult").path("typologyResult")) {
            double result = t.path("result").asDouble();
            JsonNode threshold = t.path("workflow").path("interdictionThreshold");
            scores.append(scores.isEmpty() ? "" : ", ").append(t.path("cfg").asText()).append('=').append(t.path("result").asText());
            if (threshold.isNumber() && result >= threshold.asDouble()) interdict = true;
        }
        String status = report.path("status").asText();
        String detail = status + (scores.isEmpty() ? "" : " (" + scores + ")");
        if (interdict) return new Evaluation(Verdict.INTERDICT, detail);
        if ("ALRT".equals(status)) return new Evaluation(Verdict.ALERT, detail);
        if ("NALT".equals(status)) return new Evaluation(Verdict.NO_ALERT, detail);
        return new Evaluation(Verdict.UNKNOWN, "unrecognised report status: " + detail);
    }

    private void post(String path, ObjectNode body) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(tms.resolve(path)).timeout(Duration.ofSeconds(2))
                .header("content-type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new IOException(path + " answered HTTP " + r.statusCode() + ": " + r.body());
    }

    static ObjectNode pacs008(String paymentId, String payer, String merchant, long amountMinor, String currency) {
        ObjectNode m = template("pacs008.json");
        ObjectNode grp = (ObjectNode) m.path("FIToFICstmrCdtTrf").path("GrpHdr");
        grp.put("MsgId", id()).put("CreDtTm", Instant.now().toString());
        ObjectNode tx = (ObjectNode) m.path("FIToFICstmrCdtTrf").path("CdtTrfTxInf");
        ((ObjectNode) tx.path("PmtId")).put("InstrId", paymentId).put("EndToEndId", paymentId);
        BigDecimal amount = BigDecimal.valueOf(amountMinor, 2);
        for (String f : new String[] {"IntrBkSttlmAmt", "InstdAmt"}) ((ObjectNode) tx.path(f).path("Amt")).put("Amt", amount).put("Ccy", currency);
        party(tx, "Dbtr", "DbtrAcct", payer);
        party(tx, "Cdtr", "CdtrAcct", merchant);
        ((ObjectNode) tx.path("InitgPty").path("Id").path("PrvtId").path("Othr").get(0)).put("Id", payer);
        return m;
    }

    static ObjectNode pacs002(String paymentId, String statusMsgId) {
        ObjectNode m = template("pacs002.json");
        ((ObjectNode) m.path("FIToFIPmtSts").path("GrpHdr")).put("MsgId", statusMsgId).put("CreDtTm", Instant.now().toString());
        ((ObjectNode) m.path("FIToFIPmtSts").path("TxInfAndSts")).put("OrgnlInstrId", paymentId).put("OrgnlEndToEndId", paymentId)
                .put("TxSts", "ACCC").put("AccptncDtTm", Instant.now().toString());
        return m;
    }

    private static void party(ObjectNode tx, String party, String account, String id) {
        ((ObjectNode) tx.path(party).path("Id").path("PrvtId").path("Othr").get(0)).put("Id", id);
        ((ObjectNode) tx.path(account).path("Id").path("Othr").get(0)).put("Id", id);
        ((ObjectNode) tx.path(party)).put("Nm", id);
        ((ObjectNode) tx.path(account)).put("Nm", id);
    }

    private static ObjectNode template(String name) {
        try (InputStream in = Tazama.class.getResourceAsStream("/tazama/" + name)) {
            return (ObjectNode) JSON.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String id() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
