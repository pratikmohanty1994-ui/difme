package dev.difme.core.saga;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.difme.core.common.process.LoanActivities;
import dev.difme.core.common.process.LoanApplication;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.UUID;

/**
 * Loan origination side effects: Tazama screening (the application as a pain.001, typology difme-3ds-risk: the fraud
 * model, without touching payment velocity) and booking in Fineract (loan with externalId = business key so a retry
 * finds the existing loan, approval, disbursement). Fineract login: Keycloak client credentials (client
 * loan-origination, Fineract user of the same name).
 */
public class LoanActivitiesImpl implements LoanActivities {
    static final ObjectMapper JSON = new ObjectMapper();
    static final DateTimeFormatter D = DateTimeFormatter.ofPattern("dd MMMM yyyy", Locale.ENGLISH);
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final String fineract, tokenUrl, clientId, clientSecret, basicAuth, tms, admin;
    private final long loanProductId;

    public LoanActivitiesImpl(String fineract, String tokenUrl, String clientId, String clientSecret, String basicAuth, long loanProductId,
            String tazamaTms, String tazamaAdmin) {
        this.fineract = fineract;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.basicAuth = basicAuth;
        this.loanProductId = loanProductId;
        this.tms = tazamaTms;
        this.admin = tazamaAdmin;
    }

    @Override
    public String screen(LoanApplication a) {
        if (tms == null || tms.isBlank()) return "UNKNOWN"; // no FRM configured: the decision table refers it to a person
        try {
            ObjectNode p = (ObjectNode) JSON.readTree(LoanActivitiesImpl.class.getResourceAsStream("/tazama/pain001.json"));
            p.remove("TenantId");
            ObjectNode ci = (ObjectNode) p.path("CstmrCdtTrfInitn");
            String msgId = UUID.randomUUID().toString().replace("-", "");
            ((ObjectNode) ci.path("GrpHdr")).put("MsgId", msgId).put("CreDtTm", Instant.now().toString());
            ObjectNode tx = (ObjectNode) ci.path("PmtInf").path("CdtTrfTxInf");
            ((ObjectNode) tx.path("PmtId")).put("EndToEndId", "loan-" + a.businessKey());
            for (String f : new String[] {"InstdAmt", "EqvtAmt"})
                ((ObjectNode) tx.path("Amt").path(f).path("Amt")).put("Amt", a.amountMinor() / 100.0).put("Ccy", "INR");
            ((ObjectNode) ci.path("PmtInf").path("DbtrAcct").path("Id").path("Othr").get(0)).put("Id", "client-" + a.fineractClientId());
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(tms + "/v1/evaluate/iso20022/pain.001.001.11"))
                    .header("content-type", "application/json").POST(HttpRequest.BodyPublishers.ofString(p.toString())).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return "UNKNOWN";
            for (int i = 0; i < 30; i++) {
                HttpResponse<String> e = http.send(HttpRequest.newBuilder(URI.create(admin + "/v1/admin/reports/getreportbymsgid?msgid=" + msgId)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (e.statusCode() == 200) return verdict(JSON.readTree(e.body()).path("data"));
                Thread.sleep(200);
            }
            return "UNKNOWN";
        } catch (IOException e) {
            return "UNKNOWN";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "UNKNOWN";
        }
    }

    static String verdict(JsonNode ev) {
        JsonNode report = ev.has("report") ? ev.path("report") : ev.path("evaluation").path("report");
        for (JsonNode t : report.path("tadpResult").path("typologyResult")) {
            JsonNode th = t.path("workflow").path("interdictionThreshold");
            if (th.isNumber() && t.path("result").asDouble() >= th.asDouble()) return "INTERDICT";
        }
        return switch (report.path("status").asText()) {
            case "ALRT" -> "ALERT";
            case "NALT" -> "NO_ALERT";
            default -> "UNKNOWN";
        };
    }

    @Override
    public long book(LoanApplication a) {
        try {
            String ext = "loan-" + a.businessKey();
            JsonNode existing = call("GET", "loans?externalId=" + URLEncoder.encode(ext, StandardCharsets.UTF_8), null);
            long loanId;
            JsonNode items = existing.path("pageItems");
            if (items.isArray() && !items.isEmpty()) {
                loanId = items.get(0).path("id").asLong();
            } else {
                String today = LocalDate.now().format(D);
                ObjectNode b = JSON.createObjectNode().put("clientId", a.fineractClientId()).put("productId", loanProductId)
                        .put("principal", a.amountMinor() / 100.0).put("loanTermFrequency", a.termMonths()).put("loanTermFrequencyType", 2)
                        .put("numberOfRepayments", a.termMonths()).put("repaymentEvery", 1).put("repaymentFrequencyType", 2)
                        .put("interestRatePerPeriod", 1.5).put("amortizationType", 1).put("interestType", 0).put("interestCalculationPeriodType", 1)
                        .put("transactionProcessingStrategyCode", "mifos-standard-strategy").put("loanType", "individual")
                        .put("expectedDisbursementDate", today).put("submittedOnDate", today).put("externalId", ext)
                        .put("locale", "en").put("dateFormat", "dd MMMM yyyy");
                loanId = call("POST", "loans", b).path("loanId").asLong();
            }
            JsonNode loan = call("GET", "loans/" + loanId, null);
            String today = LocalDate.now().format(D);
            if (loan.path("status").path("pendingApproval").asBoolean())
                call("POST", "loans/" + loanId + "?command=approve", JSON.createObjectNode().put("approvedOnDate", today).put("locale", "en").put("dateFormat", "dd MMMM yyyy"));
            loan = call("GET", "loans/" + loanId, null);
            if (loan.path("status").path("waitingForDisbursal").asBoolean())
                call("POST", "loans/" + loanId + "?command=disburse", JSON.createObjectNode().put("actualDisbursementDate", today)
                        .put("transactionAmount", a.amountMinor() / 100.0).put("locale", "en").put("dateFormat", "dd MMMM yyyy"));
            return loanId;
        } catch (IOException e) {
            throw new IllegalStateException("Fineract: " + e.getMessage(), e); // Temporal retries
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private String auth() throws IOException, InterruptedException {
        if (tokenUrl == null || tokenUrl.isBlank()) return "Basic " + basicAuth;
        String form = "grant_type=client_credentials&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) + "&client_secret="
                + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(tokenUrl)).header("content-type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
        String t = JSON.readTree(r.body()).path("access_token").asText();
        if (t.isEmpty()) throw new IOException("Keycloak token: HTTP " + r.statusCode());
        return "Bearer " + t;
    }

    private JsonNode call(String method, String path, JsonNode body) throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(fineract + "/api/v1/" + path)).header("Fineract-Platform-TenantId", "default")
                .header("content-type", "application/json").header("Authorization", auth());
        b = body == null ? b.GET() : b.method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new IOException(method + " " + path + ": HTTP " + r.statusCode() + " " + r.body());
        return JSON.readTree(r.body());
    }
}
