package dev.difme.core.saga;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.difme.core.common.process.LoanActivities;
import dev.difme.core.common.process.LoanApplication;
import dev.difme.core.common.process.LoanBookingWorkflow;
import dev.difme.core.common.process.LoanScreeningWorkflow;
import dev.difme.core.common.process.ProcessCallbacks;
import io.temporal.client.WorkflowOptions;
import io.temporal.testing.TestWorkflowEnvironment;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

class LoanWorkflowsTest {
    static final LoanApplication APP = new LoanApplication("pi-7", "bk-7", "cust-1", 7, 20_000_000L, 12, "EQUIPMENT");

    @Test
    void screeningAndBookingCorrelateTheBpmnProcess() {
        List<String> log = new ArrayList<>();
        TestWorkflowEnvironment env = TestWorkflowEnvironment.newInstance();
        env.newWorker(LoanScreeningWorkflow.TASK_QUEUE).registerWorkflowImplementationTypes(LoanWorkflowsImpl.Screening.class, LoanWorkflowsImpl.Booking.class);
        env.newWorker(LoanActivities.TASK_QUEUE).registerActivitiesImplementations(new LoanActivities() {
            public String screen(LoanApplication a) { log.add("screen:" + a.amountMinor()); return "NO_ALERT"; }
            public long book(LoanApplication a) { log.add("book:" + a.fineractClientId()); return 42L; }
        });
        env.newWorker(ProcessCallbacks.TASK_QUEUE).registerActivitiesImplementations((ProcessCallbacks)
                (msg, pid, vars) -> log.add("correlate:" + msg + ":" + pid + ":" + vars));
        env.start();
        var opts = WorkflowOptions.newBuilder().setTaskQueue(LoanScreeningWorkflow.TASK_QUEUE).build();
        assertEquals("NO_ALERT", env.getWorkflowClient().newWorkflowStub(LoanScreeningWorkflow.class, opts).screen(APP));
        assertEquals(42L, env.getWorkflowClient().newWorkflowStub(LoanBookingWorkflow.class, opts).book(APP));
        assertEquals(List.of("screen:20000000", "correlate:loan-screened:pi-7:{fraudVerdict=NO_ALERT}", "book:7",
                "correlate:loan-booked:pi-7:{loanId=42}"), log);
        env.close();
    }

    @Test
    void tazamaVerdicts() throws Exception {
        ObjectMapper m = new ObjectMapper();
        assertEquals("INTERDICT", LoanActivitiesImpl.verdict(m.readTree(
                "{\"report\":{\"status\":\"ALRT\",\"tadpResult\":{\"typologyResult\":[{\"result\":400,\"workflow\":{\"interdictionThreshold\":400}}]}}}")));
        assertEquals("ALERT", LoanActivitiesImpl.verdict(m.readTree("{\"report\":{\"status\":\"ALRT\",\"tadpResult\":{\"typologyResult\":[]}}}")));
        assertEquals("NO_ALERT", LoanActivitiesImpl.verdict(m.readTree("{\"report\":{\"status\":\"NALT\"}}")));
        assertEquals("UNKNOWN", new LoanActivitiesImpl("x", null, null, null, "", 1, null, null).screen(APP));
    }

    /** Live against a Fineract (FINERACT_LIVE=http://…/fineract-provider, basic auth mifos/password): books once, a retry finds the same loan. */
    @Test
    @EnabledIfEnvironmentVariable(named = "FINERACT_LIVE", matches = "http.*")
    void booksInFineractIdempotently() throws Exception {
        String f = System.getenv("FINERACT_LIVE");
        String basic = Base64.getEncoder().encodeToString("mifos:password".getBytes());
        HttpClient h = HttpClient.newHttpClient();
        ObjectMapper m = new ObjectMapper();
        String d = java.time.LocalDate.now(LoanActivitiesImpl.TENANT_ZONE).format(LoanActivitiesImpl.D);
        java.util.function.BiFunction<String, String, JsonNode> post = (path, body) -> {
            try {
                return m.readTree(h.send(HttpRequest.newBuilder(URI.create(f + "/api/v1/" + path)).header("Authorization", "Basic " + basic)
                        .header("Fineract-Platform-TenantId", "default").header("content-type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()).body());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        int r = (int) (Math.random() * 900) + 100;
        long client = post.apply("clients", "{\"officeId\":1,\"legalFormId\":1,\"firstname\":\"Loan\",\"lastname\":\"Applicant" + r
                + "\",\"active\":true,\"activationDate\":\"" + d + "\",\"locale\":\"en\",\"dateFormat\":\"dd MMMM yyyy\"}").path("clientId").asLong();
        long product = post.apply("loanproducts", "{\"name\":\"Term loan " + r + "\",\"shortName\":\"T" + r + "\",\"currencyCode\":\"INR\","
                + "\"digitsAfterDecimal\":2,\"inMultiplesOf\":0,\"principal\":100000,\"numberOfRepayments\":12,\"repaymentEvery\":1,"
                + "\"repaymentFrequencyType\":2,\"interestRatePerPeriod\":1.5,\"interestRateFrequencyType\":2,\"amortizationType\":1,\"interestType\":0,"
                + "\"interestCalculationPeriodType\":1,\"transactionProcessingStrategyCode\":\"mifos-standard-strategy\",\"accountingRule\":1,"
                + "\"daysInYearType\":1,\"daysInMonthType\":1,\"isInterestRecalculationEnabled\":false,\"locale\":\"en\"}").path("resourceId").asLong();
        LoanActivitiesImpl acts = new LoanActivitiesImpl(f, null, null, null, basic, product, null, null);
        LoanApplication app = new LoanApplication("pi-live", "live-" + r, "cust-live", client, 15_000_000L, 12, "EQUIPMENT");
        long loan = acts.book(app);
        assertEquals(loan, acts.book(app), "a retried booking finds the same loan");
        JsonNode l = m.readTree(h.send(HttpRequest.newBuilder(URI.create(f + "/api/v1/loans/" + loan)).header("Authorization", "Basic " + basic)
                .header("Fineract-Platform-TenantId", "default").GET().build(), HttpResponse.BodyHandlers.ofString()).body());
        assertTrue(l.path("status").path("active").asBoolean(), l.path("status").toString());
        assertEquals(150000.0, l.path("summary").path("principalDisbursed").asDouble());
    }
}
