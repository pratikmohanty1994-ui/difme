package dev.difme.process;

import static org.junit.jupiter.api.Assertions.*;

import dev.difme.process.rules.FieldRule;
import dev.difme.process.rules.FieldRules;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.finos.fluxnova.bpm.engine.ProcessEngine;
import org.finos.fluxnova.bpm.engine.ProcessEngineConfiguration;
import org.finos.fluxnova.bpm.engine.externaltask.LockedExternalTask;
import org.finos.fluxnova.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.finos.fluxnova.bpm.engine.repository.DeploymentBuilder;
import org.finos.fluxnova.bpm.engine.runtime.ProcessInstance;
import org.finos.fluxnova.bpm.engine.task.Task;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Deploys every model in processes/ to a real in-memory Fluxnova 3.1.1 engine and executes it. */
class ModelsOnFluxnovaEngineTest {
    static ProcessEngine engine;

    @BeforeAll
    static void deployAll() throws Exception {
        ProcessEngineConfigurationImpl cfg = (ProcessEngineConfigurationImpl)
                ProcessEngineConfiguration.createStandaloneInMemProcessEngineConfiguration();
        cfg.setJdbcUrl("jdbc:h2:mem:difme-models;DB_CLOSE_DELAY=-1");
        cfg.setDatabaseSchemaUpdate(ProcessEngineConfiguration.DB_SCHEMA_UPDATE_CREATE_DROP);
        cfg.setJobExecutorActivate(false);
        cfg.setEnforceHistoryTimeToLive(false);
        cfg.setHistoryTimeToLive("P30D");
        engine = cfg.buildProcessEngine();

        Path root = Path.of(System.getProperty("user.dir")).resolve("../../../processes").normalize();
        DeploymentBuilder d = engine.getRepositoryService().createDeployment().name("difme-processes");
        try (Stream<Path> files = Files.walk(root)) {
            // processes/ph-ee holds Zeebe-format models, deployed only after ci/zeebe-bpmn-to-fluxnova.py converts them
            for (Path p : files.filter(f -> f.toString().matches(".*\\.(bpmn|dmn|cmmn)$") && !f.toString().contains("/ph-ee/")).toList()) {
                InputStream in = Files.newInputStream(p);
                d.addInputStream(p.getFileName().toString(), in);
            }
        }
        d.deploy();
    }

    @AfterAll
    static void close() {
        engine.close();
    }

    private static Map<String, Object> vars(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @Test
    void kycRiskDecision() {
        var ds = engine.getDecisionService();
        assertEquals("LOW", ds.evaluateDecisionTableByKey("kyc-risk", vars("pep", false, "countryRisk", "LOW", "expectedMonthlyVolumeMinor", 1_000L)).getSingleResult().getSingleEntry());
        assertEquals("HIGH", ds.evaluateDecisionTableByKey("kyc-risk", vars("pep", true, "countryRisk", "LOW", "expectedMonthlyVolumeMinor", 1_000L)).getSingleResult().getSingleEntry());
        assertEquals("MEDIUM", ds.evaluateDecisionTableByKey("kyc-risk", vars("pep", false, "countryRisk", "LOW", "expectedMonthlyVolumeMinor", 20_000_000L)).getSingleResult().getSingleEntry());
    }

    @Test
    void formRulesForIndianBusiness() {
        List<Map<String, Object>> rows = engine.getDecisionService()
                .evaluateDecisionTableByKey("kyc-form-rules", vars("accountType", "BUSINESS", "country", "IN", "pep", false))
                .getResultList();
        Map<String, FieldRule> rules = FieldRules.merge(rows);
        assertEquals(Boolean.TRUE, rules.get("companyRegistrationNumber").required());
        assertEquals(Boolean.FALSE, rules.get("dateOfBirth").visible());
        assertEquals(Boolean.TRUE, rules.get("taxId").required());
        assertEquals(Boolean.FALSE, rules.get("pepDetails").visible());
        assertEquals(1_000_000_000d, rules.get("expectedMonthlyVolume").max());
        assertFalse(FieldRules.validate(rules, Map.of("companyRegistrationNumber", "U1234", "taxId", "ABCDE1234F",
                "expectedMonthlyVolume", 10)).iterator().hasNext());
    }

    @Test
    void paymentLimitsConfig() {
        Object limit = engine.getDecisionService()
                .evaluateDecisionTableByKey("payment-limits", vars("channel", "MOBILE", "riskLevel", "MEDIUM"))
                .getSingleResult().getSingleEntry();
        assertEquals(5_000_000L, ((Number) limit).longValue());
    }

    @Test
    void lowRiskGoesStraightToTemporalThenWaitsForCallback() {
        ProcessInstance pi = engine.getRuntimeService().startProcessInstanceByKey("kyc-onboarding", "bk-low",
                vars("pep", false, "countryRisk", "LOW", "expectedMonthlyVolumeMinor", 1_000L));
        List<LockedExternalTask> tasks = engine.getExternalTaskService().fetchAndLock(5, "test")
                .topic("temporal:AccountProvisioningWorkflow", 10_000).execute();
        assertEquals(1, tasks.size());
        engine.getExternalTaskService().complete(tasks.get(0).getId(), "test");
        assertEquals(1, engine.getRuntimeService().createProcessInstanceQuery().processInstanceId(pi.getId()).count(),
                "waiting for the Temporal callback");
        engine.getRuntimeService().createMessageCorrelation("account-provisioned").processInstanceId(pi.getId())
                .setVariable("accountId", "acc-1").correlate();
        assertEquals(0, engine.getRuntimeService().createProcessInstanceQuery().processInstanceId(pi.getId()).count());
    }

    @Test
    void highRiskNeedsComplianceReview() {
        ProcessInstance pi = engine.getRuntimeService().startProcessInstanceByKey("kyc-onboarding", "bk-high",
                vars("pep", true, "countryRisk", "LOW", "expectedMonthlyVolumeMinor", 1_000L));
        Task review = engine.getTaskService().createTaskQuery().processInstanceId(pi.getId()).singleResult();
        assertEquals("compliance-review", review.getTaskDefinitionKey());
        engine.getTaskService().complete(review.getId(), vars("approved", false, "reviewNotes", "insufficient evidence"));
        assertEquals(0, engine.getRuntimeService().createProcessInstanceQuery().processInstanceId(pi.getId()).count());
    }

    private static Object credit(String fraud, int score, int dti, long amount) {
        return engine.getDecisionService().evaluateDecisionTableByKey("credit-decision",
                vars("fraudVerdict", fraud, "bureauScore", score, "dtiPercent", dti, "amountMinor", amount)).getSingleResult().getSingleEntry();
    }

    @Test
    void creditDecision() {
        assertEquals("APPROVE", credit("NO_ALERT", 760, 25, 20_000_000L));
        assertEquals("DECLINE", credit("INTERDICT", 820, 10, 1_000_000L));
        assertEquals("REFER", credit("ALERT", 820, 10, 1_000_000L));
        assertEquals("REFER", credit("UNKNOWN", 820, 10, 1_000_000L));
        assertEquals("DECLINE", credit("NO_ALERT", 540, 10, 1_000_000L));
        assertEquals("DECLINE", credit("NO_ALERT", 760, 55, 1_000_000L));
        assertEquals("REFER", credit("NO_ALERT", 620, 10, 1_000_000L));
        assertEquals("REFER", credit("NO_ALERT", 760, 10, 60_000_000L));
        assertEquals("REFER", credit("NO_ALERT", 760, 45, 1_000_000L));
    }

    private ProcessInstance applyForLoan(String key, String fraudVerdict, int score, int dti, long amount) {
        ProcessInstance pi = engine.getRuntimeService().startProcessInstanceByKey("loan-origination", key,
                vars("applicantId", "cust-1", "fineractClientId", 7L, "amountMinor", amount, "termMonths", 12, "bureauScore", score, "dtiPercent", dti));
        List<LockedExternalTask> screen = engine.getExternalTaskService().fetchAndLock(50, "test")
                .topic("temporal:LoanScreeningWorkflow", 10_000).execute().stream().filter(t -> t.getProcessInstanceId().equals(pi.getId())).toList();
        assertEquals(1, screen.size());
        engine.getExternalTaskService().complete(screen.get(0).getId(), "test");
        engine.getRuntimeService().createMessageCorrelation("loan-screened").processInstanceId(pi.getId())
                .setVariable("fraudVerdict", fraudVerdict).correlate();
        return pi;
    }

    private boolean running(ProcessInstance pi) {
        return engine.getRuntimeService().createProcessInstanceQuery().processInstanceId(pi.getId()).count() == 1;
    }

    private void booked(ProcessInstance pi) {
        List<LockedExternalTask> book = engine.getExternalTaskService().fetchAndLock(50, "test")
                .topic("temporal:LoanBookingWorkflow", 10_000).execute().stream().filter(t -> t.getProcessInstanceId().equals(pi.getId())).toList();
        assertEquals(1, book.size(), "booking started");
        engine.getExternalTaskService().complete(book.get(0).getId(), "test");
        assertTrue(running(pi), "waiting for the booking callback");
        engine.getRuntimeService().createMessageCorrelation("loan-booked").processInstanceId(pi.getId()).setVariable("loanId", 42L).correlate();
        assertFalse(running(pi));
    }

    @Test
    void loanApprovedAutomaticallyIsBooked() {
        booked(applyForLoan("loan-ok", "NO_ALERT", 760, 25, 20_000_000L));
    }

    @Test
    void loanReferredGoesToUnderwriting() {
        ProcessInstance pi = applyForLoan("loan-refer", "ALERT", 760, 25, 20_000_000L);
        Task t = engine.getTaskService().createTaskQuery().processInstanceId(pi.getId()).singleResult();
        assertEquals("underwriting", t.getTaskDefinitionKey());
        engine.getTaskService().complete(t.getId(), vars("approved", true, "underwritingNotes", "verified income"));
        booked(pi);
    }

    @Test
    void loanDeclinedEndsWithoutBooking() {
        ProcessInstance pi = applyForLoan("loan-decline", "INTERDICT", 760, 25, 20_000_000L);
        assertFalse(running(pi));
        assertEquals(0, engine.getExternalTaskService().createExternalTaskQuery().topicName("temporal:LoanBookingWorkflow").count());
    }

    @Test
    void disputeCaseStarts() {
        var ci = engine.getCaseService().createCaseInstanceByKey("dispute-case");
        assertTrue(engine.getCaseService().createCaseExecutionQuery().caseInstanceId(ci.getId()).activityId("pi-investigate").count() >= 1);
    }
}
