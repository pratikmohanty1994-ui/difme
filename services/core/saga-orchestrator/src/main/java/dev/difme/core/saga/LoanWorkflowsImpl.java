package dev.difme.core.saga;

import dev.difme.core.common.process.LoanActivities;
import dev.difme.core.common.process.LoanApplication;
import dev.difme.core.common.process.LoanBookingWorkflow;
import dev.difme.core.common.process.LoanScreeningWorkflow;
import dev.difme.core.common.process.ProcessCallbacks;
import io.temporal.activity.ActivityOptions;
import io.temporal.common.RetryOptions;
import io.temporal.workflow.Workflow;
import java.time.Duration;
import java.util.Map;

/** Loan origination steps owned by Temporal (ADR-008/025): each does its side effect, then wakes the BPMN process. */
public final class LoanWorkflowsImpl {
    private LoanWorkflowsImpl() {}

    static final RetryOptions RETRY = RetryOptions.newBuilder()
            .setInitialInterval(Duration.ofMillis(500)).setBackoffCoefficient(2.0).setMaximumAttempts(10).build();

    static LoanActivities loans() {
        return Workflow.newActivityStub(LoanActivities.class, ActivityOptions.newBuilder().setTaskQueue(LoanActivities.TASK_QUEUE)
                .setStartToCloseTimeout(Duration.ofSeconds(30)).setRetryOptions(RETRY).build());
    }

    static ProcessCallbacks process() {
        return Workflow.newActivityStub(ProcessCallbacks.class, ActivityOptions.newBuilder().setTaskQueue(ProcessCallbacks.TASK_QUEUE)
                .setStartToCloseTimeout(Duration.ofSeconds(10)).setRetryOptions(RETRY).build());
    }

    public static class Screening implements LoanScreeningWorkflow {
        @Override
        public String screen(LoanApplication in) {
            String verdict = loans().screen(in);
            process().correlate("loan-screened", in.processInstanceId(), Map.of("fraudVerdict", verdict));
            return verdict;
        }
    }

    public static class Booking implements LoanBookingWorkflow {
        @Override
        public long book(LoanApplication in) {
            long loanId = loans().book(in);
            process().correlate("loan-booked", in.processInstanceId(), Map.of("loanId", loanId));
            return loanId;
        }
    }
}
