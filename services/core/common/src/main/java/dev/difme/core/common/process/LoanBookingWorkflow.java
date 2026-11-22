package dev.difme.core.common.process;

import io.temporal.workflow.WorkflowInterface;
import io.temporal.workflow.WorkflowMethod;

/** Started by process-gateway for BPMN topic {@code temporal:LoanBookingWorkflow}: loan, approval, disbursement in Fineract, then message loan-booked. */
@WorkflowInterface
public interface LoanBookingWorkflow {
    String TASK_QUEUE = "loans-saga";

    @WorkflowMethod
    long book(LoanApplication application);
}
