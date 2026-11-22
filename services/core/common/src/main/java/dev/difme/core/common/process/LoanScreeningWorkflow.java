package dev.difme.core.common.process;

import io.temporal.workflow.WorkflowInterface;
import io.temporal.workflow.WorkflowMethod;

/** Started by process-gateway for BPMN topic {@code temporal:LoanScreeningWorkflow}: fraud screening, then message loan-screened. */
@WorkflowInterface
public interface LoanScreeningWorkflow {
    String TASK_QUEUE = "loans-saga";

    @WorkflowMethod
    String screen(LoanApplication application);
}
