package dev.difme.core.common.process;

import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;

/** Side effects of loan origination (saga-orchestrator's loan-activities worker). */
@ActivityInterface
public interface LoanActivities {
    String TASK_QUEUE = "loan-activities";

    /** Tazama verdict for the application as a payment initiation: NO_ALERT, ALERT, INTERDICT or UNKNOWN. */
    @ActivityMethod
    String screen(LoanApplication application);

    /** Creates, approves and disburses the loan in Fineract; idempotent on the business key (externalId). Returns the loan id. */
    @ActivityMethod
    long book(LoanApplication application);
}
