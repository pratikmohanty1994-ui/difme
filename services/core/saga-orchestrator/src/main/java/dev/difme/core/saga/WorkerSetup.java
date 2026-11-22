package dev.difme.core.saga;

import dev.difme.core.common.process.AccountProvisioningWorkflow;
import dev.difme.core.common.saga.PaymentWorkflow;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowClientOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import io.temporal.worker.WorkerFactory;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class WorkerSetup {
    @ConfigProperty(name = "difme.temporal.target") String target;
    @ConfigProperty(name = "difme.temporal.namespace") String namespace;
    private WorkerFactory factory;

    void start(@Observes StartupEvent ev) {
        WorkflowServiceStubs stubs = WorkflowServiceStubs.newServiceStubs(
                WorkflowServiceStubsOptions.newBuilder().setTarget(target).build());
        WorkflowClient client = WorkflowClient.newInstance(stubs, WorkflowClientOptions.newBuilder().setNamespace(namespace).build());
        factory = WorkerFactory.newInstance(client);
        factory.newWorker(PaymentWorkflow.TASK_QUEUE).registerWorkflowImplementationTypes(PaymentWorkflowImpl.class);
        factory.newWorker(AccountProvisioningWorkflow.TASK_QUEUE).registerWorkflowImplementationTypes(AccountProvisioningWorkflowImpl.class);
        // Loan origination (ADR-025): workflows and their Fineract/Tazama activities
        factory.newWorker(dev.difme.core.common.process.LoanScreeningWorkflow.TASK_QUEUE).registerWorkflowImplementationTypes(
                LoanWorkflowsImpl.Screening.class, LoanWorkflowsImpl.Booking.class);
        var env = System.getenv();
        factory.newWorker(dev.difme.core.common.process.LoanActivities.TASK_QUEUE).registerActivitiesImplementations(new LoanActivitiesImpl(
                env.getOrDefault("FINERACT_URL", "http://fineract.rails.svc:8080/fineract-provider"), env.get("FINERACT_TOKEN_URL"),
                env.get("FINERACT_CLIENT_ID"), env.get("FINERACT_CLIENT_SECRET"), env.get("FINERACT_BASIC_AUTH"),
                Long.parseLong(env.getOrDefault("LOAN_PRODUCT_ID", "1")), env.get("TAZAMA_TMS_URL"), env.get("TAZAMA_ADMIN_URL")));
        factory.start();
    }

    void stop(@Observes ShutdownEvent ev) {
        if (factory != null) factory.shutdown();
    }
}
