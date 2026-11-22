package dev.difme.hub.api;

import dev.difme.hub.Hub;
import dev.difme.hub.cbs.Fineract;
import dev.difme.hub.psp.Hyperswitch;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowClientOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import io.temporal.worker.WorkerFactory;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/** Connects to Temporal, the CBS and the PSP, and runs the hub's worker in this process. */
@ApplicationScoped
public class HubSetup {
    @ConfigProperty(name = "difme.temporal.target") String target;
    @ConfigProperty(name = "difme.temporal.namespace") String namespace;
    @ConfigProperty(name = "difme.hub.fineract.url") String fineractUrl;
    @ConfigProperty(name = "difme.hub.fineract.user") String fineractUser;
    @ConfigProperty(name = "difme.hub.fineract.password") String fineractPassword;
    @ConfigProperty(name = "difme.hub.fineract.tenant") String tenant;
    @ConfigProperty(name = "difme.hub.fineract.token-url") java.util.Optional<String> fineractTokenUrl;
    @ConfigProperty(name = "difme.hub.hyperswitch.url") String pspUrl;
    @ConfigProperty(name = "difme.hub.hyperswitch.admin-key") String pspAdminKey;
    @ConfigProperty(name = "difme.hub.hyperswitch.acquirer-key") String acquirerKey;

    private WorkerFactory factory;
    private Hub hub;

    void start(@Observes StartupEvent ev) {
        // With a token URL, user/password are the Keycloak client id/secret (Fineract with OIDC federation).
        Fineract cbs = fineractTokenUrl.filter(u -> !u.isBlank())
                .map(u -> new Fineract(fineractUrl, Fineract.clientCredentials(u, fineractUser, fineractPassword), tenant))
                .orElseGet(() -> new Fineract(fineractUrl, fineractUser, fineractPassword, tenant));
        Hyperswitch psp = new Hyperswitch(pspUrl, pspAdminKey, acquirerKey);
        WorkflowServiceStubs stubs = WorkflowServiceStubs.newServiceStubs(WorkflowServiceStubsOptions.newBuilder().setTarget(target).build());
        WorkflowClient client = WorkflowClient.newInstance(stubs, WorkflowClientOptions.newBuilder().setNamespace(namespace).build());
        factory = WorkerFactory.newInstance(client);
        Hub.register(factory, cbs, psp);
        factory.start();
        // Fraud check on Tazama when TAZAMA_TMS_URL and TAZAMA_ADMIN_URL are set (ADR-023); TAZAMA_FAIL_OPEN=true captures
        // payments Tazama gave no verdict on, otherwise they are held for review.
        hub = new Hub(client, cbs, psp, dev.difme.hub.frm.Tazama.fromEnv(), Boolean.parseBoolean(System.getenv("TAZAMA_FAIL_OPEN")));
    }

    void stop(@Observes ShutdownEvent ev) {
        if (factory != null) factory.shutdown();
    }

    @Produces @Singleton
    Hub hub() { return hub; }
}
