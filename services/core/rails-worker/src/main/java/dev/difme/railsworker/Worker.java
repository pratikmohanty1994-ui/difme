package dev.difme.railsworker;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/** Long-polls Fluxnova for the external tasks of DIFME's own PH-EE flows: card checkout/refund (Hyperswitch, Tazama), account opening (Fineract). */
@ApplicationScoped
public class Worker {
    private static final Logger LOG = Logger.getLogger(Worker.class);

    @ConfigProperty(name = "difme.railsworker.enabled") boolean enabled;
    @ConfigProperty(name = "difme.railsworker.fluxnova.url") String fluxnovaUrl;
    @ConfigProperty(name = "difme.railsworker.fluxnova.basic") java.util.Optional<String> fluxnovaBasic;
    @ConfigProperty(name = "difme.railsworker.hyperswitch.url") String pspUrl;
    @ConfigProperty(name = "difme.railsworker.hyperswitch.admin-key") java.util.Optional<String> adminKey;
    @ConfigProperty(name = "difme.railsworker.hyperswitch.acquirer-key") java.util.Optional<String> acquirerKey;
    @ConfigProperty(name = "difme.railsworker.cards") java.util.Optional<String> cards;
    // Fineract (account opening): Keycloak client credentials, accepted through Fineract's OIDC federation.
    @ConfigProperty(name = "difme.railsworker.fineract.url") java.util.Optional<String> fineractUrl;
    @ConfigProperty(name = "difme.railsworker.fineract.token-url") java.util.Optional<String> fineractTokenUrl;
    @ConfigProperty(name = "difme.railsworker.fineract.client-id") java.util.Optional<String> fineractClient;
    @ConfigProperty(name = "difme.railsworker.fineract.client-secret") java.util.Optional<String> fineractSecret;

    private volatile boolean running;
    private Thread thread;

    void start(@Observes StartupEvent e) {
        if (!enabled) return;
        Fluxnova fx = new Fluxnova(fluxnovaUrl, fluxnovaBasic.orElse(null), "rails-worker-" + ProcessHandle.current().pid());
        // Fraud check before capture (ADR-023): TAZAMA_TMS_URL / TAZAMA_ADMIN_URL / TAZAMA_BUDGET_MS, off when not set.
        Tazama tazama = Tazama.fromEnv();
        CardTasks cardTasks = new CardTasks(new Hyperswitch(pspUrl, adminKey.orElse(""), acquirerKey.orElse("")), new CardsOnFile(cards.orElse("")),
                tazama == null ? null : tazama::evaluate, Boolean.parseBoolean(System.getenv("TAZAMA_FAIL_OPEN")));
        running = true;
        Tasks tasks = cardTasks;
        if (fineractUrl.filter(u -> !u.isBlank()).isPresent()) {
            Fineract cbs = new Fineract(fineractUrl.get(), Fineract.clientCredentials(fineractTokenUrl.orElseThrow(),
                    fineractClient.orElseThrow(), fineractSecret.orElseThrow()), "default");
            tasks = Tasks.of(cardTasks, new AccountTasks(name -> cbs.account(name).id()));
        }
        Tasks all = tasks;
        thread = Thread.ofPlatform().name("ph-ee-tasks").daemon().start(() -> loop(fx, all));
        LOG.info("PH-EE DIFME flows worker: topics " + all.topics() + (tazama == null ? "; no fraud check (Tazama not configured)" : "; fraud check on Tazama"));
    }

    void stop(@Observes ShutdownEvent e) {
        running = false;
        if (thread != null) thread.interrupt();
    }

    static void runOnce(Fluxnova fx, Tasks tasks, long pollMs) {
        for (Fluxnova.Task t : fx.fetchAndLock(tasks.topics(), 4, pollMs, 120_000)) {
            try {
                Map<String, Object> out = tasks.handle(t);
                fx.complete(t, out);
                LOG.info("card task " + t.topic() + " " + (t.str("refundId") != null ? t.str("refundId") : t.str("paymentId") != null ? t.str("paymentId") : t.str("accountName")) + ": " + out.getOrDefault("chargeStatus", out.getOrDefault("refundStatus", out.getOrDefault("accountStatus", "")))
                        + (out.containsKey("fraudVerdict") ? " fraud " + out.get("fraudVerdict") + " -> " + out.get("fraudAction") : "")
                        + (out.containsKey("declineCode") ? " " + out.get("declineCode") : ""));
            } catch (RuntimeException ex) {
                int left = (t.retries() < 0 ? 5 : t.retries()) - 1;
                LOG.warn("card task " + t.topic() + " " + t.id() + " failed (" + left + " retries left): " + ex.getMessage());
                fx.failure(t, ex.getMessage() == null ? ex.toString() : ex.getMessage(), left, 5_000);
            }
        }
    }

    private void loop(Fluxnova fx, Tasks tasks) {
        long backoff = 1_000;
        while (running) {
            try {
                runOnce(fx, tasks, 20_000);
                backoff = 1_000;
            } catch (RuntimeException ex) {
                LOG.warn("Fluxnova poll failed, retrying in " + backoff + " ms: " + ex.getMessage());
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    return;
                }
                backoff = Math.min(backoff * 2, 30_000);
            }
        }
    }
}
