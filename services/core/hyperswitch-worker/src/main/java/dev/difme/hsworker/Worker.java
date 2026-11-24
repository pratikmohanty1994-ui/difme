package dev.difme.hsworker;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/** Long-polls Fluxnova for the card flows' external tasks and answers them through Hyperswitch. */
@ApplicationScoped
public class Worker {
    private static final Logger LOG = Logger.getLogger(Worker.class);

    @ConfigProperty(name = "difme.hsworker.enabled") boolean enabled;
    @ConfigProperty(name = "difme.hsworker.fluxnova.url") String fluxnovaUrl;
    @ConfigProperty(name = "difme.hsworker.fluxnova.basic") java.util.Optional<String> fluxnovaBasic;
    @ConfigProperty(name = "difme.hsworker.hyperswitch.url") String pspUrl;
    @ConfigProperty(name = "difme.hsworker.hyperswitch.admin-key") java.util.Optional<String> adminKey;
    @ConfigProperty(name = "difme.hsworker.hyperswitch.acquirer-key") java.util.Optional<String> acquirerKey;
    @ConfigProperty(name = "difme.hsworker.cards") java.util.Optional<String> cards;

    private volatile boolean running;
    private Thread thread;

    void start(@Observes StartupEvent e) {
        if (!enabled) return;
        Fluxnova fx = new Fluxnova(fluxnovaUrl, fluxnovaBasic.orElse(null), "hyperswitch-worker-" + ProcessHandle.current().pid());
        CardTasks tasks = new CardTasks(new Hyperswitch(pspUrl, adminKey.orElse(""), acquirerKey.orElse("")), new CardsOnFile(cards.orElse("")));
        running = true;
        thread = Thread.ofPlatform().name("card-flows").daemon().start(() -> loop(fx, tasks));
        LOG.info("PH-EE card flows worker: topics " + CardTasks.CHARGE + ", " + CardTasks.REFUND);
    }

    void stop(@Observes ShutdownEvent e) {
        running = false;
        if (thread != null) thread.interrupt();
    }

    static void runOnce(Fluxnova fx, CardTasks tasks, long pollMs) {
        for (Fluxnova.Task t : fx.fetchAndLock(List.of(CardTasks.CHARGE, CardTasks.REFUND), 4, pollMs, 120_000)) {
            try {
                Map<String, Object> out = tasks.handle(t);
                fx.complete(t, out);
                LOG.info("card task " + t.topic() + " " + (t.str("refundId") != null ? t.str("refundId") : t.str("paymentId")) + ": " + out.getOrDefault("chargeStatus", out.get("refundStatus"))
                        + (out.containsKey("declineCode") ? " " + out.get("declineCode") : ""));
            } catch (RuntimeException ex) {
                int left = (t.retries() < 0 ? 5 : t.retries()) - 1;
                LOG.warn("card task " + t.topic() + " " + t.id() + " failed (" + left + " retries left): " + ex.getMessage());
                fx.failure(t, ex.getMessage() == null ? ex.toString() : ex.getMessage(), left, 5_000);
            }
        }
    }

    private void loop(Fluxnova fx, CardTasks tasks) {
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
