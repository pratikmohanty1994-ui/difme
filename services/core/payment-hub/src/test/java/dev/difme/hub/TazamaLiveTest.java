package dev.difme.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.difme.hub.frm.Tazama;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * The hub's Tazama client against a real Tazama (TMS validates the hub's ISO 20022 messages; the admin service serves
 * the real report). Runs when TAZAMA_LIVE_TMS and TAZAMA_LIVE_ADMIN are set, e.g. against ci/tazama-e2e.sh's stack.
 * TAZAMA_LIVE_EXPECT: the verdict that stack's configuration gives (ci/tazama-e2e.sh: INTERDICT, its stand-in scorer
 * puts every payment in the model's BLOCK band).
 */
class TazamaLiveTest {
    @Test
    void realTazamaJudgesAHubPayment() {
        String tms = System.getenv("TAZAMA_LIVE_TMS"), admin = System.getenv("TAZAMA_LIVE_ADMIN");
        assumeTrue(tms != null && admin != null, "TAZAMA_LIVE_TMS / TAZAMA_LIVE_ADMIN not set");
        Tazama t = new Tazama(tms, admin, Duration.ofSeconds(20));
        String id = "live-" + System.currentTimeMillis();
        Tazama.Evaluation e = t.evaluate(id, "partner-live", "merchant-live", 852000, "INR");
        System.out.println("Tazama verdict for " + id + ": " + e);
        String expect = System.getenv().getOrDefault("TAZAMA_LIVE_EXPECT", "INTERDICT");
        assertEquals(Tazama.Verdict.valueOf(expect), e.verdict(), e.detail());
    }
}
