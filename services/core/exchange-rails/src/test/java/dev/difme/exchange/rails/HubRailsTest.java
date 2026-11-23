package dev.difme.exchange.rails;

import static org.junit.jupiter.api.Assertions.*;

import dev.difme.exchange.rails.hub.HubCheckout;
import dev.difme.exchange.rails.sim.SimRails;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** The exchange's rails switched to the payment hub, against a scripted hub. */
class HubRailsTest {
    static final PaymentHub.CardOnFile CARD = new PaymentHub.CardOnFile("4375510000000001", "12", "2030", "123");

    static final class FakeHub implements PaymentHub {
        final List<String> calls = new CopyOnWriteArrayList<>();
        volatile Outcome cardAnswer = new Outcome("SETTLED", "merchant credited");
        final AtomicInteger outages = new AtomicInteger();

        private void maybeDown() { if (outages.getAndUpdate(n -> Math.max(0, n - 1)) > 0) throw new IllegalStateException("hub down"); }
        public Outcome deposit(String id, String account, long a) { maybeDown(); calls.add("deposit " + id + " " + account + " " + a); return new Outcome("DONE", "1"); }
        public Outcome transfer(String id, String f, String t, long a, String n) { maybeDown(); calls.add("transfer " + id + " " + f + ">" + t + " " + a); return new Outcome("DONE", "1"); }
        public Outcome payCard(String id, String m, long a, CardOnFile c) { maybeDown(); calls.add("pay " + id + " " + m + " " + a + " " + c.pan()); return cardAnswer; }
        public Outcome refundCard(String id, String p, String m, long a, String r) { calls.add("refund " + id + " " + p + " " + a); return new Outcome("REFUNDED", "ok"); }
    }

    // One instruction per order (the token is single-use, even when the network declines the attempt).
    private static MerchantCheckoutPort.Response buy(SimRails rails, long partner, String stan, long amount) {
        long order = stan.equals("000001") ? 77 : Long.parseLong(stan);
        var token = rails.credentials.issue(new AgentCredentialPort.Instruction(new UUID(order, 0), partner, "Shop-1", amount, "INR"), 1_000);
        return rails.cardCheckout().authorize(new MerchantCheckoutPort.Authorization(stan, token.token(), "Shop-1", amount, "INR"), 1_000);
    }

    @Test
    void approvedCardPaymentGoesThroughTheHub() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        rails.useHub(hub, Map.of(42L, CARD), m -> {});
        var r = buy(rails, 42, "000001", 800_000);
        assertTrue(r.approved());
        assertEquals("auc77-p42-000001", r.rrn());
        assertEquals(List.of("pay auc77-p42-000001 shop-1 800000 4375510000000001"), hub.calls);
        assertSame(r, rails.cardCheckout().authorize(new MerchantCheckoutPort.Authorization("000001", "spent", "Shop-1", 800_000, "INR"), 1_000));
        assertEquals(1, hub.calls.size());     // duplicate STAN: the first answer, no second charge
        rails.cardCheckout().reverse(r.rrn());
        assertEquals("refund rev-auc77-p42-000001 auc77-p42-000001 800000", hub.calls.get(1));
    }

    @Test
    void networkDeclineCodesReachTheFailover() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        rails.useHub(hub, Map.of(42L, CARD), m -> {});
        hub.cardAnswer = new PaymentHub.Outcome("DECLINED", "51: Insufficient funds");
        assertEquals("51", buy(rails, 42, "000002", 1).responseCode());
        hub.cardAnswer = new PaymentHub.Outcome("DECLINED", "failed: no code");
        assertEquals("05", buy(rails, 42, "000003", 1).responseCode());
        hub.cardAnswer = new PaymentHub.Outcome("REFUNDED", "merchant credit failed; card refunded");
        assertEquals("96", buy(rails, 42, "000004", 1).responseCode());
        hub.outages.set(1);
        assertEquals("91", buy(rails, 42, "000005", 1).responseCode());   // hub unreachable: issuer unavailable
        assertEquals("14", buy(rails, 99, "000006", 1).responseCode());   // no card on file for partner 99
    }

    @Test
    void partnersWithoutTheirOwnCardUseTheDefaultCard() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        var other = new PaymentHub.CardOnFile("4375510000000019", "12", "2030", "123");
        rails.useHub(hub, Map.of(42L, CARD, HubCheckout.ANY_PARTNER, other), m -> {});
        assertTrue(buy(rails, 1_000_002, "000007", 100).approved());   // a standing mandate's partner node
        assertTrue(buy(rails, 42, "000008", 100).approved());
        assertEquals(List.of("pay auc7-p1000002-000007 shop-1 100 4375510000000019", "pay auc8-p42-000008 shop-1 100 4375510000000001"), hub.calls);
    }

    @Test
    void escrowMovementsAreBookedOnTheCoreBankingSystem() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        hub.outages.set(2);                                    // the first booking needs two retries
        rails.useHub(hub, Map.of(), m -> {});
        rails.escrow.hold("auction-1", "buyer-1", 1_000);
        rails.escrow.hold("auction-1", "buyer-1", 1_000);      // idempotent: booked once
        rails.escrow.release("auction-1", "principal", "partner-42", 700);
        rails.escrow.release("auction-1", "principal", "partner-42", 700);
        rails.escrow.refund("auction-1", "return", 100);
        rails.escrow.refund("auction-1");                      // the remaining 200
        assertTrue(rails.cbsMirror().drain(10_000));
        assertEquals(List.of("deposit hold-auction-1 escrow 1000", "transfer rel-auction-1-principal escrow>partner-42 700",
                "transfer ref-auction-1-return escrow>buyer-1 100", "transfer ref-auction-1-all escrow>buyer-1 200"), hub.calls);
        assertEquals(0, rails.cbsMirror().pending());
        assertThrows(IllegalStateException.class, () -> rails.escrow.release("auction-1", "again", "partner-42", 1));
        assertTrue(rails.cbsMirror().drain(1_000));
        assertEquals(4, hub.calls.size());                     // a refused release books nothing
        rails.cbsMirror().close();
    }

    @Test
    void bookingsAreJournalledAndPendingOnesResumeAfterARestart() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        rails.useHub(hub, Map.of(), m -> {});
        var journal = new java.util.concurrent.ConcurrentHashMap<String, String>();
        rails.cbsMirror().journalTo((m, st) -> journal.put(m.id(), st));
        rails.escrow.hold("auction-9", "buyer-9", 500);
        assertTrue(rails.cbsMirror().drain(5_000));
        assertEquals(Map.of("hold-auction-9", "BOOKED"), journal);
        rails.cbsMirror().close();
        // A new process: one movement was still PENDING when the old one stopped; it is sent again, once.
        SimRails after = new SimRails();
        FakeHub hub2 = new FakeHub();
        after.useHub(hub2, Map.of(), m -> {});
        after.cbsMirror().journalTo((m, st) -> journal.put(m.id(), st));
        after.cbsMirror().resume(List.of(new dev.difme.exchange.rails.hub.HubMirror.Move("rel-auction-9-principal", "escrow", "partner-1", 500, "x")));
        assertTrue(after.cbsMirror().drain(5_000));
        assertEquals(List.of("transfer rel-auction-9-principal escrow>partner-1 500"), hub2.calls);
        assertEquals("BOOKED", journal.get("rel-auction-9-principal"));
        after.cbsMirror().close();
    }

    @Test
    void merchantNamesBecomeValidAccountNames() {
        SimRails rails = new SimRails();
        FakeHub hub = new FakeHub();
        rails.useHub(hub, Map.of(42L, CARD), m -> {});
        var token = rails.credentials.issue(new AgentCredentialPort.Instruction(new UUID(5, 0), 42, "Big Store #7", 10, "INR"), 1_000);
        rails.cardCheckout().authorize(new MerchantCheckoutPort.Authorization("000009", token.token(), "Big Store #7", 10, "INR"), 1_000);
        assertTrue(hub.calls.get(0).contains(" big-store--7 "), hub.calls.get(0));
    }
}
