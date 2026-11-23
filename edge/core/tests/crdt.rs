//! Escrow CRDT on automerge: merge laws, the no-overspend invariant under partition, and status conflicts.

use difme_edge_core::Error;
use difme_edge_core::tee::{PaymentIntent, SoftwareTee, sign_intent};
use difme_edge_core::wallet::{HUB, PaymentStatus, Wallet};

const LIMIT: i64 = 300_000;

fn genesis() -> Vec<u8> {
    Wallet::genesis("w1", "INR", LIMIT)
}

fn pay(w: &mut Wallet, payee: &str, amount: i64) -> Result<String, Error> {
    let tee = SoftwareTee::from_seed(w.replica(), [7; 32]).unwrap();
    let intent = PaymentIntent::new("w1", w.replica(), payee, amount, "INR");
    let cose = sign_intent(&tee, &intent).unwrap();
    w.record_payment(&intent, &cose).map(|_| intent.id)
}

#[test]
fn genesis_is_deterministic_so_replicas_share_one_document() {
    assert_eq!(genesis(), genesis());
    let mut a = Wallet::open(&genesis(), "a").unwrap();
    let mut b = Wallet::open(&genesis(), "b").unwrap();
    assert_eq!(a.heads(), b.heads());
    assert_eq!(a.limit(), LIMIT);
    assert_eq!(a.rights(HUB), LIMIT);
    assert_eq!(a.rights("a"), 0);
}

#[test]
fn partitioned_devices_never_overspend_and_converge() {
    let mut hub = Wallet::open(&genesis(), HUB).unwrap();
    hub.grant("a", 150_000).unwrap();
    hub.grant("b", 150_000).unwrap();
    assert!(matches!(hub.grant("c", 1), Err(Error::InsufficientRights { .. })), "hub has granted its whole limit");

    let mut a = Wallet::open(&genesis(), "a").unwrap();
    let mut b = Wallet::open(&genesis(), "b").unwrap();
    a.merge(&mut hub).unwrap();
    b.merge(&mut hub).unwrap();

    // Partition: both spend offline, concurrently, against their own rights only.
    for _ in 0..3 { pay(&mut a, "shop", 50_000).unwrap(); }
    assert!(matches!(pay(&mut a, "shop", 1), Err(Error::InsufficientRights { held: 0, .. })));
    pay(&mut b, "cafe", 100_000).unwrap();
    // b passes some of its remaining rights to a while partitioned from the hub.
    b.grant("a", 30_000).unwrap();
    assert!(b.rights("b") == 20_000);

    // Heal in different orders; re-deliveries are harmless (idempotent).
    let mut a2 = Wallet::open(&a.save(), "a").unwrap();
    hub.merge(&mut a).unwrap();
    hub.merge(&mut b).unwrap();
    hub.merge(&mut a2).unwrap();
    b.merge(&mut a2).unwrap();
    a.merge(&mut b).unwrap();
    a.merge(&mut hub).unwrap();
    b.merge(&mut hub).unwrap();

    for w in [&mut hub, &mut a, &mut b] {
        assert_eq!(w.total_spent(), 250_000);
        assert!(w.total_spent() <= LIMIT, "NoOverspend");
        assert_eq!(w.rights("a"), 30_000);
        assert_eq!(w.rights("b"), 20_000);
        assert_eq!(w.rights(HUB), 0);
        assert_eq!(w.payments().len(), 4);
    }
    assert_eq!(hub.heads(), a.heads());
    assert_eq!(a.heads(), b.heads());
    // With the transferred rights, a can spend again.
    pay(&mut a, "shop", 30_000).unwrap();
}

#[test]
fn merge_is_commutative_associative_and_idempotent() {
    let mut hub = Wallet::open(&genesis(), HUB).unwrap();
    hub.grant("a", 100_000).unwrap();
    hub.grant("b", 100_000).unwrap();
    let mut a = Wallet::open(&hub.save(), "a").unwrap();
    let mut b = Wallet::open(&hub.save(), "b").unwrap();
    pay(&mut a, "x", 10_000).unwrap();
    pay(&mut b, "y", 20_000).unwrap();
    hub.set_ledger_balance(5).unwrap();

    let view = |w: &Wallet| (w.total_spent(), w.rights("a"), w.rights("b"), w.ledger_balance(), w.payments().len());
    let fresh = |w: &mut Wallet, r: &str| Wallet::open(&w.save(), r).unwrap();

    // (a ⊔ b) ⊔ hub
    let mut l = fresh(&mut a, "a");
    l.merge(&mut fresh(&mut b, "b")).unwrap();
    l.merge(&mut fresh(&mut hub, HUB)).unwrap();
    // hub ⊔ (b ⊔ a)
    let mut r = fresh(&mut b, "b");
    r.merge(&mut fresh(&mut a, "a")).unwrap();
    let mut r2 = fresh(&mut hub, HUB);
    r2.merge(&mut r).unwrap();
    assert_eq!(view(&l), view(&r2));
    assert_eq!(view(&l), (30_000, 90_000, 80_000, 5, 2));
    // x ⊔ x = x
    let before = view(&l);
    let mut copy = fresh(&mut l, "a");
    l.merge(&mut copy).unwrap();
    assert_eq!(view(&l), before);
}

#[test]
fn concurrent_status_writes_conflict_and_resolve_deterministically() {
    let mut hub = Wallet::open(&genesis(), HUB).unwrap();
    hub.grant("a", 100_000).unwrap();
    let mut a = Wallet::open(&hub.save(), "a").unwrap();
    let id = pay(&mut a, "shop", 10_000).unwrap();
    let mut mirror = Wallet::open(&a.save(), HUB).unwrap();

    // The device times out and marks it rate-limited; the hub mirror concurrently records acceptance.
    a.set_status(&id, PaymentStatus::RejectedRateLimit).unwrap();
    mirror.set_status(&id, PaymentStatus::Accepted).unwrap();
    let mut m2 = Wallet::open(&mirror.save(), HUB).unwrap();
    a.merge(&mut mirror).unwrap();
    m2.merge(&mut Wallet::open(&a.save(), "a").unwrap()).unwrap();

    for w in [&a, &m2] {
        let p = w.payment(&id).unwrap();
        assert!(p.status_conflict, "both writes survive in the CRDT");
        assert_eq!(p.status, PaymentStatus::Accepted, "settled beats rejected on every replica");
    }
    assert_eq!(a.offline_spent("a"), 0, "no longer pending");
    // A later write after seeing both resolves the conflict.
    a.set_status(&id, PaymentStatus::Accepted).unwrap();
    assert!(!a.payment(&id).unwrap().status_conflict);
}

#[test]
fn guards_on_who_writes_what() {
    let mut a = Wallet::open(&genesis(), "a").unwrap();
    assert!(a.set_ledger_balance(1).is_err(), "only the hub sets the balance");
    assert!(a.grant("b", 1).is_err(), "no rights to grant");
    let tee = SoftwareTee::from_seed("b", [1; 32]).unwrap();
    let foreign = PaymentIntent::new("w1", "b", "x", 1, "INR");
    assert!(a.record_payment(&foreign, &sign_intent(&tee, &foreign).unwrap()).is_err(), "only own payments");
    let usd = PaymentIntent::new("w1", "a", "x", 1, "USD");
    assert!(a.record_payment(&usd, b"").is_err());
}

#[test]
fn sealed_storage_and_sync_protocol() {
    let mut hub = Wallet::open(&genesis(), HUB).unwrap();
    hub.grant("a", 50_000).unwrap();
    let mut a = Wallet::open(&genesis(), "a").unwrap();
    let rounds = a.sync_with(&mut hub).unwrap();
    assert!(rounds >= 1);
    assert_eq!(a.rights("a"), 50_000);
    let id = pay(&mut a, "shop", 5_000).unwrap();
    let base = Wallet::open(&hub.save(), HUB).unwrap().save();

    // The delta sent with the payment applies on a replica that has the state before it.
    let delta = a.delta_for(&id);
    assert!(!delta.is_empty());
    let mut rehydrated = Wallet::open(&base, HUB).unwrap();
    rehydrated.apply(&delta).unwrap();
    assert_eq!(rehydrated.payment(&id).unwrap().amount_minor, 5_000);
    assert_eq!(rehydrated.spent("a"), 5_000);

    let mut blob = a.save_sealed();
    let reopened = Wallet::open_sealed(&blob, "a").unwrap();
    assert_eq!(reopened.offline_spent("a"), 5_000);
    let n = blob.len();
    blob[n - 3] ^= 0x40;
    assert!(matches!(Wallet::open_sealed(&blob, "a"), Err(Error::Integrity(_))));
}
