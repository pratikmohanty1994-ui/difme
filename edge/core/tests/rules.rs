//! The offline-limit rule runs as a WASI Preview 2 component on Wasmtime.

use difme_edge_core::Error;
use difme_edge_core::rules::{OFFLINE_LIMIT_B3, OFFLINE_LIMIT_WASM, RuleDecision, RuleEngine, RuleInput};

fn input(amount: i64, spent: i64, rights: i64) -> RuleInput {
    RuleInput { amount_minor: amount, currency: "INR".into(), offline_spent: spent, rights_available: rights }
}

fn denied(d: RuleDecision, needle: &str) {
    match d {
        RuleDecision::Deny(reason) => assert!(reason.contains(needle), "{reason}"),
        RuleDecision::Allow => panic!("expected a denial containing {needle:?}"),
    }
}

#[test]
fn offline_limits_are_enforced_by_the_component() {
    let rule = RuleEngine::offline_limit().unwrap();
    assert!(rule.description().starts_with("offline-limit/0.1.0 per-payment=50000 cumulative=200000"), "{}", rule.description());
    assert_eq!(rule.sha256().len(), 64);
    assert_eq!(rule.check(&input(50_000, 150_000, 200_000)).unwrap(), RuleDecision::Allow);
    denied(rule.check(&input(50_001, 0, 200_000)).unwrap(), "per-payment");
    denied(rule.check(&input(10_000, 195_000, 200_000)).unwrap(), "cumulative");
    denied(rule.check(&input(10_000, i64::MAX, 200_000)).unwrap(), "cumulative");
    denied(rule.check(&input(10_000, 0, 9_999)).unwrap(), "escrow rights");
    denied(rule.check(&input(0, 0, 9_999)).unwrap(), "positive");
    let mut usd = input(100, 0, 1_000);
    usd.currency = "USD".into();
    denied(rule.check(&usd).unwrap(), "INR only");
}

#[test]
fn each_check_gets_a_fresh_sandbox() {
    let rule = RuleEngine::offline_limit().unwrap();
    for _ in 0..50 {
        assert_eq!(rule.check(&input(100, 0, 1_000)).unwrap(), RuleDecision::Allow);
    }
}

#[test]
fn a_component_that_does_not_match_its_pin_is_refused() {
    let mut tampered = OFFLINE_LIMIT_WASM.to_vec();
    let n = tampered.len();
    tampered[n - 1] ^= 1;
    assert!(matches!(RuleEngine::load(&tampered, OFFLINE_LIMIT_B3.trim()), Err(Error::Integrity(_))));
    assert!(matches!(RuleEngine::load(b"\0asm\x01\0\0\0", &difme_edge_core::integrity::hex_digest(b"\0asm\x01\0\0\0")), Err(Error::Rule(_))),
        "a core module is not a component");
}
