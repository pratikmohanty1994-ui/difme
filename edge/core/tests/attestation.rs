//! The simulated TEE's evidence, appraised by the real verifier (services/attestation, unchanged).

use difme_attestation_verifier::proto::VerifyRequest;
use difme_attestation_verifier::{Policy, Verifier};
use difme_edge_core::rules::RuleEngine;
use difme_edge_core::tee::{self, Evidence, PaymentIntent, SecurityLevel, SoftwareTee, Tee, claims};
use p256::ecdsa::VerifyingKey;
use std::collections::{HashMap, HashSet};

const NOW: i64 = 1_800_000_000_000;

fn verifier(tee: &dyn Tee, approved_wasm: &str) -> Verifier {
    let mut device_keys = HashMap::new();
    device_keys.insert(tee.device_id().to_string(), VerifyingKey::from_sec1_bytes(&tee.public_key_sec1()).unwrap());
    Verifier::new(Policy { device_keys, approved_wasm: HashSet::from([approved_wasm.to_string()]), revoked: HashSet::new() })
}

#[test]
fn eat_from_the_software_tee_is_trusted_by_the_verifier() {
    let tee = SoftwareTee::generate("dev-emu-1").unwrap();
    let rule = RuleEngine::offline_limit().unwrap();
    let v = verifier(&tee, rule.sha256());
    let intent = PaymentIntent::new("w1", "dev-emu-1", "shop", 1_000, "INR");

    let (nonce, _) = v.challenge("dev-emu-1", NOW);
    let token = tee::attest(&tee, &Evidence { nonce: &nonce, rule_sha256: rule.sha256(), intent_b3: Some(&intent.digest_hex()) }).unwrap();
    let r = v.verify(&VerifyRequest { device_id: "dev-emu-1".into(), eat_token: token.clone(), nonce: nonce.clone(), fraud_score: 0.0, wasm_module_sha256: rule.sha256().into() }, NOW + 1);
    assert!(r.trusted, "{:?}", r.failed_checks);
    assert!(!r.fallback_server_check);

    // The claims the device put in are readable and bound to this payment and rule.
    let payload = tee::verify_sign1(&token, &tee.public_key_sec1()).unwrap();
    assert_eq!(tee::claim(&payload, claims::NONCE).unwrap().as_bytes().unwrap(), &nonce);
    assert_eq!(tee::claim(&payload, claims::INTENT_B3).unwrap().as_text().unwrap(), intent.digest_hex());
    assert_eq!(tee::claim(&payload, claims::RULE_SHA256).unwrap().as_text().unwrap(), rule.sha256());
    assert_eq!(tee::claim(&payload, claims::SECURITY_LEVEL).unwrap().as_text().unwrap(), "SOFTWARE");
    assert_eq!(tee::claim(&payload, claims::EAT_PROFILE).unwrap().as_text().unwrap(), tee::EAT_PROFILE);
    assert_eq!(tee.security_level(), SecurityLevel::Software);
}

#[test]
fn the_verifier_rejects_what_it_should() {
    let tee = SoftwareTee::generate("dev-emu-2").unwrap();
    let other = SoftwareTee::generate("dev-emu-2").unwrap();
    let rule = RuleEngine::offline_limit().unwrap();
    let v = verifier(&tee, rule.sha256());
    let req = |token: Vec<u8>, nonce: &[u8], wasm: &str| VerifyRequest {
        device_id: "dev-emu-2".into(), eat_token: token, nonce: nonce.to_vec(), fraud_score: 0.0, wasm_module_sha256: wasm.into(),
    };

    // A different key (e.g. a cloned app on another device) fails the signature check.
    let (n, _) = v.challenge("dev-emu-2", NOW);
    let t = tee::attest(&other, &Evidence { nonce: &n, rule_sha256: rule.sha256(), intent_b3: None }).unwrap();
    assert_eq!(v.verify(&req(t, &n, rule.sha256()), NOW).failed_checks, vec!["signature"]);

    // A flipped byte in the token fails the signature check.
    let (n, _) = v.challenge("dev-emu-2", NOW);
    let mut t = tee::attest(&tee, &Evidence { nonce: &n, rule_sha256: rule.sha256(), intent_b3: None }).unwrap();
    let mid = t.len() / 2;
    t[mid] ^= 1;
    assert_eq!(v.verify(&req(t, &n, rule.sha256()), NOW).failed_checks, vec!["signature"]);

    // A self-chosen nonce (what the device uses while the hub cannot relay challenges) fails freshness only.
    let intent = PaymentIntent::new("w1", "dev-emu-2", "shop", 1_000, "INR");
    let self_nonce = difme_edge_core::integrity::unhex(&intent.digest_hex()).unwrap();
    let t = tee::attest(&tee, &Evidence { nonce: &self_nonce, rule_sha256: rule.sha256(), intent_b3: Some(&intent.digest_hex()) }).unwrap();
    let r = v.verify(&req(t, &self_nonce, rule.sha256()), NOW);
    assert_eq!(r.failed_checks, vec!["freshness"]);
    assert!(r.fallback_server_check);

    // An unapproved rule build fails binary_hash.
    let (n, _) = v.challenge("dev-emu-2", NOW);
    let t = tee::attest(&tee, &Evidence { nonce: &n, rule_sha256: rule.sha256(), intent_b3: None }).unwrap();
    assert_eq!(v.verify(&req(t, &n, &"0".repeat(64)), NOW).failed_checks, vec!["binary_hash"]);
}

#[test]
fn signed_intents_verify_and_the_key_store_survives_a_restart() {
    let tee = SoftwareTee::generate("dev-emu-3").unwrap();
    let intent = PaymentIntent::new("w1", "dev-emu-3", "shop", 42_00, "INR");
    let cose = tee::sign_intent(&tee, &intent).unwrap();
    assert_eq!(tee::verify_sign1(&cose, &tee.public_key_sec1()).unwrap(), intent.canonical());

    let restored = SoftwareTee::import_sealed(&tee.export_sealed()).unwrap();
    assert_eq!(restored.device_id(), "dev-emu-3");
    assert_eq!(restored.public_key_sec1(), tee.public_key_sec1());
    let mut blob = tee.export_sealed();
    blob[45] ^= 1;
    assert!(SoftwareTee::import_sealed(&blob).is_err());
    assert!(tee::verify_sign1(&cose, &SoftwareTee::generate("x").unwrap().public_key_sec1()).is_err());
}
