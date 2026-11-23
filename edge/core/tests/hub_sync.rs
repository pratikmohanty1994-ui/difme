//! Sync against the real QUIC hub (services/hub, unchanged) in front of a fake core: pending offline payments are
//! submitted over `difme/1`, carry EAT evidence and the CRDT delta, and the outcomes land in the wallet.

use difme_edge_core::ml::NoModel;
use difme_edge_core::rules::RuleEngine;
use difme_edge_core::sync::{self, HubClient, HubEndpoint, IntentBoundNonce};
use difme_edge_core::tee::{self, PaymentIntent, SoftwareTee, Tee};
use difme_edge_core::wallet::{HUB, PaymentStatus, Wallet};
use difme_edge_core::{EdgeConfig, EdgeCore};
use difme_quinn_hub::proto::payment_command_service_server::{PaymentCommandService, PaymentCommandServiceServer};
use difme_quinn_hub::proto::{SubmitPaymentRequest, SubmitPaymentResponse, submit_payment_response::Status};
use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};

/// Accepts once per idempotency key, answers DUPLICATE after that, rejects amounts ending in 13 as fraud, and
/// fails (UNAVAILABLE) while `down` is set.
#[derive(Default)]
struct FakeCore {
    seen: Mutex<HashSet<String>>,
    requests: Mutex<Vec<SubmitPaymentRequest>>,
    down: std::sync::atomic::AtomicBool,
}

struct Core(Arc<FakeCore>);

#[tonic::async_trait]
impl PaymentCommandService for Core {
    async fn submit_payment(&self, req: tonic::Request<SubmitPaymentRequest>) -> Result<tonic::Response<SubmitPaymentResponse>, tonic::Status> {
        let this = &self.0;
        if this.down.load(Relaxed) {
            return Err(tonic::Status::unavailable("core down"));
        }
        let r = req.into_inner();
        this.requests.lock().unwrap().push(r.clone());
        let status = if r.amount.as_ref().is_some_and(|m| m.amount_minor % 100 == 13) {
            Status::RejectedFraud
        } else if this.seen.lock().unwrap().insert(r.idempotency_key.clone()) {
            Status::Accepted
        } else {
            Status::Duplicate
        };
        Ok(tonic::Response::new(SubmitPaymentResponse { payment_id: r.idempotency_key, workflow_id: "wf".into(), status: status as i32 }))
    }
}

async fn start_hub(core: Arc<FakeCore>) -> (HubEndpoint, Arc<difme_quinn_hub::State>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(tonic::transport::Server::builder()
        .add_service(PaymentCommandServiceServer::new(Core(core)))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)));
    let state = difme_quinn_hub::State::new(&format!("http://{addr}")).unwrap();
    let server = difme_quinn_hub::bind_quic("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let hub = HubEndpoint { addr: server.endpoint.local_addr().unwrap(), server_name: "localhost".into(), trusted_certs_der: vec![server.cert_der.clone()] };
    tokio::spawn(difme_quinn_hub::serve_quic(server.endpoint, state.clone()));
    (hub, state)
}

fn device(genesis: &[u8], grant: i64) -> (Wallet, SoftwareTee) {
    let mut hub = Wallet::open(genesis, HUB).unwrap();
    hub.grant("dev-1", grant).unwrap();
    let mut w = Wallet::open(genesis, "dev-1").unwrap();
    w.merge(&mut hub).unwrap();
    (w, SoftwareTee::generate("dev-1").unwrap())
}

fn pay(w: &mut Wallet, tee: &SoftwareTee, amount: i64) -> String {
    let intent = PaymentIntent::new("w1", "dev-1", "merchant-7", amount, "INR");
    w.record_payment(&intent, &tee::sign_intent(tee, &intent).unwrap()).unwrap();
    intent.id
}

#[tokio::test]
async fn offline_payments_sync_through_the_hub() {
    let core = Arc::new(FakeCore::default());
    let (hub, hub_state) = start_hub(core.clone()).await;
    let genesis = Wallet::genesis("w1", "INR", 1_000_000);
    let (mut w, tee) = device(&genesis, 200_000);
    let rules = RuleEngine::offline_limit().unwrap();
    let before = Wallet::open(&w.save(), HUB).unwrap().save();

    let ok = pay(&mut w, &tee, 12_000);
    let fraud = pay(&mut w, &tee, 5_013);
    assert_eq!(w.offline_spent("dev-1"), 17_013);

    let client = HubClient::connect(&hub).await.unwrap();
    let report = sync::sync_pending(&mut w, &tee, &rules, &NoModel, &mut IntentBoundNonce, &client).await;
    assert_eq!((report.attempted, report.accepted, report.rejected, report.retry_later), (2, 1, 1, 0), "{report:?}");
    assert_eq!(w.payment(&ok).unwrap().status, PaymentStatus::Accepted);
    assert_eq!(w.payment(&fraud).unwrap().status, PaymentStatus::RejectedFraud);
    assert_eq!(w.offline_spent("dev-1"), 0);
    assert!(w.pending("dev-1").is_empty());

    // What reached the core: idempotency key = payment id, evidence signed by the device key and bound to the
    // intent, and a CRDT delta that rehydrates the payment on a replica holding the earlier state.
    let reqs = core.requests.lock().unwrap().clone();
    let r = reqs.iter().find(|r| r.idempotency_key == ok).unwrap();
    assert_eq!(r.debit_account_id, "w1");
    assert_eq!(r.credit_account_id, "merchant-7");
    assert_eq!(r.amount.as_ref().unwrap().amount_minor, 12_000);
    assert_eq!(r.channel, 1, "CHANNEL_MOBILE");
    assert_eq!(r.trace_id.len(), 32);
    let payload = tee::verify_sign1(&r.attestation_token, &tee.public_key_sec1()).unwrap();
    let intent_b3 = w.payment(&ok).unwrap().intent_b3;
    assert_eq!(tee::claim(&payload, tee::claims::INTENT_B3).unwrap().as_text().unwrap(), intent_b3);
    let mut mirror = Wallet::open(&before, HUB).unwrap();
    mirror.apply(&r.crdt_delta).unwrap();
    assert_eq!(mirror.payment(&ok).unwrap().amount_minor, 12_000);

    // A retried payment (e.g. the answer was lost) is deduplicated by the core.
    let mut req = sync::build_request(&mut w, &tee, &rules, &NoModel, &mut IntentBoundNonce, &ok).unwrap();
    req.trace_id = "retry".into();
    assert_eq!(client.submit(&req).await.unwrap().status(), sync::proto::submit_payment_response::Status::Duplicate);
    client.close().await;
    assert_eq!(hub_state.metrics.accepted_total.load(Relaxed), 1);
    assert_eq!(hub_state.metrics.duplicate_total.load(Relaxed), 1);
    assert_eq!(hub_state.metrics.rejected_total.load(Relaxed), 1);
}

#[tokio::test]
async fn core_outage_keeps_payments_pending_until_the_next_sync() {
    let core = Arc::new(FakeCore::default());
    let (hub, _) = start_hub(core.clone()).await;
    let (mut w, tee) = device(&Wallet::genesis("w1", "INR", 1_000_000), 100_000);
    let rules = RuleEngine::offline_limit().unwrap();
    let id = pay(&mut w, &tee, 3_000);

    core.down.store(true, Relaxed);
    let client = HubClient::connect(&hub).await.unwrap();
    let report = sync::sync_pending(&mut w, &tee, &rules, &NoModel, &mut IntentBoundNonce, &client).await;
    assert_eq!((report.attempted, report.retry_later), (1, 1), "{report:?}");
    assert!(report.last_error.unwrap().contains("unavailable"));
    assert_eq!(w.payment(&id).unwrap().status, PaymentStatus::Pending);

    core.down.store(false, Relaxed);
    let report = sync::sync_pending(&mut w, &tee, &rules, &NoModel, &mut IntentBoundNonce, &client).await;
    assert_eq!(report.accepted, 1, "{report:?}");
    assert_eq!(w.payment(&id).unwrap().status, PaymentStatus::Accepted);
    client.close().await;
}

#[tokio::test]
async fn edge_core_end_to_end_with_persistence() {
    let core = Arc::new(FakeCore::default());
    let (hub, _) = start_hub(core.clone()).await;
    let dir = std::env::temp_dir().join(format!("difme-edge-test-{}", uuid_like()));
    let cfg = EdgeConfig { data_dir: Some(dir.clone()), hub: Some(hub), ..Default::default() };

    let mut edge = EdgeCore::open(cfg.clone()).unwrap();
    let s = edge.status();
    assert_eq!((s.ledger_balance, s.rights_available), (difme_edge_core::DEMO_BALANCE, difme_edge_core::DEMO_GRANT));
    let p = edge.pay_offline("merchant-1", 25_000).unwrap();
    assert!(matches!(edge.pay_offline("merchant-1", 60_000), Err(difme_edge_core::Error::RuleDenied(_))));
    let att = edge.attestation().unwrap();
    assert!(att.self_check);
    assert_eq!(att.security_level, "SOFTWARE");

    // Simulated NFC tap returns the armed signed intent.
    let select = [&[0x00, 0xA4, 0x04, 0x00, 7][..], difme_edge_core::hce::AID, &[0]].concat();
    assert_eq!(edge.hce_apdu(&select), vec![0x90, 0x00]);
    let resp = edge.hce_apdu(&[0x80, 0xCA, 0x00, 0x01, 0x00]);
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00]);
    tee::verify_sign1(&resp[..resp.len() - 2], &edge.tee().public_key_sec1()).unwrap();
    let key = edge.tee().public_key_sec1();
    drop(edge);

    // Restart: same key, same pending payment.
    let mut edge = EdgeCore::open(cfg).unwrap();
    assert_eq!(edge.tee().public_key_sec1(), key);
    assert_eq!(edge.status().pending_count, 1);
    let report = edge.sync().await.unwrap();
    assert_eq!(report.accepted, 1, "{report:?}");
    assert_eq!(edge.wallet().payment(&p.id).unwrap().status, PaymentStatus::Accepted);
    assert_eq!(edge.status().last_sync.unwrap().accepted, 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sync_without_a_hub_reports_instead_of_failing() {
    let mut edge = EdgeCore::open(EdgeConfig::default()).unwrap();
    edge.pay_offline("m", 100).unwrap();
    let r = edge.sync().await.unwrap();
    assert_eq!(r.attempted, 0);
    assert!(r.last_error.unwrap().contains("no hub configured"));
    assert_eq!(edge.status().pending_count, 1);
}

fn uuid_like() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    difme_edge_core::integrity::hex(&b)
}
