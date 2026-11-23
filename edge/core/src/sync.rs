//! Sync with the QUIC hub (services/hub) over its existing protocol, unchanged: ALPN `difme/1`, one payment per
//! bidirectional stream, a 4-byte big-endian length followed by a protobuf `SubmitPaymentRequest`
//! (api/proto/difme/payments/v1/payments.proto), answered on the same stream with a length-prefixed
//! `SubmitPaymentResponse`. A stream reset with code 1 means the core was unavailable: the payment stays pending
//! and the next sync retries it under the same idempotency key (the payment id), which the core deduplicates.
//!
//! Each request carries the EAT for that payment (`attestation_token`), the automerge changes that recorded it
//! (`crdt_delta`) and the on-device fraud score. Pulling state down (grants, balance) needs the hub extension
//! described in edge/README.md; `Wallet::sync_with` is the exchange it would carry.

use crate::rules::RuleEngine;
use crate::tee::{self, Evidence, Tee};
use crate::wallet::{PaymentStatus, Wallet};
use crate::{Error, ml::FraudModel};
use prost::Message;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/difme.payments.v1.rs"));
}

use proto::{Channel, Money, SubmitPaymentRequest, SubmitPaymentResponse, submit_payment_response::Status};

pub const ALPN: &[u8] = b"difme/1";
/// Same bound as the hub's.
pub const MAX_FRAME: usize = 64 * 1024;
/// Hub reset code: the core was unavailable.
pub const RESET_CORE_UNAVAILABLE: u32 = 1;

/// Where the hub is and the certificate (or CA) to trust for it. Production pins the SPIFFE trust bundle.
#[derive(Clone, Debug)]
pub struct HubEndpoint {
    pub addr: SocketAddr,
    pub server_name: String,
    pub trusted_certs_der: Vec<Vec<u8>>,
}

pub struct HubClient {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl HubClient {
    pub async fn connect(hub: &HubEndpoint) -> Result<Self, Error> {
        let mut roots = rustls::RootCertStore::empty();
        for der in &hub.trusted_certs_der {
            roots.add(rustls::pki_types::CertificateDer::from(der.clone())).map_err(|e| Error::Sync(format!("bad hub certificate: {e}")))?;
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Error::Sync(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| Error::Sync(e.to_string()))?;
        let bind: SocketAddr = if hub.addr.is_ipv6() { "[::]:0".parse().expect("addr") } else { "0.0.0.0:0".parse().expect("addr") };
        let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| Error::Sync(e.to_string()))?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint.connect(hub.addr, &hub.server_name).map_err(|e| Error::Sync(e.to_string()))?;
        let conn = tokio::time::timeout(std::time::Duration::from_secs(5), connecting)
            .await
            .map_err(|_| Error::Sync("hub connect timed out".into()))?
            .map_err(|e| Error::Sync(format!("hub connect: {e}")))?;
        Ok(HubClient { endpoint, conn })
    }

    /// One payment, one stream.
    pub async fn submit(&self, req: &SubmitPaymentRequest) -> Result<SubmitPaymentResponse, Error> {
        let body = req.encode_to_vec();
        if body.len() > MAX_FRAME {
            return Err(Error::Sync(format!("request of {} bytes exceeds the hub frame limit", body.len())));
        }
        let (mut send, mut recv) = self.conn.open_bi().await.map_err(|e| Error::Sync(e.to_string()))?;
        send.write_all(&(body.len() as u32).to_be_bytes()).await.map_err(|e| Error::Sync(e.to_string()))?;
        send.write_all(&body).await.map_err(|e| Error::Sync(e.to_string()))?;
        send.finish().map_err(|e| Error::Sync(e.to_string()))?;
        let mut len = [0u8; 4];
        match recv.read_exact(&mut len).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))) if code.into_inner() == RESET_CORE_UNAVAILABLE as u64 => {
                return Err(Error::HubUnavailable);
            }
            Err(e) => return Err(Error::Sync(e.to_string())),
        }
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(Error::Sync(format!("hub frame of {n} bytes exceeds {MAX_FRAME}")));
        }
        let mut buf = vec![0u8; n];
        recv.read_exact(&mut buf).await.map_err(|e| Error::Sync(e.to_string()))?;
        SubmitPaymentResponse::decode(buf.as_slice()).map_err(|e| Error::Sync(e.to_string()))
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        self.endpoint.wait_idle().await;
    }
}

/// Supplies the verifier's nonce for each payment's evidence.
pub trait NonceSource: Send {
    fn nonce(&mut self, device_id: &str, intent_b3: &str) -> Vec<u8>;
}

/// Used until the hub relays `AttestationVerifierService.Challenge` to devices (see edge/README.md): the nonce is
/// the intent digest, which binds the evidence to the payment but was not issued by the verifier, so the verifier
/// fails `freshness` and the payment takes the full server-side fraud check (its documented FAIL path).
pub struct IntentBoundNonce;

impl NonceSource for IntentBoundNonce {
    fn nonce(&mut self, _device_id: &str, intent_b3: &str) -> Vec<u8> {
        crate::integrity::unhex(intent_b3).unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub attempted: u32,
    pub accepted: u32,
    pub duplicate: u32,
    pub rejected: u32,
    /// Left pending for the next sync (hub or core unavailable).
    pub retry_later: u32,
    pub last_error: Option<String>,
    pub finished_ms: i64,
}

fn random_trace_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::fill(&mut b);
    crate::integrity::hex(&b)
}

/// Builds the hub request for one pending payment.
pub fn build_request(
    wallet: &mut Wallet,
    tee: &dyn Tee,
    rules: &RuleEngine,
    fraud: &dyn FraudModel,
    nonces: &mut dyn NonceSource,
    id: &str,
) -> Result<SubmitPaymentRequest, Error> {
    let p = wallet.payment(id).ok_or_else(|| Error::Wallet(format!("no payment {id}")))?;
    let nonce = nonces.nonce(tee.device_id(), &p.intent_b3);
    let token = tee::attest(tee, &Evidence { nonce: &nonce, rule_sha256: rules.sha256(), intent_b3: Some(&p.intent_b3) })?;
    let score = fraud.score(&crate::ml::Features { amount_minor: p.amount_minor, offline_spent: wallet.offline_spent(&p.payer), created_ms: p.created_ms });
    Ok(SubmitPaymentRequest {
        idempotency_key: p.id.clone(),
        trace_id: random_trace_id(),
        debit_account_id: wallet.wallet_id(),
        credit_account_id: p.payee.clone(),
        amount: Some(Money { amount_minor: p.amount_minor, currency: p.currency.clone() }),
        channel: Channel::Mobile as i32,
        edge_fraud_score: score as f64,
        attestation_token: token,
        crdt_delta: wallet.delta_for(id),
        target_bank: String::new(),
        client_timestamp_ms: p.created_ms,
    })
}

/// Submits every payment this device signed offline and records the hub's answers in the CRDT.
pub async fn sync_pending(
    wallet: &mut Wallet,
    tee: &dyn Tee,
    rules: &RuleEngine,
    fraud: &dyn FraudModel,
    nonces: &mut dyn NonceSource,
    hub: &HubClient,
) -> SyncReport {
    let mut report = SyncReport::default();
    let ids: Vec<String> = wallet.pending(tee.device_id()).into_iter().map(|p| p.id).collect();
    for id in ids {
        report.attempted += 1;
        let outcome = match build_request(wallet, tee, rules, fraud, nonces, &id) {
            Ok(req) => hub.submit(&req).await,
            Err(e) => Err(e),
        };
        match outcome {
            Ok(resp) => {
                let status = match resp.status() {
                    Status::Accepted => { report.accepted += 1; PaymentStatus::Accepted }
                    Status::Duplicate => { report.duplicate += 1; PaymentStatus::Duplicate }
                    Status::RejectedFraud => { report.rejected += 1; PaymentStatus::RejectedFraud }
                    Status::RejectedRateLimit => { report.rejected += 1; PaymentStatus::RejectedRateLimit }
                    Status::Unspecified => { report.retry_later += 1; continue; }
                };
                if let Err(e) = wallet.set_status(&id, status) {
                    report.last_error = Some(e.to_string());
                }
            }
            Err(e) => {
                report.retry_later += 1;
                report.last_error = Some(e.to_string());
                // A dead connection fails every remaining stream; stop and keep them pending.
                if !matches!(e, Error::HubUnavailable) && hub.conn.close_reason().is_some() {
                    break;
                }
            }
        }
    }
    report.finished_ms = crate::wallet::now_ms();
    report
}
