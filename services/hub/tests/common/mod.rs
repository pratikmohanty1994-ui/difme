//! Shared test fixtures: a scriptable fake core and a QUIC client that pins the server's certificate.
#![allow(dead_code)]

use difme_quinn_hub::proto::payment_command_service_server::{PaymentCommandService, PaymentCommandServiceServer};
use difme_quinn_hub::proto::{submit_payment_response::Status, Money, SubmitPaymentRequest, SubmitPaymentResponse};
use difme_quinn_hub::ALPN;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fails the first `fail_first` calls with UNAVAILABLE, sleeps `delay` per call, records metadata it saw.
#[derive(Default)]
pub struct FakeCore {
    pub calls: AtomicU32,
    pub fail_first: u32,
    pub delay: Duration,
    pub traceparents: Mutex<Vec<String>>,
}

pub struct Shared(pub Arc<FakeCore>);

#[tonic::async_trait]
impl PaymentCommandService for Shared {
    async fn submit_payment(&self, req: tonic::Request<SubmitPaymentRequest>) -> Result<tonic::Response<SubmitPaymentResponse>, tonic::Status> {
        let n = self.0.calls.fetch_add(1, SeqCst) + 1;
        if let Some(tp) = req.metadata().get("traceparent") {
            self.0.traceparents.lock().unwrap().push(tp.to_str().unwrap().to_string());
        }
        if n <= self.0.fail_first {
            return Err(tonic::Status::unavailable("core starting"));
        }
        tokio::time::sleep(self.0.delay).await;
        let r = req.into_inner();
        let status = if r.idempotency_key.ends_with("dup") { Status::Duplicate } else { Status::Accepted };
        Ok(tonic::Response::new(SubmitPaymentResponse { payment_id: r.idempotency_key, workflow_id: format!("wf-{n}"), status: status as i32 }))
    }
}

pub async fn start_core(core: Arc<FakeCore>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PaymentCommandServiceServer::new(Shared(core)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    format!("http://{addr}")
}

/// A port nothing listens on.
pub async fn dead_core() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    format!("http://{addr}")
}

pub fn client(cert_der: &[u8]) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(cert_der.to_vec())).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap())));
    ep
}

pub fn payment(key: &str) -> SubmitPaymentRequest {
    SubmitPaymentRequest {
        idempotency_key: key.into(),
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        debit_account_id: "a".into(),
        credit_account_id: "b".into(),
        amount: Some(Money { amount_minor: 12_345, currency: "INR".into() }),
        ..Default::default()
    }
}

/// One payment on its own stream; the decoded answer or the stream error.
pub async fn submit(conn: &quinn::Connection, key: &str) -> Result<SubmitPaymentResponse, String> {
    use prost::Message;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    difme_quinn_hub::write_frame(&mut send, &payment(key).encode_to_vec()).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let body = difme_quinn_hub::read_frame(&mut recv).await.map_err(|e| e.to_string())?;
    SubmitPaymentResponse::decode(body.as_slice()).map_err(|e| e.to_string())
}

/// Sends telemetry frames on one unidirectional stream.
pub async fn send_telemetry(conn: &quinn::Connection, frames: &[&[u8]]) {
    let mut send = conn.open_uni().await.unwrap();
    for f in frames {
        send.write_all(&(f.len() as u32).to_be_bytes()).await.unwrap();
        send.write_all(f).await.unwrap();
    }
    send.finish().unwrap();
    let _ = send.stopped().await;
}

/// Polls `cond` for up to two seconds.
pub async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}
