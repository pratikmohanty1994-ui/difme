//! Scenario D chain on loopback: device → relay → hub → fake core.

use difme_quic_relay::{Relay, Upstream, ALPN, CLOSE_UPSTREAM_UNAVAILABLE};
use difme_quinn_hub::proto::payment_command_service_server::{PaymentCommandService, PaymentCommandServiceServer};
use difme_quinn_hub::proto::{submit_payment_response::Status, SubmitPaymentRequest, SubmitPaymentResponse};
use difme_quinn_hub::{bind_quic, read_frame, serve_quic, write_frame, State};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

struct FakeCore;

#[tonic::async_trait]
impl PaymentCommandService for FakeCore {
    async fn submit_payment(&self, req: tonic::Request<SubmitPaymentRequest>) -> Result<tonic::Response<SubmitPaymentResponse>, tonic::Status> {
        let r = req.into_inner();
        Ok(tonic::Response::new(SubmitPaymentResponse { payment_id: r.idempotency_key, workflow_id: "wf".into(), status: Status::Accepted as i32 }))
    }
}

async fn core_url(up: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    if up {
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(PaymentCommandServiceServer::new(FakeCore))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
    }
    format!("http://{addr}")
}

/// Hub on loopback; its address and certificate.
async fn hub(core_up: bool) -> (Arc<State>, SocketAddr, Vec<u8>) {
    let state = State::new(&core_url(core_up).await).unwrap();
    let server = bind_quic("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    tokio::spawn(serve_quic(server.endpoint, state.clone()));
    (state, addr, server.cert_der)
}

fn roots(cert: &[u8]) -> rustls::RootCertStore {
    let mut r = rustls::RootCertStore::empty();
    r.add(rustls::pki_types::CertificateDer::from(cert.to_vec())).unwrap();
    r
}

fn relay(hub_addr: SocketAddr, hub_cert: &[u8]) -> Arc<Relay> {
    // The hub's dev certificate names "quinn-hub" and "localhost".
    let upstream = Upstream { address: hub_addr.to_string(), server_name: "quinn-hub".into(), roots: roots(hub_cert), connect_timeout: Duration::from_secs(2) };
    let r = Arc::new(Relay::bind("127.0.0.1:0".parse().unwrap(), None, upstream).unwrap());
    tokio::spawn(r.clone().serve());
    r
}

async fn device(relay: &Relay) -> quinn::Connection {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots(&relay.cert_der))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap())));
    ep.connect(relay.endpoint.local_addr().unwrap(), "localhost").unwrap().await.unwrap()
}

async fn submit(conn: &quinn::Connection, key: &str) -> Result<SubmitPaymentResponse, String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let req = SubmitPaymentRequest { idempotency_key: key.into(), ..Default::default() };
    write_frame(&mut send, &req.encode_to_vec()).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let body = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
    SubmitPaymentResponse::decode(body.as_slice()).map_err(|e| e.to_string())
}

async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn payments_and_telemetry_cross_the_relay() {
    let (state, hub_addr, hub_cert) = hub(true).await;
    let relay = relay(hub_addr, &hub_cert);
    let conn = device(&relay).await;
    for key in ["0190f3c0-0000-7000-8000-000000000001", "0190f3c0-0000-7000-8000-000000000002"] {
        let r = submit(&conn, key).await.unwrap();
        assert_eq!((r.payment_id.as_str(), r.status()), (key, Status::Accepted));
    }
    // Telemetry: one unidirectional stream, passed through unchanged.
    let mut uni = conn.open_uni().await.unwrap();
    let rec = br#"{"battery":77}"#;
    uni.write_all(&(rec.len() as u32).to_be_bytes()).await.unwrap();
    uni.write_all(rec).await.unwrap();
    uni.finish().unwrap();
    assert!(eventually(|| state.telemetry.stats.received_total.load(Relaxed) == 1).await);

    assert_eq!(state.metrics.accepted_total.load(Relaxed), 2);
    assert_eq!(state.sessions.active(), 1, "one upstream session for the device");
    assert_eq!(relay.metrics.streams_total.load(Relaxed), 3);
    assert!(relay.metrics.bytes_up_total.load(Relaxed) > 0 && relay.metrics.bytes_down_total.load(Relaxed) > 0);

    // The device leaving ends its hub session too.
    conn.close(0u32.into(), b"done");
    assert!(eventually(|| state.sessions.active() == 0).await);
    assert!(eventually(|| relay.metrics.connections_open.load(Relaxed) == 0).await);
}

#[tokio::test]
async fn the_hubs_core_unavailable_reset_reaches_the_device() {
    let (_state, hub_addr, hub_cert) = hub(false).await;
    let relay = relay(hub_addr, &hub_cert);
    let conn = device(&relay).await;
    let e = submit(&conn, "k").await.unwrap_err();
    assert!(e.contains("reset by peer: error 1"), "same code as a direct connection: {e}");
    assert!(relay.metrics.stream_resets_total.load(Relaxed) >= 1);
}

#[tokio::test]
async fn an_unreachable_hub_closes_the_device_connection() {
    let (_state, _hub_addr, hub_cert) = hub(true).await;
    // Nothing listens on this UDP port.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let upstream = Upstream { address: dead.to_string(), server_name: "quinn-hub".into(), roots: roots(&hub_cert), connect_timeout: Duration::from_millis(300) };
    let r = Arc::new(Relay::bind("127.0.0.1:0".parse().unwrap(), None, upstream).unwrap());
    tokio::spawn(r.clone().serve());
    let conn = device(&r).await;
    match conn.closed().await {
        quinn::ConnectionError::ApplicationClosed(c) => assert_eq!(c.error_code, CLOSE_UPSTREAM_UNAVAILABLE.into()),
        other => panic!("expected an application close, got {other:?}"),
    }
    assert_eq!(r.metrics.upstream_failures_total.load(Relaxed), 1);
}

#[tokio::test]
async fn a_hub_with_the_wrong_certificate_is_refused() {
    let (_state, hub_addr, _hub_cert) = hub(true).await;
    let other = rcgen_cert();
    let relay = relay(hub_addr, &other);
    let conn = device(&relay).await;
    assert!(matches!(conn.closed().await, quinn::ConnectionError::ApplicationClosed(_)));
    assert_eq!(relay.metrics.upstream_failures_total.load(Relaxed), 1);
}

/// A certificate the hub doesn't have.
fn rcgen_cert() -> Vec<u8> {
    let other = bind_quic("127.0.0.1:0".parse().unwrap(), None).unwrap();
    other.cert_der
}
