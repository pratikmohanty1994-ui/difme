//! DIFME QUIC hub (PDF §5.2). Edge devices open a QUIC connection (ALPN `difme/1`) and send one payment per
//! bidirectional stream: a 4-byte big-endian length, then a protobuf `SubmitPaymentRequest`. The hub forwards it to
//! the core's `PaymentCommandService` over gRPC and answers on the same stream with the length-prefixed
//! `SubmitPaymentResponse`. Unidirectional streams carry device telemetry (see `telemetry`). Every outcome, telemetry
//! record and session change is published to the live dashboards (`dashboard`, server-sent events).
//!
//! Parts (README row 5.2): `session` (admission, per-device activity, in-flight coalescing by idempotency key),
//! `bridge` (tonic gRPC client to the core with retries, deadlines, trace propagation and a circuit breaker),
//! `telemetry` (relay to OTLP/HTTP logs), `dashboard` (topics, replay on reconnect). The local QUIC relay for the
//! scenario D proxy chain is the `quic-relay` crate next to this one.

pub mod bridge;
pub mod dashboard;
pub mod session;
pub mod telemetry;

pub mod proto {
    tonic::include_proto!("difme.payments.v1");
}

use bridge::{BridgeConfig, GrpcBridge};
use dashboard::{DashboardRelay, TOPIC_PAYMENTS, TOPIC_SESSIONS, TOPIC_TELEMETRY};
use proto::payment_command_service_client::PaymentCommandServiceClient;
use proto::{SubmitPaymentRequest, SubmitPaymentResponse};
use prost::Message;
use session::{Claim, SessionConfig, SessionManager};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use telemetry::{TelemetryConfig, TelemetryRecord, TelemetryRelay, TelemetrySink};
use tonic::transport::{Channel, Endpoint};

/// Stream reset code: the core could not be reached (or its circuit is open); the device retries with the same key.
pub const RESET_CORE_UNAVAILABLE: u32 = 1;

pub const ALPN: &[u8] = b"difme/1";
/// Largest frame accepted from a device; a payment request is a few hundred bytes.
pub const MAX_FRAME: usize = 64 * 1024;

/// Counters exported at /metrics. Hand-rolled atomics instead of a metrics crate: a few bytes, no allocation.
#[derive(Default)]
pub struct Metrics {
    pub connections_open: AtomicI64,
    pub streams_total: AtomicU64,
    pub accepted_total: AtomicU64,
    pub duplicate_total: AtomicU64,
    pub rejected_total: AtomicU64,
    pub errors_total: AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        format!(
            "# TYPE difme_hub_connections_open gauge\ndifme_hub_connections_open {}\n\
             # TYPE difme_hub_streams_total counter\ndifme_hub_streams_total {}\n\
             # TYPE difme_hub_payments_total counter\n\
             difme_hub_payments_total{{outcome=\"accepted\"}} {}\n\
             difme_hub_payments_total{{outcome=\"duplicate\"}} {}\n\
             difme_hub_payments_total{{outcome=\"rejected\"}} {}\n\
             # TYPE difme_hub_errors_total counter\ndifme_hub_errors_total {}\n",
            self.connections_open.load(Relaxed),
            self.streams_total.load(Relaxed),
            self.accepted_total.load(Relaxed),
            self.duplicate_total.load(Relaxed),
            self.rejected_total.load(Relaxed),
            self.errors_total.load(Relaxed)
        )
    }
}

/// Tunables for `State::with_options`; `Default` matches `State::new`.
#[derive(Clone, Default)]
pub struct HubOptions {
    pub sessions: SessionConfig,
    pub bridge: BridgeConfig,
    pub telemetry: TelemetryConfig,
    /// None: telemetry reaches only the dashboards and the counters.
    pub telemetry_sink: Option<Arc<dyn TelemetrySink>>,
    /// Dashboard events kept for reconnecting subscribers (0 = 256).
    pub dashboard_replay: usize,
}

/// Shared by the QUIC and HTTP sides.
pub struct State {
    pub metrics: Metrics,
    /// Live-dashboard relay: payments, telemetry and session topics, replayable by event id.
    pub dashboard: DashboardRelay,
    pub sessions: Arc<SessionManager>,
    pub bridge: GrpcBridge,
    pub telemetry: TelemetryRelay,
    pub core: PaymentCommandServiceClient<Channel>,
}

impl State {
    /// `core_url` is the gRPC endpoint (h2c), e.g. http://quarkus-cmd-svc.core-platform.svc:9000. Connects lazily.
    pub fn new(core_url: &str) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        Self::with_options(core_url, HubOptions::default())
    }

    /// Call from inside a Tokio runtime when a telemetry sink is given (its batching task is spawned here).
    pub fn with_options(core_url: &str, opts: HubOptions) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let channel = Endpoint::from_shared(core_url.to_string())?
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .connect_lazy();
        let core = PaymentCommandServiceClient::new(channel);
        Ok(Arc::new(State {
            metrics: Metrics::default(),
            dashboard: DashboardRelay::new(if opts.dashboard_replay == 0 { 256 } else { opts.dashboard_replay }),
            sessions: SessionManager::new(opts.sessions),
            bridge: GrpcBridge::new(core.clone(), opts.bridge),
            telemetry: TelemetryRelay::new(opts.telemetry_sink, opts.telemetry),
            core,
        }))
    }

    /// Everything exported at /metrics.
    pub fn render_metrics(&self) -> String {
        let s = &self.sessions;
        format!(
            "{}{}{}# TYPE difme_hub_sessions_active gauge\ndifme_hub_sessions_active {}\n\
             # TYPE difme_hub_sessions_opened_total counter\ndifme_hub_sessions_opened_total {}\n\
             # TYPE difme_hub_sessions_refused_total counter\ndifme_hub_sessions_refused_total {}\n\
             # TYPE difme_hub_payments_coalesced_total counter\ndifme_hub_payments_coalesced_total {}\n\
             # TYPE difme_hub_dashboard_subscribers gauge\ndifme_hub_dashboard_subscribers {}\n\
             # TYPE difme_hub_dashboard_events_total counter\ndifme_hub_dashboard_events_total {}\n",
            self.metrics.render(),
            self.bridge.render_metrics(),
            self.telemetry.render_metrics(),
            s.active(),
            s.opened_total.load(Relaxed),
            s.refused_total.load(Relaxed),
            s.coalesced_total.load(Relaxed),
            self.dashboard.subscribers(),
            self.dashboard.published_total.load(Relaxed),
        )
    }
}

/// A QUIC endpoint plus the certificate it presents (dev: self-signed, so clients and tests can pin it).
pub struct QuicServer {
    pub endpoint: quinn::Endpoint,
    pub cert_der: Vec<u8>,
}

/// Binds the QUIC endpoint. Without a certificate pair a self-signed one is generated (dev and tests); production
/// mounts the SPIFFE X.509 SVID instead.
pub fn bind_quic(addr: SocketAddr, cert_and_key: Option<(Vec<u8>, Vec<u8>)>) -> Result<QuicServer, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, key_der) = match cert_and_key {
        Some(pair) => pair,
        None => {
            let ck = rcgen::generate_simple_self_signed(vec!["quinn-hub".into(), "localhost".into()])?;
            (ck.cert.der().to_vec(), ck.signing_key.serialize_der())
        }
    };
    bind_quic_identity(
        addr,
        vec![rustls::pki_types::CertificateDer::from(cert_der)],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
    )
}

/// Reads a PEM certificate chain and private key (PKCS#8, PKCS#1 or SEC1), e.g. a cert-manager `kubernetes.io/tls`
/// Secret mounted as files.
pub fn load_pem_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>), Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::pem::PemObject;
    let chain = rustls::pki_types::CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        return Err(format!("{cert_path}: no certificate").into());
    }
    Ok((chain, rustls::pki_types::PrivateKeyDer::from_pem_file(key_path)?))
}

/// Reads every certificate in a PEM file into a root store (the CA a client trusts).
pub fn load_pem_roots(path: &str) -> Result<rustls::RootCertStore, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_file_iter(path)? {
        roots.add(cert?)?;
    }
    if roots.is_empty() {
        return Err(format!("{path}: no certificate").into());
    }
    Ok(roots)
}

/// Binds the QUIC endpoint with a given certificate chain (leaf first) and key.
pub fn bind_quic_identity(
    addr: SocketAddr,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<QuicServer, Box<dyn std::error::Error + Send + Sync>> {
    let cert_der = chain.first().ok_or("empty certificate chain")?.to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(64u32.into())          // per device: bounded in-flight payments
        .max_concurrent_uni_streams(16u32.into())           // telemetry streams
        .keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    server.transport_config(Arc::new(transport));
    Ok(QuicServer { endpoint: quinn::Endpoint::server(server, addr)?, cert_der })
}

/// Accepts connections until the endpoint closes.
pub async fn serve_quic(endpoint: quinn::Endpoint, state: Arc<State>) {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let guard = match state.sessions.open(conn.remote_address()) {
                Ok(g) => g,
                Err(refused) => {
                    conn.close(quinn::VarInt::from_u32(refused.code()), refused.reason());
                    return;
                }
            };
            let session = guard.session.clone();
            state.metrics.connections_open.fetch_add(1, Relaxed);
            state.dashboard.publish(TOPIC_SESSIONS, format!(r#"{{"session":{},"event":"open"}}"#, session.id));
            loop {
                tokio::select! {
                    bi = conn.accept_bi() => {
                        let Ok((send, recv)) = bi else { break };
                        let (state, session) = (state.clone(), session.clone());
                        tokio::spawn(async move {
                            state.metrics.streams_total.fetch_add(1, Relaxed);
                            session.touch();
                            if handle_stream(send, recv, &state, &session).await.is_err() {
                                state.metrics.errors_total.fetch_add(1, Relaxed);
                            }
                        });
                    }
                    uni = conn.accept_uni() => {
                        let Ok(recv) = uni else { break };
                        let (state, session) = (state.clone(), session.clone());
                        tokio::spawn(async move {
                            state.metrics.streams_total.fetch_add(1, Relaxed);
                            if handle_telemetry(recv, &state, &session).await.is_err() {
                                state.metrics.errors_total.fetch_add(1, Relaxed);
                            }
                        });
                    }
                }
            }
            state.metrics.connections_open.fetch_sub(1, Relaxed);
            state.dashboard.publish(TOPIC_SESSIONS, format!(r#"{{"session":{},"event":"close"}}"#, session.id));
            drop(guard);
        });
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

async fn handle_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream, state: &State, session: &session::Session) -> Result<(), BoxError> {
    let request = SubmitPaymentRequest::decode(read_frame(&mut recv).await?.as_slice())?;
    session.payments.fetch_add(1, Relaxed);
    // A retry of a payment that is still in flight (same idempotency key) waits for the first attempt's answer.
    let outcome = match state.sessions.claim(&request.idempotency_key) {
        Claim::Follower(rx) => session::wait(rx).await,
        Claim::Leader(claim) => {
            let outcome = match state.bridge.submit(request).await {
                Ok(r) => {
                    record(state, &r);
                    Ok(r.encode_to_vec())
                }
                Err(e) => Err(e.to_string()),
            };
            claim.complete(outcome.clone());
            outcome
        }
    };
    match outcome {
        Ok(body) => {
            write_frame(&mut send, &body).await?;
            send.finish()?;
            Ok(())
        }
        Err(e) => {
            let _ = send.reset(quinn::VarInt::from_u32(RESET_CORE_UNAVAILABLE));
            Err(e.into())
        }
    }
}

/// Reads telemetry frames until the device finishes the stream. An invalid record is counted and skipped; a frame
/// over the size limit ends the stream (the length can't be trusted to resynchronise).
async fn handle_telemetry(mut recv: quinn::RecvStream, state: &State, session: &session::Session) -> Result<(), BoxError> {
    loop {
        let mut len = [0u8; 4];
        match recv.read_exact(&mut len).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let n = u32::from_be_bytes(len) as usize;
        if n > telemetry::MAX_TELEMETRY_FRAME {
            state.telemetry.stats.invalid_total.fetch_add(1, Relaxed);
            let _ = recv.stop(quinn::VarInt::from_u32(2));
            return Err(format!("telemetry frame of {n} bytes exceeds the limit").into());
        }
        let mut buf = vec![0u8; n];
        recv.read_exact(&mut buf).await?;
        session.touch();
        match telemetry::parse_record(&buf) {
            Ok(body) => {
                session.telemetry_records.fetch_add(1, Relaxed);
                let rec = TelemetryRecord { session: session.id, received_ms: session::now_ms(), body };
                if state.dashboard.subscribers() > 0 {
                    state.dashboard.publish(TOPIC_TELEMETRY, serde_json::to_string(&rec)?);
                }
                state.telemetry.push(rec);
            }
            Err(_) => {
                state.telemetry.stats.invalid_total.fetch_add(1, Relaxed);
            }
        }
    }
}

fn record(state: &State, r: &SubmitPaymentResponse) {
    use proto::submit_payment_response::Status;
    let outcome = match r.status() {
        Status::Accepted => { state.metrics.accepted_total.fetch_add(1, Relaxed); "ACCEPTED" }
        Status::Duplicate => { state.metrics.duplicate_total.fetch_add(1, Relaxed); "DUPLICATE" }
        Status::RejectedFraud | Status::RejectedRateLimit => { state.metrics.rejected_total.fetch_add(1, Relaxed); r.status().as_str_name() }
        Status::Unspecified => "UNSPECIFIED",
    };
    // Published even without subscribers: the ring lets a dashboard that reconnects catch up.
    state.dashboard.publish(TOPIC_PAYMENTS, format!(r#"{{"paymentId":"{}","status":"{}"}}"#, r.payment_id, outcome));
}

pub async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(format!("frame of {n} bytes exceeds {MAX_FRAME}").into());
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_frame(send: &mut quinn::SendStream, body: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    send.write_all(&(body.len() as u32).to_be_bytes()).await?;
    send.write_all(body).await?;
    Ok(())
}

/// Health, metrics, sessions and the live-dashboard relay (SSE) on one small HTTP listener. Port 9100 is cluster
/// internal: `/v1/sessions` lists device addresses.
pub fn http_router(state: Arc<State>) -> axum::Router {
    use axum::extract::Query;
    use axum::http::HeaderMap;
    use axum::response::sse::{Event, KeepAlive, Sse};
    use axum::routing::get;
    use std::collections::{HashMap, HashSet};
    use tokio_stream::StreamExt;
    axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get({ let s = state.clone(); move || async move { s.render_metrics() } }))
        .route("/v1/sessions", get({ let s = state.clone(); move || async move { axum::Json(s.sessions.snapshot()) } }))
        .route("/v1/events", get({
            let s = state.clone();
            move |Query(q): Query<HashMap<String, String>>, headers: HeaderMap| async move {
                let topics: Option<HashSet<String>> = q.get("topics").map(|t| t.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect());
                let last = headers.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
                let stream = s.dashboard.subscribe(topics, last).map(|e| {
                    let ev = Event::default().event(e.topic).data(e.data.clone());
                    Ok::<_, std::convert::Infallible>(if e.id > 0 { ev.id(e.id.to_string()) } else { ev })
                });
                Sse::new(stream).keep_alive(KeepAlive::default())
            }
        }))
}
