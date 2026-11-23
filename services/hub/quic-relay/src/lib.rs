//! Local QUIC relay for the scenario D proxy chain: **edge device → relay → quinn-hub**.
//!
//! The relay runs close to the devices (a branch, a store, a cloud edge site) and speaks the hub's protocol (ALPN
//! `difme/1`) on both sides without interpreting it. For each device connection it opens one upstream connection to
//! the hub and splices every stream onto it: bidirectional streams (payments) both ways, unidirectional streams
//! (telemetry) device → hub. Stream resets travel through with their codes, so a device sees the hub's "core
//! unavailable" (1) exactly as if it were connected directly, and an unreachable hub resets with the same code.
//!
//! Why terminate instead of forwarding UDP: the device's handshake, loss recovery and congestion control run over
//! the short local link, and the long haul to the hub is one well-behaved connection per device from a fixed address
//! that the hub's site firewall can allow. One upstream connection per device (not one shared connection) keeps the
//! hub's per-session limits, flow control and session view per device.
//!
//! TLS: the device trusts the relay's certificate; the relay verifies the hub against a pinned CA. The relay sees
//! payment frames in the clear, so it runs on a trusted site with the same handling as the hub.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

pub use difme_quinn_hub::{ALPN, RESET_CORE_UNAVAILABLE};

/// Close code sent to a device when the relay cannot reach the hub.
pub const CLOSE_UPSTREAM_UNAVAILABLE: u32 = 0x20;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Default)]
pub struct RelayMetrics {
    pub connections_open: AtomicI64,
    pub connections_total: AtomicU64,
    pub upstream_failures_total: AtomicU64,
    pub streams_total: AtomicU64,
    pub stream_resets_total: AtomicU64,
    pub bytes_up_total: AtomicU64,
    pub bytes_down_total: AtomicU64,
}

impl RelayMetrics {
    pub fn render(&self) -> String {
        format!(
            "# TYPE difme_relay_connections_open gauge\ndifme_relay_connections_open {}\n\
             # TYPE difme_relay_connections_total counter\ndifme_relay_connections_total {}\n\
             # TYPE difme_relay_upstream_failures_total counter\ndifme_relay_upstream_failures_total {}\n\
             # TYPE difme_relay_streams_total counter\ndifme_relay_streams_total {}\n\
             # TYPE difme_relay_stream_resets_total counter\ndifme_relay_stream_resets_total {}\n\
             # TYPE difme_relay_bytes_total counter\n\
             difme_relay_bytes_total{{direction=\"up\"}} {}\n\
             difme_relay_bytes_total{{direction=\"down\"}} {}\n",
            self.connections_open.load(Relaxed),
            self.connections_total.load(Relaxed),
            self.upstream_failures_total.load(Relaxed),
            self.streams_total.load(Relaxed),
            self.stream_resets_total.load(Relaxed),
            self.bytes_up_total.load(Relaxed),
            self.bytes_down_total.load(Relaxed),
        )
    }
}

/// Where and how the relay reaches the hub.
#[derive(Clone)]
pub struct Upstream {
    /// host:port, resolved on every new device connection (a Service IP or DNS change is picked up).
    pub address: String,
    /// TLS server name the hub's certificate must carry.
    pub server_name: String,
    pub roots: rustls::RootCertStore,
    pub connect_timeout: Duration,
}

pub fn client_config(roots: rustls::RootCertStore) -> Result<quinn::ClientConfig, BoxError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

pub struct Relay {
    /// Device-facing endpoint; upstream connections leave from the same UDP socket.
    pub endpoint: quinn::Endpoint,
    pub cert_der: Vec<u8>,
    pub upstream: Upstream,
    pub metrics: Arc<RelayMetrics>,
}

impl Relay {
    /// Binds the device side with the hub's own server settings (same ALPN, TLS 1.3 and stream limits). Without a
    /// certificate a self-signed one is generated (dev and tests).
    pub fn bind(
        addr: SocketAddr,
        identity: Option<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)>,
        upstream: Upstream,
    ) -> Result<Self, BoxError> {
        let server = match identity {
            Some((chain, key)) => difme_quinn_hub::bind_quic_identity(addr, chain, key)?,
            None => difme_quinn_hub::bind_quic(addr, None)?,
        };
        let mut endpoint = server.endpoint;
        endpoint.set_default_client_config(client_config(upstream.roots.clone())?);
        Ok(Relay { endpoint, cert_der: server.cert_der, upstream, metrics: Arc::new(RelayMetrics::default()) })
    }

    pub async fn connect_upstream(&self) -> Result<quinn::Connection, BoxError> {
        let addr = tokio::net::lookup_host(&self.upstream.address).await?.next().ok_or("upstream address did not resolve")?;
        let connecting = self.endpoint.connect(addr, &self.upstream.server_name)?;
        Ok(tokio::time::timeout(self.upstream.connect_timeout, connecting).await.map_err(|_| "upstream connect timed out")??)
    }

    /// Accepts devices until the endpoint closes.
    pub async fn serve(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let relay = self.clone();
            tokio::spawn(async move {
                let Ok(device) = incoming.await else { return };
                relay.metrics.connections_total.fetch_add(1, Relaxed);
                let upstream = match relay.connect_upstream().await {
                    Ok(c) => c,
                    Err(_) => {
                        relay.metrics.upstream_failures_total.fetch_add(1, Relaxed);
                        device.close(quinn::VarInt::from_u32(CLOSE_UPSTREAM_UNAVAILABLE), b"hub unreachable");
                        return;
                    }
                };
                relay.metrics.connections_open.fetch_add(1, Relaxed);
                relay.splice(&device, &upstream).await;
                relay.metrics.connections_open.fetch_sub(1, Relaxed);
            });
        }
    }

    /// Relays streams until either side's connection ends, then closes the other with the same code.
    async fn splice(&self, device: &quinn::Connection, upstream: &quinn::Connection) {
        let reason = loop {
            tokio::select! {
                bi = device.accept_bi() => match bi {
                    Ok((dsend, drecv)) => {
                        self.metrics.streams_total.fetch_add(1, Relaxed);
                        match upstream.open_bi().await {
                            Ok((usend, urecv)) => {
                                let m = self.metrics.clone();
                                tokio::spawn(pipe(drecv, usend, m.clone(), true));
                                tokio::spawn(pipe(urecv, dsend, m, false));
                            }
                            Err(_) => {
                                let mut dsend = dsend;
                                let _ = dsend.reset(quinn::VarInt::from_u32(RESET_CORE_UNAVAILABLE));
                                self.metrics.stream_resets_total.fetch_add(1, Relaxed);
                            }
                        }
                    }
                    Err(e) => break Some(e),
                },
                uni = device.accept_uni() => match uni {
                    Ok(drecv) => {
                        self.metrics.streams_total.fetch_add(1, Relaxed);
                        if let Ok(usend) = upstream.open_uni().await {
                            tokio::spawn(pipe(drecv, usend, self.metrics.clone(), true));
                        }
                    }
                    Err(e) => break Some(e),
                },
                e = upstream.closed() => {
                    let (code, why) = match &e {
                        quinn::ConnectionError::ApplicationClosed(c) => (c.error_code, c.reason.to_vec()),
                        _ => (quinn::VarInt::from_u32(CLOSE_UPSTREAM_UNAVAILABLE), b"hub connection lost".to_vec()),
                    };
                    device.close(code, &why);
                    break None;
                }
            }
        };
        if let Some(e) = reason {
            let (code, why) = match &e {
                quinn::ConnectionError::ApplicationClosed(c) => (c.error_code, c.reason.to_vec()),
                _ => (quinn::VarInt::from_u32(0), b"device gone".to_vec()),
            };
            upstream.close(code, &why);
        }
    }
}

/// Copies one stream direction. A reset on the reading side is passed on as a reset with the same code; a stop on
/// the writing side is passed back as a stop.
async fn pipe(mut from: quinn::RecvStream, mut to: quinn::SendStream, m: Arc<RelayMetrics>, up: bool) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf).await {
            Ok(Some(n)) => {
                if let Err(e) = to.write_all(&buf[..n]).await {
                    if let quinn::WriteError::Stopped(code) = e {
                        let _ = from.stop(code);
                    }
                    m.stream_resets_total.fetch_add(1, Relaxed);
                    return;
                }
                (if up { &m.bytes_up_total } else { &m.bytes_down_total }).fetch_add(n as u64, Relaxed);
            }
            Ok(None) => {
                let _ = to.finish();
                return;
            }
            Err(quinn::ReadError::Reset(code)) => {
                let _ = to.reset(code);
                m.stream_resets_total.fetch_add(1, Relaxed);
                return;
            }
            Err(_) => {
                let _ = to.reset(quinn::VarInt::from_u32(RESET_CORE_UNAVAILABLE));
                m.stream_resets_total.fetch_add(1, Relaxed);
                return;
            }
        }
    }
}

/// Health and metrics.
pub fn http_router(metrics: Arc<RelayMetrics>) -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(move || async move { metrics.render() }))
}
