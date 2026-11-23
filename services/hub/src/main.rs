use difme_quinn_hub::bridge::BridgeConfig;
use difme_quinn_hub::session::SessionConfig;
use difme_quinn_hub::telemetry::{OtlpHttpSink, TelemetrySink};
use difme_quinn_hub::HubOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    match std::env::var(name) {
        Ok(v) => v.parse().map_err(|_| format!("{name}={v} is not a number").into()),
        Err(_) => Ok(default),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Process-level memory (owner rule): two runtime workers unless told otherwise, not one per node CPU.
    let workers: usize = env("HUB_WORKER_THREADS", "2").parse()?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sink: Option<Arc<dyn TelemetrySink>> = match std::env::var("HUB_TELEMETRY_OTLP_URL") {
        Ok(url) if !url.is_empty() => Some(Arc::new(OtlpHttpSink::new(&url, "quinn-hub")?)),
        _ => None,
    };
    let defaults = BridgeConfig::default();
    let opts = HubOptions {
        sessions: SessionConfig { max_sessions: env_num("HUB_MAX_SESSIONS", 10_000)?, max_per_ip: env_num("HUB_MAX_SESSIONS_PER_IP", 0)? },
        bridge: BridgeConfig {
            max_in_flight: env_num("HUB_BRIDGE_MAX_IN_FLIGHT", defaults.max_in_flight)?,
            attempts: env_num("HUB_BRIDGE_ATTEMPTS", defaults.attempts)?,
            deadline: Duration::from_millis(env_num("HUB_BRIDGE_DEADLINE_MS", 5_000)?),
            ..defaults
        },
        telemetry_sink: sink,
        ..HubOptions::default()
    };
    let state = difme_quinn_hub::State::with_options(&env("HUB_GRPC_CORE", "http://127.0.0.1:9000"), opts)?;
    let quic_addr: SocketAddr = env("HUB_QUIC_ADDR", "0.0.0.0:4443").parse()?;
    // PEM (a cert-manager Secret) or DER files; neither: a self-signed dev certificate.
    let quic = match (std::env::var("HUB_TLS_CERT"), std::env::var("HUB_TLS_KEY"), std::env::var("HUB_TLS_CERT_DER"), std::env::var("HUB_TLS_KEY_DER")) {
        (Ok(c), Ok(k), _, _) => {
            let (chain, key) = difme_quinn_hub::load_pem_identity(&c, &k)?;
            difme_quinn_hub::bind_quic_identity(quic_addr, chain, key)?
        }
        (_, _, Ok(c), Ok(k)) => difme_quinn_hub::bind_quic(quic_addr, Some((std::fs::read(c)?, std::fs::read(k)?)))?,
        _ => difme_quinn_hub::bind_quic(quic_addr, None)?,
    };
    let http_addr = env("HUB_HTTP_ADDR", "0.0.0.0:9100");
    eprintln!("quinn-hub: QUIC on udp/{quic_addr}, HTTP (health, metrics, sessions, SSE) on tcp/{http_addr}");
    tokio::spawn(difme_quinn_hub::serve_quic(quic.endpoint, state.clone()));
    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    axum::serve(listener, difme_quinn_hub::http_router(state))
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await?;
    Ok(())
}
