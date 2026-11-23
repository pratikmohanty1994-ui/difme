use difme_quic_relay::{Relay, Upstream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let workers: usize = env("RELAY_WORKER_THREADS", "2").parse()?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = std::env::var("RELAY_UPSTREAM").map_err(|_| "RELAY_UPSTREAM (hub host:port) is required")?;
    let server_name = std::env::var("RELAY_UPSTREAM_NAME")
        .unwrap_or_else(|_| address.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| address.clone()));
    let ca = std::env::var("RELAY_UPSTREAM_CA").map_err(|_| "RELAY_UPSTREAM_CA (PEM CA of the hub's certificate) is required")?;
    let upstream = Upstream {
        address,
        server_name,
        roots: difme_quinn_hub::load_pem_roots(&ca)?,
        connect_timeout: Duration::from_millis(env("RELAY_CONNECT_TIMEOUT_MS", "3000").parse()?),
    };
    let identity = match (std::env::var("RELAY_TLS_CERT"), std::env::var("RELAY_TLS_KEY")) {
        (Ok(c), Ok(k)) => Some(difme_quinn_hub::load_pem_identity(&c, &k)?),
        _ => None,
    };
    let quic_addr: SocketAddr = env("RELAY_QUIC_ADDR", "0.0.0.0:4443").parse()?;
    let http_addr = env("RELAY_HTTP_ADDR", "0.0.0.0:9101");
    let relay = Arc::new(Relay::bind(quic_addr, identity, upstream)?);
    eprintln!("quic-relay: devices on udp/{quic_addr} → hub {} ({}), HTTP on tcp/{http_addr}", relay.upstream.address, relay.upstream.server_name);
    let metrics = relay.metrics.clone();
    tokio::spawn(relay.serve());
    let listener = tokio::net::TcpListener::bind(&http_addr).await?;
    axum::serve(listener, difme_quic_relay::http_router(metrics))
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await?;
    Ok(())
}
