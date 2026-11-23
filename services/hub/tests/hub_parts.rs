//! Session manager, gRPC bridge, telemetry relay and live dashboard relay, end to end over QUIC and HTTP.

mod common;

use common::*;
use difme_quinn_hub::bridge::BridgeConfig;
use difme_quinn_hub::proto::submit_payment_response::Status;
use difme_quinn_hub::session::SessionConfig;
use difme_quinn_hub::telemetry::{SinkFuture, TelemetryConfig, TelemetryRecord, TelemetrySink};
use difme_quinn_hub::{bind_quic, http_router, serve_quic, HubOptions, State};
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn hub(core_url: &str, opts: HubOptions) -> (Arc<State>, std::net::SocketAddr, Vec<u8>) {
    let state = State::with_options(core_url, opts).unwrap();
    let server = bind_quic("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    tokio::spawn(serve_quic(server.endpoint, state.clone()));
    (state, addr, server.cert_der)
}

async fn connect(addr: std::net::SocketAddr, cert: &[u8]) -> quinn::Connection {
    client(cert).connect(addr, "localhost").unwrap().await.unwrap()
}

#[tokio::test]
async fn concurrent_retries_of_one_payment_reach_the_core_once() {
    let core = Arc::new(FakeCore { delay: Duration::from_millis(300), ..Default::default() });
    let (state, addr, cert) = hub(&start_core(core.clone()).await, HubOptions::default()).await;
    // Two connections, as when a device reconnects and resends while the first attempt is still in flight.
    let (c1, c2) = (connect(addr, &cert).await, connect(addr, &cert).await);
    let (a, b) = tokio::join!(submit(&c1, "0190f3c0-0000-7000-8000-0000000000aa"), submit(&c2, "0190f3c0-0000-7000-8000-0000000000aa"));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(core.calls.load(SeqCst), 1, "the second attempt waited for the first");
    assert_eq!(a, b, "both attempts get the same answer");
    assert_eq!(state.sessions.coalesced_total.load(Relaxed), 1);
    assert_eq!(state.sessions.active(), 2);
    // Once answered, a later retry is a new call (the core's idempotency answers it).
    submit(&c1, "0190f3c0-0000-7000-8000-0000000000aa").await.unwrap();
    assert_eq!(core.calls.load(SeqCst), 2);
    c2.close(0u32.into(), b"bye");
    assert!(eventually(|| state.sessions.active() == 1).await, "a closed connection ends its session");
}

#[tokio::test]
async fn the_hub_refuses_connections_over_its_session_cap() {
    let core = Arc::new(FakeCore::default());
    let opts = HubOptions { sessions: SessionConfig { max_sessions: 1, max_per_ip: 0 }, ..Default::default() };
    let (state, addr, cert) = hub(&start_core(core).await, opts).await;
    let first = connect(addr, &cert).await;
    let second = connect(addr, &cert).await;
    let err = second.closed().await;
    match err {
        quinn::ConnectionError::ApplicationClosed(c) => assert_eq!(c.error_code, 0x10u32.into()),
        other => panic!("expected an application close, got {other:?}"),
    }
    assert_eq!(state.sessions.refused_total.load(Relaxed), 1);
    assert_eq!(submit(&first, "k-1").await.unwrap().status(), Status::Accepted, "the admitted session works");
}

#[tokio::test]
async fn the_bridge_retries_a_starting_core_and_propagates_the_trace() {
    let core = Arc::new(FakeCore { fail_first: 2, ..Default::default() });
    let opts = HubOptions { bridge: BridgeConfig { backoff: Duration::from_millis(5), ..Default::default() }, ..Default::default() };
    let (state, addr, cert) = hub(&start_core(core.clone()).await, opts).await;
    let conn = connect(addr, &cert).await;
    assert_eq!(submit(&conn, "k-retry").await.unwrap().status(), Status::Accepted);
    assert_eq!(core.calls.load(SeqCst), 3);
    assert_eq!(state.bridge.stats.retries_total.load(Relaxed), 2);
    let tps = core.traceparents.lock().unwrap().clone();
    assert_eq!(tps.len(), 3);
    assert!(tps.iter().all(|t| t == &tps[0] && t.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")), "{tps:?}");
}

#[tokio::test]
async fn the_breaker_opens_on_a_dead_core_and_fails_fast() {
    let opts = HubOptions {
        bridge: BridgeConfig { attempts: 1, breaker_threshold: 2, breaker_cooldown: Duration::from_millis(300), ..Default::default() },
        ..Default::default()
    };
    let (state, addr, cert) = hub(&dead_core().await, opts).await;
    let conn = connect(addr, &cert).await;
    for _ in 0..2 {
        let e = submit(&conn, "k-dead").await.unwrap_err();
        assert!(e.contains("reset by peer: error 1"), "core unavailable resets with code 1: {e}");
    }
    assert!(state.bridge.breaker_open());
    let before = state.bridge.stats.calls_total.load(Relaxed);
    assert!(submit(&conn, "k-dead").await.is_err());
    assert_eq!(state.bridge.stats.calls_total.load(Relaxed), before, "open breaker: the core was not called");
    assert_eq!(state.bridge.stats.short_circuited_total.load(Relaxed), 1);
    assert!(state.render_metrics().contains("difme_hub_bridge_breaker_open 1"));
}

#[tokio::test]
async fn the_breaker_closes_again_when_the_core_recovers() {
    let core = Arc::new(FakeCore { fail_first: 2, ..Default::default() });
    let opts = HubOptions {
        bridge: BridgeConfig { attempts: 1, breaker_threshold: 2, breaker_cooldown: Duration::from_millis(100), ..Default::default() },
        ..Default::default()
    };
    let (state, addr, cert) = hub(&start_core(core).await, opts).await;
    let conn = connect(addr, &cert).await;
    assert!(submit(&conn, "a").await.is_err() && submit(&conn, "b").await.is_err());
    assert!(state.bridge.breaker_open());
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(submit(&conn, "c").await.unwrap().status(), Status::Accepted, "the half-open probe succeeds");
    assert!(!state.bridge.breaker_open());
}

struct Collect(Mutex<Vec<TelemetryRecord>>);
impl TelemetrySink for Collect {
    fn send(&self, batch: Vec<TelemetryRecord>) -> SinkFuture<'_> {
        self.0.lock().unwrap().extend(batch);
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn telemetry_streams_reach_the_sink_with_their_session() {
    let sink = Arc::new(Collect(Mutex::new(vec![])));
    let opts = HubOptions {
        telemetry_sink: Some(sink.clone()),
        telemetry: TelemetryConfig { flush_every: Duration::from_millis(20), ..Default::default() },
        ..Default::default()
    };
    let (state, addr, cert) = hub(&start_core(Arc::new(FakeCore::default())).await, opts).await;
    let conn = connect(addr, &cert).await;
    send_telemetry(&conn, &[br#"{"battery":81}"#, b"not json", br#"{"syncLagMs":40}"#]).await;
    assert!(eventually(|| sink.0.lock().unwrap().len() == 2).await, "two valid records forwarded");
    let got = sink.0.lock().unwrap().clone();
    assert_eq!(got[0].body["battery"], 81);
    assert_eq!(got[1].body["syncLagMs"], 40);
    let session = state.sessions.snapshot()[0].id;
    assert!(got.iter().all(|r| r.session == session));
    assert_eq!(state.telemetry.stats.invalid_total.load(Relaxed), 1);
    assert_eq!(state.sessions.snapshot()[0].telemetry_records, 2);
}

/// Opens `/v1/events` and returns the raw SSE text received within `wait`.
async fn sse(http: std::net::SocketAddr, query: &str, last_event_id: Option<u64>, wait: Duration, during: impl std::future::Future<Output = ()>) -> String {
    let mut s = tokio::net::TcpStream::connect(http).await.unwrap();
    let extra = last_event_id.map(|i| format!("Last-Event-ID: {i}\r\n")).unwrap_or_default();
    s.write_all(format!("GET /v1/events{query} HTTP/1.1\r\nHost: hub\r\nAccept: text/event-stream\r\n{extra}\r\n").as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await; // subscribed before the events
    during.await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn dashboards_filter_topics_and_replay_after_reconnect() {
    let (state, addr, cert) = hub(&start_core(Arc::new(FakeCore::default())).await, HubOptions::default()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, http_router(state)).await.unwrap() });
    let conn = connect(addr, &cert).await;

    // Live, payments only: the session "open" event (published before) and telemetry are filtered out.
    let live = sse(http, "?topics=payments", None, Duration::from_millis(400), async {
        submit(&conn, "pay-1").await.unwrap();
        send_telemetry(&conn, &[br#"{"battery":50}"#]).await;
    })
    .await;
    assert!(live.contains("event: payments") && live.contains(r#"data: {"paymentId":"pay-1","status":"ACCEPTED"}"#), "{live}");
    assert!(!live.contains("event: telemetry") && !live.contains("event: sessions"), "{live}");

    // A dashboard that saw event 1 reconnects: it gets everything after it from the ring, in order.
    submit(&conn, "pay-2").await.unwrap();
    let replay = sse(http, "", Some(1), Duration::from_millis(300), async {}).await;
    let p1 = replay.find("pay-1").expect("pay-1 replayed");
    let p2 = replay.find("pay-2").expect("pay-2 replayed");
    assert!(p1 < p2, "{replay}");
    assert!(!replay.contains("id: 1\n"), "event 1 is not sent again: {replay}");

    let sessions = sse(http, "?topics=sessions", Some(0), Duration::from_millis(200), async {}).await;
    assert!(sessions.contains(r#""event":"open""#), "{sessions}");
}

#[tokio::test]
async fn sessions_endpoint_lists_devices() {
    let (state, addr, cert) = hub(&start_core(Arc::new(FakeCore::default())).await, HubOptions::default()).await;
    let conn = connect(addr, &cert).await;
    submit(&conn, "p").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, http_router(state)).await.unwrap() });
    let mut s = tokio::net::TcpStream::connect(http).await.unwrap();
    s.write_all(b"GET /v1/sessions HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();
    assert!(body.contains(r#""payments":1"#) && body.contains(r#""remote":"127.0.0.1:"#), "{body}");
}
