//! Telemetry relay. Devices send telemetry on QUIC unidirectional streams: any number of frames, each a 4-byte
//! big-endian length and a UTF-8 JSON object (battery, sync lag, rule-engine timings, queue depth...). Payments keep
//! the bidirectional streams, so telemetry never waits behind a payment and a payment never waits behind telemetry.
//!
//! The relay validates each record, stamps it with the session and receive time, publishes it to the live dashboards,
//! and (if a sink is configured) batches it to OTLP/HTTP logs on Alloy, which stores it in Loki next to the hub's own
//! logs. The queue to the sink is bounded: when the sink is slow or down, records are dropped and counted rather than
//! held in memory. Telemetry is best-effort by design; payments are not.

use serde::Serialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tokio::sync::mpsc;

/// Largest telemetry frame accepted.
pub const MAX_TELEMETRY_FRAME: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryRecord {
    pub session: u64,
    pub received_ms: u64,
    /// The device's JSON object, unchanged.
    pub body: serde_json::Value,
}

pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Where batches go. `OtlpHttpSink` in production; tests supply their own.
pub trait TelemetrySink: Send + Sync + 'static {
    fn send(&self, batch: Vec<TelemetryRecord>) -> SinkFuture<'_>;
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub queue: usize,
    pub max_batch: usize,
    pub flush_every: Duration,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig { queue: 4096, max_batch: 256, flush_every: Duration::from_secs(1) }
    }
}

#[derive(Default)]
pub struct TelemetryStats {
    pub received_total: AtomicU64,
    pub invalid_total: AtomicU64,
    pub dropped_total: AtomicU64,
    pub forwarded_total: AtomicU64,
    pub sink_errors_total: AtomicU64,
}

pub struct TelemetryRelay {
    tx: Option<mpsc::Sender<TelemetryRecord>>,
    pub stats: Arc<TelemetryStats>,
}

/// Parses one frame: a JSON object of at most `MAX_TELEMETRY_FRAME` bytes.
pub fn parse_record(frame: &[u8]) -> Result<serde_json::Value, String> {
    if frame.len() > MAX_TELEMETRY_FRAME {
        return Err(format!("telemetry frame of {} bytes exceeds {MAX_TELEMETRY_FRAME}", frame.len()));
    }
    match serde_json::from_slice::<serde_json::Value>(frame) {
        Ok(v @ serde_json::Value::Object(_)) => Ok(v),
        Ok(_) => Err("telemetry frame is not a JSON object".into()),
        Err(e) => Err(format!("telemetry frame is not JSON: {e}")),
    }
}

impl TelemetryRelay {
    /// Without a sink records only reach the dashboards and the counters. With one, a batching task is spawned
    /// (call from inside a Tokio runtime).
    pub fn new(sink: Option<Arc<dyn TelemetrySink>>, cfg: TelemetryConfig) -> Self {
        let stats = Arc::new(TelemetryStats::default());
        let tx = sink.map(|sink| {
            let (tx, rx) = mpsc::channel(cfg.queue.max(1));
            tokio::spawn(batch_loop(rx, sink, cfg, stats.clone()));
            tx
        });
        TelemetryRelay { tx, stats }
    }

    /// Accepts one record for the sink; never blocks.
    pub fn push(&self, record: TelemetryRecord) {
        self.stats.received_total.fetch_add(1, Relaxed);
        if let Some(tx) = &self.tx {
            if tx.try_send(record).is_err() {
                self.stats.dropped_total.fetch_add(1, Relaxed);
            }
        }
    }

    pub fn render_metrics(&self) -> String {
        let s = &self.stats;
        format!(
            "# TYPE difme_hub_telemetry_records_total counter\n\
             difme_hub_telemetry_records_total{{result=\"received\"}} {}\n\
             difme_hub_telemetry_records_total{{result=\"invalid\"}} {}\n\
             difme_hub_telemetry_records_total{{result=\"dropped\"}} {}\n\
             difme_hub_telemetry_records_total{{result=\"forwarded\"}} {}\n\
             # TYPE difme_hub_telemetry_sink_errors_total counter\ndifme_hub_telemetry_sink_errors_total {}\n",
            s.received_total.load(Relaxed),
            s.invalid_total.load(Relaxed),
            s.dropped_total.load(Relaxed),
            s.forwarded_total.load(Relaxed),
            s.sink_errors_total.load(Relaxed),
        )
    }
}

async fn batch_loop(mut rx: mpsc::Receiver<TelemetryRecord>, sink: Arc<dyn TelemetrySink>, cfg: TelemetryConfig, stats: Arc<TelemetryStats>) {
    let mut batch = Vec::with_capacity(cfg.max_batch);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + cfg.flush_every, cfg.flush_every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_flush = tokio::time::Instant::now();
    loop {
        let (closed, timer) = tokio::select! {
            r = rx.recv() => match r {
                Some(rec) => { batch.push(rec); (false, false) }
                None => (true, false),
            },
            _ = tick.tick() => (false, true),
        };
        // Flush when full, when the interval has passed (by the timer, or by a steady trickle of records), or at the end.
        let due = batch.len() >= cfg.max_batch || timer || closed || last_flush.elapsed() >= cfg.flush_every;
        if due && !batch.is_empty() {
            last_flush = tokio::time::Instant::now();
            let n = batch.len() as u64;
            match sink.send(std::mem::replace(&mut batch, Vec::with_capacity(cfg.max_batch))).await {
                Ok(()) => {
                    stats.forwarded_total.fetch_add(n, Relaxed);
                }
                Err(_) => {
                    // No retry queue: a failed batch is counted as dropped (best-effort, bounded memory).
                    stats.sink_errors_total.fetch_add(1, Relaxed);
                    stats.dropped_total.fetch_add(n, Relaxed);
                }
            }
        }
        if closed {
            return;
        }
    }
}

/// OTLP/HTTP JSON logs (`POST {url}`, e.g. http://alloy.observability.svc:4318/v1/logs).
pub struct OtlpHttpSink {
    url: hyper::Uri,
    client: hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, http_body_util::Full<bytes::Bytes>>,
    service_name: String,
}

impl OtlpHttpSink {
    pub fn new(url: &str, service_name: &str) -> Result<Self, String> {
        let url: hyper::Uri = url.parse().map_err(|e| format!("telemetry sink url: {e}"))?;
        if url.scheme_str() != Some("http") {
            return Err("telemetry sink url must be http:// (the mesh adds mTLS)".into());
        }
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        Ok(OtlpHttpSink { url, client, service_name: service_name.into() })
    }
}

fn attr_str(key: &str, value: &str) -> serde_json::Value {
    serde_json::json!({ "key": key, "value": { "stringValue": value } })
}

/// The OTLP logs request for a batch (one log record per telemetry record; the body is the device's JSON).
pub fn otlp_logs_body(service_name: &str, batch: &[TelemetryRecord]) -> serde_json::Value {
    let records: Vec<_> = batch
        .iter()
        .map(|r| {
            serde_json::json!({
                "timeUnixNano": (r.received_ms as u128 * 1_000_000).to_string(),
                "severityText": "INFO",
                "body": { "stringValue": r.body.to_string() },
                "attributes": [ attr_str("difme.hub.session", &r.session.to_string()), attr_str("event.domain", "device.telemetry") ],
            })
        })
        .collect();
    serde_json::json!({
        "resourceLogs": [{
            "resource": { "attributes": [ attr_str("service.name", service_name) ] },
            "scopeLogs": [{ "scope": { "name": "difme.hub.telemetry" }, "logRecords": records }],
        }]
    })
}

impl TelemetrySink for OtlpHttpSink {
    fn send(&self, batch: Vec<TelemetryRecord>) -> SinkFuture<'_> {
        Box::pin(async move {
            let body = otlp_logs_body(&self.service_name, &batch).to_string();
            let req = hyper::Request::post(self.url.clone())
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                .map_err(|e| e.to_string())?;
            let resp = tokio::time::timeout(Duration::from_secs(5), self.client.request(req))
                .await
                .map_err(|_| "telemetry sink timed out".to_string())?
                .map_err(|e| e.to_string())?;
            if resp.status().is_success() { Ok(()) } else { Err(format!("telemetry sink answered {}", resp.status())) }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    #[test]
    fn records_must_be_small_json_objects() {
        assert!(parse_record(br#"{"battery":81}"#).is_ok());
        assert!(parse_record(b"[1,2]").is_err());
        assert!(parse_record(b"not json").is_err());
        let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_TELEMETRY_FRAME));
        assert!(parse_record(big.as_bytes()).is_err());
    }

    #[test]
    fn otlp_body_shape() {
        let b = otlp_logs_body("quinn-hub", &[TelemetryRecord { session: 7, received_ms: 1_700_000_000_123, body: serde_json::json!({"lag_ms": 12}) }]);
        let rec = &b["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["timeUnixNano"], "1700000000123000000");
        assert_eq!(rec["body"]["stringValue"], r#"{"lag_ms":12}"#);
        assert_eq!(rec["attributes"][0]["value"]["stringValue"], "7");
        assert_eq!(b["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"], "quinn-hub");
    }

    struct Collect(Mutex<Vec<Vec<TelemetryRecord>>>, bool);
    impl TelemetrySink for Collect {
        fn send(&self, batch: Vec<TelemetryRecord>) -> SinkFuture<'_> {
            Box::pin(async move {
                self.0.lock().await.push(batch);
                if self.1 { Err("down".into()) } else { Ok(()) }
            })
        }
    }

    fn rec(i: u64) -> TelemetryRecord {
        TelemetryRecord { session: 1, received_ms: i, body: serde_json::json!({ "i": i }) }
    }

    #[tokio::test]
    async fn batches_by_size_and_by_time() {
        let sink = Arc::new(Collect(Mutex::new(vec![]), false));
        let relay = TelemetryRelay::new(Some(sink.clone()), TelemetryConfig { queue: 100, max_batch: 3, flush_every: Duration::from_millis(50) });
        for i in 0..4 {
            relay.push(rec(i));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let batches = sink.0.lock().await.clone();
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), vec![3, 1], "a full batch at once, the rest on the timer");
        assert_eq!(relay.stats.forwarded_total.load(Relaxed), 4);
    }

    #[tokio::test]
    async fn a_full_queue_or_failing_sink_drops_and_counts() {
        let sink = Arc::new(Collect(Mutex::new(vec![]), true));
        let relay = TelemetryRelay::new(Some(sink), TelemetryConfig { queue: 2, max_batch: 100, flush_every: Duration::from_millis(30) });
        for i in 0..10 {
            relay.push(rec(i)); // the batcher hasn't run yet: 2 fit, 8 are dropped at the queue
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(relay.stats.received_total.load(Relaxed), 10);
        assert_eq!(relay.stats.dropped_total.load(Relaxed), 10, "8 at the queue + 2 in the failed batch");
        assert_eq!(relay.stats.sink_errors_total.load(Relaxed), 1);
        assert!(relay.render_metrics().contains("result=\"dropped\"} 10"));
    }

    #[tokio::test]
    async fn without_a_sink_records_are_only_counted() {
        let relay = TelemetryRelay::new(None, TelemetryConfig::default());
        relay.push(rec(1));
        assert_eq!(relay.stats.received_total.load(Relaxed), 1);
        assert_eq!(relay.stats.dropped_total.load(Relaxed), 0);
    }
}
