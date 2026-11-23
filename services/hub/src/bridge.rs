//! tonic gRPC bridge from the hub to the core's `PaymentCommandService` (quarkus-cmd-svc, h2c on 9000).
//!
//! - **Bounded concurrency**: at most `max_in_flight` calls to the core; the rest wait for a slot (the device's QUIC
//!   stream credit is the back-pressure further out).
//! - **Retries** on `UNAVAILABLE` and `DEADLINE_EXCEEDED` with exponential backoff. Safe because every command
//!   carries the device's idempotency key; the core answers a repeat with `STATUS_DUPLICATE` or the original result.
//! - **Deadline**: each attempt carries `grpc-timeout`, so the core stops work the device has given up on.
//! - **Trace propagation**: the request's 32-hex `trace_id` becomes a W3C `traceparent`, and the idempotency key is
//!   sent as `x-difme-idempotency-key` metadata for the core's logs.
//! - **Circuit breaker**: after `breaker_threshold` consecutive failed calls the bridge fails fast for
//!   `breaker_cooldown`, then lets one probe through. Devices get a stream reset at once and retry later instead of
//!   piling onto a core that is down.

use crate::proto::payment_command_service_client::PaymentCommandServiceClient;
use crate::proto::{SubmitPaymentRequest, SubmitPaymentResponse};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tonic::transport::Channel;
use tonic::{Code, Status};

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub max_in_flight: usize,
    /// Attempts per call, including the first.
    pub attempts: u32,
    pub backoff: Duration,
    pub deadline: Duration,
    pub breaker_threshold: u32,
    pub breaker_cooldown: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        BridgeConfig {
            max_in_flight: 256,
            attempts: 3,
            backoff: Duration::from_millis(50),
            deadline: Duration::from_secs(5),
            breaker_threshold: 5,
            breaker_cooldown: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub enum BridgeError {
    /// The breaker is open: the core was not called.
    CircuitOpen,
    Core(Status),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::CircuitOpen => write!(f, "core circuit open"),
            BridgeError::Core(s) => write!(f, "core: {} {}", s.code(), s.message()),
        }
    }
}

impl std::error::Error for BridgeError {}

#[derive(Debug, Default)]
struct Breaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
    probing: bool,
}

#[derive(Default)]
pub struct BridgeStats {
    pub calls_total: AtomicU64,
    pub retries_total: AtomicU64,
    pub failures_total: AtomicU64,
    pub short_circuited_total: AtomicU64,
    pub breaker_opened_total: AtomicU64,
}

pub struct GrpcBridge {
    client: PaymentCommandServiceClient<Channel>,
    cfg: BridgeConfig,
    slots: Semaphore,
    breaker: Mutex<Breaker>,
    pub stats: BridgeStats,
}

fn retryable(code: Code) -> bool {
    matches!(code, Code::Unavailable | Code::DeadlineExceeded)
}

/// W3C traceparent for a 32-hex trace id; the span id is derived from the idempotency key so retries share it.
pub fn traceparent(trace_id: &str, idempotency_key: &str) -> Option<String> {
    let valid = trace_id.len() == 32 && trace_id.bytes().all(|b| b.is_ascii_hexdigit()) && trace_id.bytes().any(|b| b != b'0');
    if !valid {
        return None;
    }
    // FNV-1a, 64 bit: stable across processes (std's hasher is randomly seeded).
    let mut h: u64 = 0xcbf29ce484222325;
    for b in idempotency_key.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    Some(format!("00-{}-{:016x}-01", trace_id.to_ascii_lowercase(), h.max(1)))
}

impl GrpcBridge {
    pub fn new(client: PaymentCommandServiceClient<Channel>, cfg: BridgeConfig) -> Self {
        GrpcBridge { client, slots: Semaphore::new(cfg.max_in_flight.max(1)), cfg, breaker: Mutex::new(Breaker::default()), stats: BridgeStats::default() }
    }

    pub fn breaker_open(&self) -> bool {
        self.breaker.lock().unwrap().open_until.is_some()
    }

    /// Ok(()) if a call may go to the core now.
    fn admit(&self) -> Result<(), BridgeError> {
        let mut b = self.breaker.lock().unwrap();
        match b.open_until {
            None => Ok(()),
            Some(until) if Instant::now() >= until && !b.probing => {
                b.probing = true; // half-open: this call is the probe
                Ok(())
            }
            Some(_) => Err(BridgeError::CircuitOpen),
        }
    }

    fn record(&self, ok: bool) {
        let mut b = self.breaker.lock().unwrap();
        if ok {
            *b = Breaker::default();
            return;
        }
        b.consecutive_failures += 1;
        if b.probing || b.consecutive_failures >= self.cfg.breaker_threshold {
            if b.open_until.is_none() {
                self.stats.breaker_opened_total.fetch_add(1, Relaxed);
            }
            b.open_until = Some(Instant::now() + self.cfg.breaker_cooldown);
            b.probing = false;
        }
    }

    pub async fn submit(&self, request: SubmitPaymentRequest) -> Result<SubmitPaymentResponse, BridgeError> {
        if let Err(e) = self.admit() {
            self.stats.short_circuited_total.fetch_add(1, Relaxed);
            return Err(e);
        }
        let _slot = self.slots.acquire().await.expect("semaphore never closed");
        self.stats.calls_total.fetch_add(1, Relaxed);
        let trace = traceparent(&request.trace_id, &request.idempotency_key);
        let key = request.idempotency_key.clone();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut req = tonic::Request::new(request.clone());
            req.set_timeout(self.cfg.deadline);
            if let Some(Ok(v)) = trace.as_deref().map(str::parse) {
                req.metadata_mut().insert("traceparent", v);
            }
            if let Ok(v) = key.parse() {
                req.metadata_mut().insert("x-difme-idempotency-key", v);
            }
            match self.client.clone().submit_payment(req).await {
                Ok(r) => {
                    self.record(true);
                    return Ok(r.into_inner());
                }
                Err(s) if retryable(s.code()) && attempt < self.cfg.attempts => {
                    self.stats.retries_total.fetch_add(1, Relaxed);
                    tokio::time::sleep(self.cfg.backoff * 2u32.pow(attempt - 1)).await;
                }
                Err(s) => {
                    // Only transport-level trouble counts against the core's health; a business refusal does not.
                    self.record(!retryable(s.code()));
                    self.stats.failures_total.fetch_add(1, Relaxed);
                    return Err(BridgeError::Core(s));
                }
            }
        }
    }

    pub fn render_metrics(&self) -> String {
        format!(
            "# TYPE difme_hub_bridge_calls_total counter\ndifme_hub_bridge_calls_total {}\n\
             # TYPE difme_hub_bridge_retries_total counter\ndifme_hub_bridge_retries_total {}\n\
             # TYPE difme_hub_bridge_failures_total counter\ndifme_hub_bridge_failures_total {}\n\
             # TYPE difme_hub_bridge_short_circuited_total counter\ndifme_hub_bridge_short_circuited_total {}\n\
             # TYPE difme_hub_bridge_breaker_opened_total counter\ndifme_hub_bridge_breaker_opened_total {}\n\
             # TYPE difme_hub_bridge_breaker_open gauge\ndifme_hub_bridge_breaker_open {}\n",
            self.stats.calls_total.load(Relaxed),
            self.stats.retries_total.load(Relaxed),
            self.stats.failures_total.load(Relaxed),
            self.stats.short_circuited_total.load(Relaxed),
            self.stats.breaker_opened_total.load(Relaxed),
            self.breaker_open() as u8,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::traceparent;

    #[test]
    fn traceparent_from_trace_id() {
        let t = traceparent("4BF92F3577B34DA6A3CE929D0E0E4736", "key-1").unwrap();
        assert!(t.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-") && t.ends_with("-01") && t.len() == 55, "{t}");
        assert_eq!(t, traceparent("4bf92f3577b34da6a3ce929d0e0e4736", "key-1").unwrap(), "stable for retries");
        assert_ne!(t, traceparent("4bf92f3577b34da6a3ce929d0e0e4736", "key-2").unwrap());
        assert_eq!(traceparent("", "k"), None);
        assert_eq!(traceparent("00000000000000000000000000000000", "k"), None, "all-zero ids are invalid");
        assert_eq!(traceparent("xyz", "k"), None);
    }
}
