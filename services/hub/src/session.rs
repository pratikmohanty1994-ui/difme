//! Session manager. One session per device QUIC connection: admission (a global cap and an optional per-address cap),
//! per-session activity counters for `/v1/sessions` and the dashboards, and coalescing of in-flight payments by
//! idempotency key.
//!
//! Coalescing matters because devices retry: when the hub resets a stream (core unavailable) or a link flaps, the
//! device resends the same payment, possibly on a new connection, while the first attempt is still waiting for the
//! core. The second attempt then waits for the first one's answer instead of sending the core a second command.
//! (The core is idempotent too; this keeps duplicate load off it and gives both attempts the same answer.)

use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Connections the hub admits in total.
    pub max_sessions: usize,
    /// Connections from one IP address; 0 = no per-address cap. Behind a QUIC relay (scenario D) or a NAT every device
    /// shares the relay's address, so this stays 0 there.
    pub max_per_ip: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { max_sessions: 10_000, max_per_ip: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    HubFull,
    AddressFull,
}

impl Refused {
    /// QUIC application close code sent to the device.
    pub fn code(self) -> u32 {
        match self {
            Refused::HubFull => 0x10,
            Refused::AddressFull => 0x11,
        }
    }
    pub fn reason(self) -> &'static [u8] {
        match self {
            Refused::HubFull => b"hub at session capacity",
            Refused::AddressFull => b"too many sessions from this address",
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// What a device's session has done so far.
pub struct Session {
    pub id: u64,
    pub remote: SocketAddr,
    pub opened_ms: u64,
    pub last_seen_ms: AtomicU64,
    pub payments: AtomicU64,
    pub telemetry_records: AtomicU64,
}

impl Session {
    pub fn touch(&self) {
        self.last_seen_ms.store(now_ms(), Relaxed);
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    pub id: u64,
    pub remote: String,
    pub opened_ms: u64,
    pub last_seen_ms: u64,
    pub payments: u64,
    pub telemetry_records: u64,
}

/// The shared outcome of one in-flight payment: the encoded `SubmitPaymentResponse`, or the error text.
pub type Outcome = Result<Vec<u8>, String>;

#[derive(Default)]
struct Inner {
    sessions: HashMap<u64, Arc<Session>>,
    per_ip: HashMap<IpAddr, usize>,
}

pub struct SessionManager {
    cfg: SessionConfig,
    inner: Mutex<Inner>,
    inflight: Mutex<HashMap<String, watch::Receiver<Option<Outcome>>>>,
    next_id: AtomicU64,
    pub opened_total: AtomicU64,
    pub refused_total: AtomicU64,
    pub coalesced_total: AtomicU64,
}

/// Removes the session when the connection ends (dropped with the connection task).
pub struct SessionGuard {
    manager: Arc<SessionManager>,
    pub session: Arc<Session>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut inner = self.manager.inner.lock().unwrap();
        inner.sessions.remove(&self.session.id);
        let ip = self.session.remote.ip();
        if let Some(n) = inner.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                inner.per_ip.remove(&ip);
            }
        }
    }
}

/// Either this caller sends the payment (and must `complete` the claim) or it waits for the caller that already is.
pub enum Claim {
    Leader(LeaderClaim),
    Follower(watch::Receiver<Option<Outcome>>),
}

pub struct LeaderClaim {
    manager: Arc<SessionManager>,
    key: String,
    tx: Option<watch::Sender<Option<Outcome>>>,
}

impl LeaderClaim {
    pub fn complete(mut self, outcome: Outcome) {
        self.finish(outcome);
    }
    fn finish(&mut self, outcome: Outcome) {
        if let Some(tx) = self.tx.take() {
            self.manager.inflight.lock().unwrap().remove(&self.key);
            let _ = tx.send(Some(outcome));
        }
    }
}

impl Drop for LeaderClaim {
    /// A leader that goes away without an answer (task cancelled) releases its followers with an error; they reset
    /// their streams and the devices retry.
    fn drop(&mut self) {
        self.finish(Err("abandoned".into()));
    }
}

impl SessionManager {
    pub fn new(cfg: SessionConfig) -> Arc<Self> {
        Arc::new(SessionManager {
            cfg,
            inner: Mutex::new(Inner::default()),
            inflight: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            opened_total: AtomicU64::new(0),
            refused_total: AtomicU64::new(0),
            coalesced_total: AtomicU64::new(0),
        })
    }

    pub fn open(self: &Arc<Self>, remote: SocketAddr) -> Result<SessionGuard, Refused> {
        let mut inner = self.inner.lock().unwrap();
        if inner.sessions.len() >= self.cfg.max_sessions {
            self.refused_total.fetch_add(1, Relaxed);
            return Err(Refused::HubFull);
        }
        let from_ip = inner.per_ip.get(&remote.ip()).copied().unwrap_or(0);
        if self.cfg.max_per_ip > 0 && from_ip >= self.cfg.max_per_ip {
            self.refused_total.fetch_add(1, Relaxed);
            return Err(Refused::AddressFull);
        }
        let now = now_ms();
        let session = Arc::new(Session {
            id: self.next_id.fetch_add(1, Relaxed) + 1,
            remote,
            opened_ms: now,
            last_seen_ms: AtomicU64::new(now),
            payments: AtomicU64::new(0),
            telemetry_records: AtomicU64::new(0),
        });
        inner.sessions.insert(session.id, session.clone());
        *inner.per_ip.entry(remote.ip()).or_default() += 1;
        self.opened_total.fetch_add(1, Relaxed);
        Ok(SessionGuard { manager: self.clone(), session })
    }

    pub fn active(&self) -> usize {
        self.inner.lock().unwrap().sessions.len()
    }

    /// Sessions ordered by id, for `/v1/sessions`.
    pub fn snapshot(&self) -> Vec<SessionView> {
        let inner = self.inner.lock().unwrap();
        let mut v: Vec<_> = inner
            .sessions
            .values()
            .map(|s| SessionView {
                id: s.id,
                remote: s.remote.to_string(),
                opened_ms: s.opened_ms,
                last_seen_ms: s.last_seen_ms.load(Relaxed),
                payments: s.payments.load(Relaxed),
                telemetry_records: s.telemetry_records.load(Relaxed),
            })
            .collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// Claims the payment with `idempotency_key`. An empty key is never coalesced.
    pub fn claim(self: &Arc<Self>, idempotency_key: &str) -> Claim {
        let mut inflight = self.inflight.lock().unwrap();
        if !idempotency_key.is_empty() {
            if let Some(rx) = inflight.get(idempotency_key) {
                self.coalesced_total.fetch_add(1, Relaxed);
                return Claim::Follower(rx.clone());
            }
        }
        let (tx, rx) = watch::channel(None);
        if !idempotency_key.is_empty() {
            inflight.insert(idempotency_key.to_string(), rx);
        }
        Claim::Leader(LeaderClaim { manager: self.clone(), key: idempotency_key.to_string(), tx: Some(tx) })
    }

    pub fn in_flight(&self) -> usize {
        self.inflight.lock().unwrap().len()
    }
}

/// Waits for a leader's outcome.
pub async fn wait(mut rx: watch::Receiver<Option<Outcome>>) -> Outcome {
    match rx.wait_for(|o| o.is_some()).await {
        Ok(o) => o.clone().unwrap_or_else(|| Err("abandoned".into())),
        Err(_) => Err("abandoned".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admission_caps_and_release_on_drop() {
        let m = SessionManager::new(SessionConfig { max_sessions: 3, max_per_ip: 2 });
        let a = m.open(addr("10.0.0.1:1")).unwrap();
        let _b = m.open(addr("10.0.0.1:2")).unwrap();
        assert_eq!(m.open(addr("10.0.0.1:3")).err(), Some(Refused::AddressFull));
        let _c = m.open(addr("10.0.0.2:1")).unwrap();
        assert_eq!(m.open(addr("10.0.0.3:1")).err(), Some(Refused::HubFull));
        assert_eq!(m.active(), 3);
        drop(a);
        assert_eq!(m.active(), 2);
        assert!(m.open(addr("10.0.0.1:4")).is_ok(), "the address slot is free again");
        assert_eq!(m.refused_total.load(Relaxed), 2);
        let ids: Vec<_> = m.snapshot().iter().map(|s| s.id).collect();
        assert_eq!(ids, vec![2, 3], "the last open was dropped at the end of the statement");
    }

    #[test]
    fn per_ip_zero_means_unlimited() {
        let m = SessionManager::new(SessionConfig { max_sessions: 100, max_per_ip: 0 });
        let guards: Vec<_> = (0..50).map(|p| m.open(addr(&format!("10.0.0.9:{}", p + 1))).unwrap()).collect();
        assert_eq!(m.active(), guards.len());
    }

    #[tokio::test]
    async fn followers_get_the_leaders_outcome() {
        let m = SessionManager::new(SessionConfig::default());
        let Claim::Leader(leader) = m.claim("k1") else { panic!("first claim leads") };
        let Claim::Follower(f1) = m.claim("k1") else { panic!("second claim follows") };
        let Claim::Follower(f2) = m.claim("k1") else { panic!("third claim follows") };
        assert!(matches!(m.claim("k2"), Claim::Leader(_)), "other keys are independent");
        let waiter = tokio::spawn(wait(f1));
        leader.complete(Ok(vec![1, 2, 3]));
        assert_eq!(waiter.await.unwrap(), Ok(vec![1, 2, 3]));
        assert_eq!(wait(f2).await, Ok(vec![1, 2, 3]), "a late follower still sees the outcome");
        assert_eq!(m.coalesced_total.load(Relaxed), 2);
        assert!(matches!(m.claim("k1"), Claim::Leader(_)), "a finished key can be claimed again (a later retry)");
    }

    #[tokio::test]
    async fn abandoned_leader_releases_followers() {
        let m = SessionManager::new(SessionConfig::default());
        let leader = m.claim("k");
        let Claim::Follower(f) = m.claim("k") else { panic!() };
        drop(leader);
        assert_eq!(wait(f).await, Err("abandoned".into()));
        assert_eq!(m.in_flight(), 0);
        assert!(matches!(m.claim(""), Claim::Leader(_)) && matches!(m.claim(""), Claim::Leader(_)), "empty keys never coalesce");
    }
}
