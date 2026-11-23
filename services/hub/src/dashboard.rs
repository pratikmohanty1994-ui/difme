//! Live dashboard relay. Everything the hub observes (payment outcomes, device telemetry, session changes) is published
//! once to a topic; browsers subscribe over server-sent events at `/v1/events` and pick topics with `?topics=a,b`.
//!
//! Every event carries a sequence id. The relay keeps the last `replay` events in a ring, so a dashboard that
//! reconnects with `Last-Event-ID` (browsers send it automatically) gets what it missed instead of a gap. A
//! subscriber that falls behind the live channel is told so with a `lagged` event and skips ahead; it never holds
//! memory on the hub.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt};

pub const TOPIC_PAYMENTS: &str = "payments";
pub const TOPIC_TELEMETRY: &str = "telemetry";
pub const TOPIC_SESSIONS: &str = "sessions";
/// Sent (without an id) to a subscriber that missed live events because it read too slowly.
pub const TOPIC_LAGGED: &str = "lagged";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardEvent {
    /// Sequence id, starting at 1; 0 only for the synthetic `lagged` notice.
    pub id: u64,
    pub topic: &'static str,
    /// JSON object.
    pub data: String,
}

pub struct DashboardRelay {
    live: broadcast::Sender<Arc<DashboardEvent>>,
    ring: Mutex<VecDeque<Arc<DashboardEvent>>>,
    replay: usize,
    seq: AtomicU64,
    pub published_total: AtomicU64,
}

impl DashboardRelay {
    /// `replay`: events kept for reconnecting subscribers; the live channel holds the same number.
    pub fn new(replay: usize) -> Self {
        let replay = replay.max(1);
        let (live, _) = broadcast::channel(replay);
        DashboardRelay { live, ring: Mutex::new(VecDeque::with_capacity(replay)), replay, seq: AtomicU64::new(0), published_total: AtomicU64::new(0) }
    }

    pub fn subscribers(&self) -> usize {
        self.live.receiver_count()
    }

    /// Publishes `data` (a JSON object) on `topic` and returns its id.
    pub fn publish(&self, topic: &'static str, data: String) -> u64 {
        // The id is taken under the ring lock so the ring stays ordered and a subscriber's replay/live hand-over is exact.
        let mut ring = self.ring.lock().unwrap();
        let id = self.seq.fetch_add(1, Relaxed) + 1;
        let ev = Arc::new(DashboardEvent { id, topic, data });
        if ring.len() == self.replay {
            ring.pop_front();
        }
        ring.push_back(ev.clone());
        let _ = self.live.send(ev);
        drop(ring);
        self.published_total.fetch_add(1, Relaxed);
        id
    }

    /// Events after `last_event_id` (if given and still in the ring), then live events; filtered by `topics`
    /// (None = all).
    pub fn subscribe(&self, topics: Option<HashSet<String>>, last_event_id: Option<u64>) -> impl Stream<Item = Arc<DashboardEvent>> + Send + use<> {
        // Subscribe before reading the ring, under the same lock that orders publishes: every event is then either in
        // the backlog snapshot or (with a higher id) on the live receiver, never lost and never doubled.
        let (rx, backlog, high) = {
            let ring = self.ring.lock().unwrap();
            let rx = self.live.subscribe();
            let backlog: Vec<_> = match last_event_id {
                Some(last) => ring.iter().filter(|e| e.id > last).cloned().collect(),
                None => Vec::new(),
            };
            (rx, backlog, ring.back().map(|e| e.id).unwrap_or(0))
        };
        let wanted = move |e: &DashboardEvent| e.topic == TOPIC_LAGGED || topics.as_ref().is_none_or(|t| t.contains(e.topic));
        let live = BroadcastStream::new(rx).filter_map(move |m| match m {
            Ok(e) if e.id <= high => None,
            Ok(e) => Some(e),
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                Some(Arc::new(DashboardEvent { id: 0, topic: TOPIC_LAGGED, data: format!(r#"{{"missed":{n}}}"#) }))
            }
        });
        tokio_stream::iter(backlog).chain(live).filter(move |e| wanted(e))
    }
}
