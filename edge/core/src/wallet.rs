//! Offline-first wallet state as an automerge document carrying the escrow ("bounded counter") CRDT verified in
//! specs/tla/CrdtMerge.tla (ADR-016).
//!
//! Document layout (all amounts in minor units):
//!
//! ```text
//! ROOT
//!   wallet_id: str          currency: str        limit: int    (genesis, written once by the hub)
//!   balance: int            ledger balance last confirmed by the hub (last-writer-wins, hub-only)
//!   spent:   { replica -> counter }               spent[r] is written only by r
//!   xfer:    { from -> { to -> counter } }        xfer[a][b] is written only by a (rights a granted to b)
//!   payments:{ id -> { payer, payee, amount, currency, created_ms, status, intent_b3, intent_cose, base_heads } }
//! ```
//!
//! Every counter has exactly one writer, so automerge's counter merge (sum of distinct increments, idempotent on
//! re-delivery) equals the spec's pointwise max. A replica may spend or grant only what `Rights` shows from its own
//! view, which is what keeps total spend under `limit` while partitioned (`NoOverspend` in the spec).
//!
//! All replicas start from the same deterministic genesis change (fixed actor and timestamp), so the shared maps are
//! one object everywhere instead of concurrent creations that would shadow each other.

use crate::{Error, integrity};
use automerge::transaction::{CommitOptions, Transactable};
use automerge::{ActorId, AutoCommit, ChangeHash, ObjId, ObjType, ROOT, ReadDoc, ScalarValue, Value};
use serde::Serialize;

pub const HUB: &str = "hub";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    /// Signed offline, not yet acknowledged by the hub.
    Pending,
    Accepted,
    Duplicate,
    RejectedFraud,
    RejectedRateLimit,
}

impl PaymentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Accepted => "ACCEPTED",
            Self::Duplicate => "DUPLICATE",
            Self::RejectedFraud => "REJECTED_FRAUD",
            Self::RejectedRateLimit => "REJECTED_RATE_LIMIT",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Pending, Self::Accepted, Self::Duplicate, Self::RejectedFraud, Self::RejectedRateLimit].into_iter().find(|v| v.as_str() == s)
    }

    /// Conflict resolution for concurrent status writes (e.g. the device and a hub mirror both record an outcome):
    /// a settled outcome beats a rejection, which beats pending. Deterministic on every replica, unlike automerge's
    /// arbitrary-but-consistent pick, and it never moves a settled payment back to pending.
    fn rank(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::RejectedRateLimit => 1,
            Self::RejectedFraud => 2,
            Self::Duplicate => 3,
            Self::Accepted => 4,
        }
    }

    pub fn is_final(self) -> bool {
        self != Self::Pending
    }
}

/// A payment as stored in the CRDT.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRecord {
    pub id: String,
    pub payer: String,
    pub payee: String,
    pub amount_minor: i64,
    pub currency: String,
    pub created_ms: i64,
    pub status: PaymentStatus,
    /// Blake3 of the canonical intent (hex); the EAT carries the same digest.
    pub intent_b3: String,
    /// The COSE_Sign1 intent the TEE signed.
    #[serde(skip)]
    pub intent_cose: Vec<u8>,
    /// True when replicas wrote different statuses concurrently (resolved by `PaymentStatus::rank`).
    pub status_conflict: bool,
}

pub struct Wallet {
    doc: AutoCommit,
    replica: String,
}

fn commit(doc: &mut AutoCommit, message: &str) {
    doc.commit_with(CommitOptions::default().with_message(message.to_string()).with_time(now_ms() / 1000));
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn int(v: &Value<'_>) -> Option<i64> {
    match v {
        Value::Scalar(s) => s.as_i64(),
        _ => None,
    }
}

impl Wallet {
    /// The deterministic genesis document for a wallet: the same bytes on the hub and on every device.
    pub fn genesis(wallet_id: &str, currency: &str, limit_minor: i64) -> Vec<u8> {
        let digest = blake3::hash(format!("difme-genesis:{wallet_id}").as_bytes());
        let mut doc = AutoCommit::new().with_actor(ActorId::from(&digest.as_bytes()[..16]));
        doc.put(ROOT, "wallet_id", wallet_id).expect("root put");
        doc.put(ROOT, "currency", currency).expect("root put");
        doc.put(ROOT, "limit", limit_minor).expect("root put");
        doc.put(ROOT, "balance", 0i64).expect("root put");
        for key in ["spent", "xfer", "payments"] {
            doc.put_object(ROOT, key, ObjType::Map).expect("root map");
        }
        doc.commit_with(CommitOptions::default().with_message("genesis".to_string()).with_time(0));
        doc.save()
    }

    /// Opens a saved document (or a genesis) as `replica` ("hub" or a device id). Each open uses a fresh random
    /// actor, so a reinstalled device can never reuse sequence numbers of changes it lost.
    pub fn open(bytes: &[u8], replica: &str) -> Result<Self, Error> {
        let doc = AutoCommit::load(bytes)?;
        let w = Wallet { doc, replica: replica.to_string() };
        w.map("spent")?;
        w.map("xfer")?;
        w.map("payments")?;
        Ok(w)
    }

    pub fn replica(&self) -> &str {
        &self.replica
    }

    fn map(&self, key: &str) -> Result<ObjId, Error> {
        match self.doc.get(ROOT, key)? {
            Some((Value::Object(ObjType::Map), id)) => Ok(id),
            _ => Err(Error::Wallet(format!("document has no '{key}' map; not a wallet"))),
        }
    }

    fn root_str(&self, key: &str) -> String {
        match self.doc.get(ROOT, key) {
            Ok(Some((Value::Scalar(s), _))) => s.as_str().unwrap_or_default().to_string(),
            _ => String::new(),
        }
    }

    pub fn wallet_id(&self) -> String {
        self.root_str("wallet_id")
    }

    pub fn currency(&self) -> String {
        self.root_str("currency")
    }

    pub fn limit(&self) -> i64 {
        self.doc.get(ROOT, "limit").ok().flatten().and_then(|(v, _)| int(&v)).unwrap_or(0)
    }

    /// Ledger balance last confirmed by the hub.
    pub fn ledger_balance(&self) -> i64 {
        self.doc.get(ROOT, "balance").ok().flatten().and_then(|(v, _)| int(&v)).unwrap_or(0)
    }

    pub fn set_ledger_balance(&mut self, minor: i64) -> Result<(), Error> {
        if self.replica != HUB {
            return Err(Error::Wallet("only the hub confirms the ledger balance".into()));
        }
        self.doc.put(ROOT, "balance", minor)?;
        commit(&mut self.doc, "balance");
        Ok(())
    }

    fn counter(&self, obj: &ObjId, key: &str) -> i64 {
        self.doc.get(obj, key).ok().flatten().and_then(|(v, _)| int(&v)).unwrap_or(0)
    }

    pub fn spent(&self, replica: &str) -> i64 {
        self.map("spent").map(|m| self.counter(&m, replica)).unwrap_or(0)
    }

    /// Rights granted from `from` to `to`, as this replica has seen them.
    pub fn transferred(&self, from: &str, to: &str) -> i64 {
        let Ok(xfer) = self.map("xfer") else { return 0 };
        match self.doc.get(&xfer, from) {
            Ok(Some((Value::Object(ObjType::Map), m))) => self.counter(&m, to),
            _ => 0,
        }
    }

    /// `Rights(r)` from the spec, judged from this replica's view.
    pub fn rights(&self, replica: &str) -> i64 {
        let Ok(xfer) = self.map("xfer") else { return 0 };
        let alloc = if replica == HUB { self.limit() } else { 0 };
        let mut incoming = 0;
        let mut outgoing = 0;
        for from in self.doc.keys(&xfer) {
            if let Ok(Some((Value::Object(ObjType::Map), m))) = self.doc.get(&xfer, from.as_str()) {
                for to in self.doc.keys(&m) {
                    let n = self.counter(&m, &to);
                    if to == replica { incoming += n; }
                    if from == replica { outgoing += n; }
                }
            }
        }
        alloc + incoming - outgoing - self.spent(replica)
    }

    /// Sum of every replica's own spend entry (`TotalSpent` in the spec).
    pub fn total_spent(&self) -> i64 {
        let Ok(spent) = self.map("spent") else { return 0 };
        self.doc.keys(&spent).map(|k| self.counter(&spent, &k)).sum()
    }

    fn bump(&mut self, obj: &ObjId, key: &str, by: i64) -> Result<(), Error> {
        if self.doc.get(obj, key)?.is_none() {
            self.doc.put(obj, key, ScalarValue::counter(0))?;
        }
        self.doc.increment(obj, key, by)?;
        Ok(())
    }

    /// Grants `amount` of this replica's rights to `to` (`Grant` in the spec).
    pub fn grant(&mut self, to: &str, amount: i64) -> Result<(), Error> {
        if amount <= 0 || to == self.replica {
            return Err(Error::Wallet("a grant needs a positive amount and another replica".into()));
        }
        if self.rights(&self.replica) < amount {
            return Err(Error::InsufficientRights { needed: amount, held: self.rights(&self.replica) });
        }
        let xfer = self.map("xfer")?;
        let mine = match self.doc.get(&xfer, self.replica.as_str())? {
            Some((Value::Object(ObjType::Map), m)) => m,
            _ => self.doc.put_object(&xfer, self.replica.as_str(), ObjType::Map)?,
        };
        self.bump(&mine, to, amount)?;
        commit(&mut self.doc, "grant");
        Ok(())
    }

    /// Records an offline payment this replica signed (`Spend` in the spec). Fails without enough rights, leaving
    /// the document unchanged.
    pub fn record_payment(&mut self, intent: &crate::tee::PaymentIntent, intent_cose: &[u8]) -> Result<(), Error> {
        if intent.payer != self.replica {
            return Err(Error::Wallet("a replica records only its own payments".into()));
        }
        if intent.currency != self.currency() {
            return Err(Error::Wallet(format!("wallet is {}, payment is {}", self.currency(), intent.currency)));
        }
        let held = self.rights(&self.replica);
        if intent.amount_minor <= 0 || held < intent.amount_minor {
            return Err(Error::InsufficientRights { needed: intent.amount_minor, held });
        }
        let payments = self.map("payments")?;
        if self.doc.get(&payments, intent.id.as_str())?.is_some() {
            return Err(Error::Wallet(format!("payment {} already recorded", intent.id)));
        }
        let base_heads: Vec<String> = self.doc.get_heads().iter().map(|h| h.to_string()).collect();
        let spent = self.map("spent")?;
        let replica = self.replica.clone();
        self.bump(&spent, &replica, intent.amount_minor)?;
        let p = self.doc.put_object(&payments, intent.id.as_str(), ObjType::Map)?;
        self.doc.put(&p, "payer", intent.payer.as_str())?;
        self.doc.put(&p, "payee", intent.payee.as_str())?;
        self.doc.put(&p, "amount", intent.amount_minor)?;
        self.doc.put(&p, "currency", intent.currency.as_str())?;
        self.doc.put(&p, "created_ms", intent.created_ms)?;
        self.doc.put(&p, "status", PaymentStatus::Pending.as_str())?;
        self.doc.put(&p, "intent_b3", intent.digest_hex().as_str())?;
        self.doc.put(&p, "intent_cose", ScalarValue::Bytes(intent_cose.to_vec()))?;
        self.doc.put(&p, "base_heads", base_heads.join(",").as_str())?;
        commit(&mut self.doc, "payment");
        Ok(())
    }

    pub fn set_status(&mut self, id: &str, status: PaymentStatus) -> Result<(), Error> {
        let payments = self.map("payments")?;
        let Some((Value::Object(ObjType::Map), p)) = self.doc.get(&payments, id)? else {
            return Err(Error::Wallet(format!("no payment {id}")));
        };
        self.doc.put(&p, "status", status.as_str())?;
        commit(&mut self.doc, "status");
        Ok(())
    }

    fn read_payment(&self, id: &str, p: &ObjId) -> Option<PaymentRecord> {
        let s = |k: &str| match self.doc.get(p, k) {
            Ok(Some((Value::Scalar(v), _))) => v.as_str().map(str::to_string),
            _ => None,
        };
        let statuses: Vec<PaymentStatus> = self.doc.get_all(p, "status").ok()?.iter()
            .filter_map(|(v, _)| match v { Value::Scalar(s) => s.as_str().and_then(PaymentStatus::parse), _ => None })
            .collect();
        let status = statuses.iter().copied().max_by_key(|s| s.rank())?;
        let intent_cose = match self.doc.get(p, "intent_cose") {
            Ok(Some((Value::Scalar(v), _))) => v.as_bytes().map(<[u8]>::to_vec).unwrap_or_default(),
            _ => Vec::new(),
        };
        Some(PaymentRecord {
            id: id.to_string(),
            payer: s("payer")?,
            payee: s("payee")?,
            amount_minor: self.doc.get(p, "amount").ok()??.0.as_i64()?,
            currency: s("currency")?,
            created_ms: self.doc.get(p, "created_ms").ok()??.0.as_i64()?,
            status,
            intent_b3: s("intent_b3").unwrap_or_default(),
            intent_cose,
            status_conflict: statuses.len() > 1,
        })
    }

    pub fn payment(&self, id: &str) -> Option<PaymentRecord> {
        let payments = self.map("payments").ok()?;
        match self.doc.get(&payments, id).ok()? {
            Some((Value::Object(ObjType::Map), p)) => self.read_payment(id, &p),
            _ => None,
        }
    }

    /// All payments, oldest first (UUIDv7 ids sort by creation time).
    pub fn payments(&self) -> Vec<PaymentRecord> {
        let Ok(payments) = self.map("payments") else { return Vec::new() };
        let ids: Vec<String> = self.doc.keys(&payments).collect();
        ids.iter().filter_map(|id| self.payment(id)).collect()
    }

    pub fn pending(&self, payer: &str) -> Vec<PaymentRecord> {
        self.payments().into_iter().filter(|p| p.payer == payer && p.status == PaymentStatus::Pending).collect()
    }

    /// Offline spend not yet acknowledged by the hub: the cumulative figure the offline-limit rule checks.
    pub fn offline_spent(&self, payer: &str) -> i64 {
        self.pending(payer).iter().map(|p| p.amount_minor).sum()
    }

    /// The automerge changes that recorded payment `id` (and anything after them): the `crdt_delta` the hub forwards
    /// to the rehydration service. Empty when it would not fit comfortably in one hub frame.
    pub fn delta_for(&mut self, id: &str) -> Vec<u8> {
        let Ok(payments) = self.map("payments") else { return Vec::new() };
        let heads: Vec<ChangeHash> = match self.doc.get(&payments, id) {
            Ok(Some((Value::Object(ObjType::Map), p))) => match self.doc.get(&p, "base_heads") {
                Ok(Some((Value::Scalar(v), _))) => v.as_str().unwrap_or_default().split(',').filter_map(|h| h.parse().ok()).collect(),
                _ => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        let delta = self.doc.save_after(&heads);
        if delta.len() > 32 * 1024 { Vec::new() } else { delta }
    }

    pub fn heads(&mut self) -> Vec<ChangeHash> {
        self.doc.get_heads()
    }

    /// Merges another replica's state (`Sync` in the spec). Idempotent, commutative and associative.
    pub fn merge(&mut self, other: &mut Wallet) -> Result<(), Error> {
        self.doc.merge(&mut other.doc)?;
        Ok(())
    }

    /// Applies changes received from elsewhere (a delta or a full save).
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.doc.load_incremental(bytes)?;
        Ok(())
    }

    /// Runs the automerge sync protocol between two replicas until both have everything. This is the exchange the
    /// proposed hub extension (`difme-sync/1`, see edge/README.md) carries; in-process here for tests and the demo.
    pub fn sync_with(&mut self, other: &mut Wallet) -> Result<usize, Error> {
        use automerge::sync::{State, SyncDoc};
        let (mut sa, mut sb) = (State::new(), State::new());
        let mut rounds = 0;
        loop {
            let a = self.doc.sync().generate_sync_message(&mut sa);
            if let Some(m) = &a { other.doc.sync().receive_sync_message(&mut sb, m.clone())?; }
            let b = other.doc.sync().generate_sync_message(&mut sb);
            if let Some(m) = &b { self.doc.sync().receive_sync_message(&mut sa, m.clone())?; }
            if a.is_none() && b.is_none() { return Ok(rounds); }
            rounds += 1;
            if rounds > 64 { return Err(Error::Wallet("sync did not converge".into())); }
        }
    }

    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Document bytes sealed with a Blake3 digest, for storage.
    pub fn save_sealed(&mut self) -> Vec<u8> {
        integrity::seal(&self.doc.save())
    }

    pub fn open_sealed(blob: &[u8], replica: &str) -> Result<Self, Error> {
        Self::open(integrity::unseal(blob)?, replica)
    }
}
