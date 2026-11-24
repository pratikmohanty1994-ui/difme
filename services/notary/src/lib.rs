//! Independent witness for evidence chains (decided 2026-11-20: the witness is a separate notary service with its own
//! key, never the operator). It signs the raw 32 bytes of a sealed chain's last-artifact hash, exactly as the operator
//! does, and records every hash it witnessed with the time, so a third party can later ask "did you see this, when?".
//!
//! API: GET /v1/key -> {"name", "publicKey": base64 raw 32 bytes}; POST /v1/witness {"hash": hex64} -> {"signature",
//! "witnessedAtMs"}; GET /v1/witnessed/{hash} -> the record or 404; GET /healthz.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
pub mod keyrelease;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub hash: String,
    pub signature: String,
    pub witnessed_at_ms: u64,
}

/// Bounded in-memory index of recent records (the append-only log file is the durable copy).
struct Index {
    by_hash: HashMap<String, Record>,
    order: VecDeque<String>,
    cap: usize,
}

pub struct Notary {
    name: String,
    key: SigningKey,
    index: Mutex<Index>,
    /// Serialises check, log and record, so a hash is signed once even under concurrent requests.
    write: tokio::sync::Mutex<Option<tokio::fs::File>>,
}

impl Notary {
    pub fn new(name: String, seed: [u8; 32], cap: usize, log: Option<tokio::fs::File>) -> Arc<Self> {
        Arc::new(Self {
            name,
            key: SigningKey::from_bytes(&seed),
            index: Mutex::new(Index { by_hash: HashMap::new(), order: VecDeque::new(), cap: cap.max(1) }),
            write: tokio::sync::Mutex::new(log),
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Witnesses a hash once: a repeated request returns the first record, so the time can't be moved forward.
    pub async fn witness(&self, hash_hex: &str) -> Result<Record, &'static str> {
        let hash = hash_hex.to_ascii_lowercase();
        let raw = hex::decode(&hash).map_err(|_| "hash must be hex")?;
        if raw.len() != 32 {
            return Err("hash must be 32 bytes (SHA-256)");
        }
        let mut write = self.write.lock().await;
        if let Some(r) = self.index.lock().unwrap().by_hash.get(&hash) {
            return Ok(r.clone());
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        let rec = Record { hash: hash.clone(), signature: B64.encode(self.key.sign(&raw).to_bytes()), witnessed_at_ms: now };
        if let Some(f) = write.as_mut() {
            // The durable record is written before the answer: a signature the log doesn't hold is never handed out.
            let mut line = serde_json::to_vec(&rec).map_err(|_| "encode")?;
            line.push(b'\n');
            f.write_all(&line).await.map_err(|_| "log write failed")?;
            f.sync_data().await.map_err(|_| "log sync failed")?;
        }
        let mut idx = self.index.lock().unwrap();
        if idx.order.len() >= idx.cap {
            if let Some(old) = idx.order.pop_front() {
                idx.by_hash.remove(&old);
            }
        }
        idx.order.push_back(hash.clone());
        idx.by_hash.insert(hash, rec.clone());
        Ok(rec)
    }

    pub fn lookup(&self, hash_hex: &str) -> Option<Record> {
        self.index.lock().unwrap().by_hash.get(&hash_hex.to_ascii_lowercase()).cloned()
    }
}

#[derive(Deserialize)]
struct WitnessReq {
    hash: String,
}

pub fn router(n: Arc<Notary>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/key", get(key))
        .route("/v1/witness", post(witness))
        .route("/v1/witnessed/{hash}", get(witnessed))
        .with_state(n)
}

async fn key(State(n): State<Arc<Notary>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "name": n.name, "alg": "Ed25519", "publicKey": B64.encode(n.public_key()) }))
}

async fn witness(State(n): State<Arc<Notary>>, Json(req): Json<WitnessReq>) -> Result<Json<Record>, (StatusCode, String)> {
    n.witness(&req.hash).await.map(Json).map_err(|e| {
        let code = if e.starts_with("hash") { StatusCode::BAD_REQUEST } else { StatusCode::SERVICE_UNAVAILABLE };
        (code, e.to_string())
    })
}

async fn witnessed(State(n): State<Arc<Notary>>, Path(hash): Path<String>) -> Result<Json<Record>, StatusCode> {
    n.lookup(&hash).map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// Reads a 32-byte Ed25519 seed, base64 or hex, from a file (a mounted Kubernetes secret).
pub fn read_seed(text: &str) -> Result<[u8; 32], String> {
    let t = text.trim();
    let bytes = B64.decode(t).ok().filter(|b| b.len() == 32).or_else(|| hex::decode(t).ok()).ok_or("seed is neither base64 nor hex")?;
    bytes.try_into().map_err(|_| "seed must be 32 bytes".to_string())
}
