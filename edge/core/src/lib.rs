//! DIFME edge wallet core (README row 5.1; ADR-005, ADR-016). Shared by the Tauri app (desktop and Android) and
//! usable on its own:
//!
//! * [`wallet`]    offline-first wallet state, an automerge document carrying the escrow CRDT of CrdtMerge.tla;
//! * [`integrity`] Blake3 sealing of everything at rest and pinning of rule components;
//! * [`tee`]       the `Tee` trait, a software key store standing in for StrongBox/KeyMint, signed payment intents
//!                 and EAT evidence in the format services/attestation appraises;
//! * [`rules`]     the Wasmtime WASI Preview 2 host running the sandboxed offline-limit rule;
//! * [`sync`]      the QUIC client for services/hub's `difme/1` protocol;
//! * [`hce`]       the APDU responder behind Host Card Emulation (simulated NFC off-device);
//! * [`ml`]        the on-device fraud-model seam (no ONNX model exists in ml/ yet).

pub mod hce;
pub mod integrity;
pub mod ml;
pub mod rules;
pub mod sync;
pub mod tee;
pub mod wallet;

use rules::{RuleDecision, RuleEngine, RuleInput};
use serde::Serialize;
use std::path::PathBuf;
use sync::{HubEndpoint, SyncReport};
use tee::{PaymentIntent, SoftwareTee, Tee};
use wallet::{PaymentRecord, Wallet};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("wallet: {0}")]
    Wallet(String),
    #[error("not enough offline spending rights: need {needed}, hold {held}")]
    InsufficientRights { needed: i64, held: i64 },
    #[error("refused by the offline rule: {0}")]
    RuleDenied(String),
    #[error("rule host: {0}")]
    Rule(String),
    #[error("key store: {0}")]
    Tee(String),
    #[error("sync: {0}")]
    Sync(String),
    #[error("the hub's core is unavailable; the payment stays pending")]
    HubUnavailable,
    #[error("storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("crdt: {0}")]
    Crdt(#[from] automerge::AutomergeError),
}

/// How the app opens the core.
#[derive(Clone, Debug)]
pub struct EdgeConfig {
    pub wallet_id: String,
    pub device_id: String,
    pub currency: String,
    /// Where the sealed wallet and key store live; `None` keeps everything in memory.
    pub data_dir: Option<PathBuf>,
    pub hub: Option<HubEndpoint>,
    /// On first start, provision the wallet from a simulated hub replica (balance and an escrow grant). Stands in for
    /// the hub's state-sync extension, which does not exist yet (edge/README.md).
    pub simulated_provisioning: bool,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        EdgeConfig {
            wallet_id: "wallet-demo".into(),
            device_id: "device-emulator".into(),
            currency: "INR".into(),
            data_dir: None,
            hub: None,
            simulated_provisioning: true,
        }
    }
}

/// Simulated provisioning amounts (minor units): ₹10,000 ledger balance, ₹2,000 of offline rights from a ₹1,00,000
/// wallet escrow limit.
pub const DEMO_LIMIT: i64 = 10_000_000;
pub const DEMO_BALANCE: i64 = 1_000_000;
pub const DEMO_GRANT: i64 = 200_000;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatus {
    pub wallet_id: String,
    pub device_id: String,
    pub currency: String,
    pub ledger_balance: i64,
    pub rights_available: i64,
    pub offline_spent: i64,
    pub pending_count: usize,
    pub payments: Vec<PaymentRecord>,
    pub hub_configured: bool,
    pub last_sync: Option<SyncReport>,
    pub rule: String,
    pub fraud_model: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationStatus {
    pub device_id: String,
    pub security_level: &'static str,
    pub public_key_hex: String,
    pub eat_profile: &'static str,
    pub rule_sha256: String,
    pub rule_blake3: String,
    pub token_bytes: usize,
    /// The token verified against the device's own key (the hub-side verifier does the real appraisal).
    pub self_check: bool,
    /// Why the verifier would not fully trust this evidence yet.
    pub caveats: Vec<String>,
}

pub struct EdgeCore {
    cfg: EdgeConfig,
    wallet: Wallet,
    tee: Box<dyn Tee>,
    rules: RuleEngine,
    fraud: Box<dyn ml::FraudModel>,
    last_sync: Option<SyncReport>,
    armed_intent: Option<Vec<u8>>,
    hce: hce::HceSession,
}

const WALLET_FILE: &str = "wallet.am.sealed";
const KEY_FILE: &str = "keystore.sealed";

impl EdgeCore {
    pub fn open(cfg: EdgeConfig) -> Result<Self, Error> {
        let read = |name: &str| cfg.data_dir.as_ref().map(|d| d.join(name)).filter(|p| p.exists()).map(std::fs::read).transpose();
        let tee = match read(KEY_FILE)? {
            Some(blob) => SoftwareTee::import_sealed(&blob)?,
            None => SoftwareTee::generate(&cfg.device_id)?,
        };
        let wallet = match read(WALLET_FILE)? {
            Some(blob) => Wallet::open_sealed(&blob, tee.device_id())?,
            None => Self::provision(&cfg, tee.device_id())?,
        };
        if let Some(dir) = &cfg.data_dir {
            std::fs::create_dir_all(dir)?;
            if !dir.join(KEY_FILE).exists() {
                // Only the software store is exportable; a hardware-backed Tee would never be written out.
                std::fs::write(dir.join(KEY_FILE), tee.export_sealed())?;
            }
        }
        let mut core = EdgeCore {
            wallet,
            tee: Box::new(tee),
            rules: RuleEngine::offline_limit()?,
            fraud: Box::new(ml::NoModel),
            last_sync: None,
            armed_intent: None,
            hce: hce::HceSession::default(),
            cfg,
        };
        core.persist()?;
        Ok(core)
    }

    fn provision(cfg: &EdgeConfig, device: &str) -> Result<Wallet, Error> {
        let genesis = Wallet::genesis(&cfg.wallet_id, &cfg.currency, DEMO_LIMIT);
        let mut wallet = Wallet::open(&genesis, device)?;
        if cfg.simulated_provisioning {
            let mut hub = Wallet::open(&genesis, wallet::HUB)?;
            hub.set_ledger_balance(DEMO_BALANCE)?;
            hub.grant(device, DEMO_GRANT)?;
            wallet.sync_with(&mut hub)?;
        }
        Ok(wallet)
    }

    fn persist(&mut self) -> Result<(), Error> {
        if let Some(dir) = &self.cfg.data_dir {
            std::fs::create_dir_all(dir)?;
            let tmp = dir.join(format!("{WALLET_FILE}.tmp"));
            std::fs::write(&tmp, self.wallet.save_sealed())?;
            std::fs::rename(tmp, dir.join(WALLET_FILE))?;
        }
        Ok(())
    }

    pub fn wallet(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    pub fn tee(&self) -> &dyn Tee {
        self.tee.as_ref()
    }

    pub fn rules(&self) -> &RuleEngine {
        &self.rules
    }

    pub fn status(&self) -> WalletStatus {
        let me = self.tee.device_id();
        let mut payments = self.wallet.payments();
        payments.reverse();
        WalletStatus {
            wallet_id: self.wallet.wallet_id(),
            device_id: me.to_string(),
            currency: self.wallet.currency(),
            ledger_balance: self.wallet.ledger_balance(),
            rights_available: self.wallet.rights(me),
            offline_spent: self.wallet.offline_spent(me),
            pending_count: self.wallet.pending(me).len(),
            payments,
            hub_configured: self.cfg.hub.is_some(),
            last_sync: self.last_sync.clone(),
            rule: self.rules.description().to_string(),
            fraud_model: self.fraud.name().to_string(),
        }
    }

    /// Pays offline: the sandboxed rule decides, the TEE signs the intent, the CRDT records it, the state is sealed
    /// to disk, and the signed intent is armed for an NFC tap.
    pub fn pay_offline(&mut self, payee: &str, amount_minor: i64) -> Result<PaymentRecord, Error> {
        let me = self.tee.device_id().to_string();
        let payee = payee.trim();
        if payee.is_empty() {
            return Err(Error::Wallet("payee is required".into()));
        }
        let input = RuleInput {
            amount_minor,
            currency: self.wallet.currency(),
            offline_spent: self.wallet.offline_spent(&me),
            rights_available: self.wallet.rights(&me),
        };
        if let RuleDecision::Deny(reason) = self.rules.check(&input)? {
            return Err(Error::RuleDenied(reason));
        }
        let intent = PaymentIntent::new(&self.wallet.wallet_id(), &me, payee, amount_minor, &input.currency);
        let cose = tee::sign_intent(self.tee.as_ref(), &intent)?;
        self.wallet.record_payment(&intent, &cose)?;
        self.persist()?;
        self.armed_intent = Some(cose);
        self.wallet.payment(&intent.id).ok_or_else(|| Error::Wallet("payment vanished".into()))
    }

    /// Submits pending payments to the hub.
    pub async fn sync(&mut self) -> Result<SyncReport, Error> {
        let hub = self.cfg.hub.clone().ok_or_else(|| Error::Sync("no hub configured (set DIFME_HUB_ADDR and DIFME_HUB_CERT)".into()));
        let report = match hub {
            Ok(hub) => match sync::HubClient::connect(&hub).await {
                Ok(client) => {
                    let r = sync::sync_pending(&mut self.wallet, self.tee.as_ref(), &self.rules, self.fraud.as_ref(), &mut sync::IntentBoundNonce, &client).await;
                    client.close().await;
                    r
                }
                Err(e) => SyncReport { last_error: Some(e.to_string()), finished_ms: wallet::now_ms(), ..Default::default() },
            },
            Err(e) => SyncReport { last_error: Some(e.to_string()), finished_ms: wallet::now_ms(), ..Default::default() },
        };
        self.persist()?;
        self.last_sync = Some(report.clone());
        Ok(report)
    }

    /// Produces fresh evidence and checks it locally.
    pub fn attestation(&self) -> Result<AttestationStatus, Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| Error::Tee(e.to_string()))?;
        let token = tee::attest(self.tee.as_ref(), &tee::Evidence { nonce: &nonce, rule_sha256: self.rules.sha256(), intent_b3: None })?;
        let pk = self.tee.public_key_sec1();
        let self_check = tee::verify_sign1(&token, &pk)
            .map(|payload| tee::claim(&payload, tee::claims::NONCE).and_then(|v| v.as_bytes().cloned()) == Some(nonce.to_vec()))
            .unwrap_or(false);
        let mut caveats = Vec::new();
        if self.tee.security_level() == tee::SecurityLevel::Software {
            caveats.push("software key store (emulator): no StrongBox/KeyMint key attestation chain".into());
        }
        caveats.push("hub does not relay verifier challenges yet: evidence uses an intent-bound nonce and takes the server-side check".into());
        Ok(AttestationStatus {
            device_id: self.tee.device_id().to_string(),
            security_level: self.tee.security_level().as_str(),
            public_key_hex: integrity::hex(&pk),
            eat_profile: tee::EAT_PROFILE,
            rule_sha256: self.rules.sha256().to_string(),
            rule_blake3: self.rules.blake3().to_string(),
            token_bytes: token.len(),
            self_check,
            caveats,
        })
    }

    /// Simulated NFC: one command APDU from a reader, answered as the HCE service would.
    pub fn hce_apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.hce.process(apdu, self.armed_intent.as_deref())
    }
}
