//! Wasmtime host for sandboxed rule components (ADR-016). A rule is a WASI Preview 2 component exporting
//! `difme:rules/limit` (edge/wit/offline-limit.wit). Each check runs in a fresh store with:
//!
//! * a WASI context that grants nothing: no preopened directories, environment, arguments, sockets or stdio;
//! * a fuel budget (a runaway rule traps instead of hanging the wallet) and a memory cap;
//! * an integrity gate: the component's Blake3 must match the pinned digest before it is compiled.
//!
//! Its SHA-256 goes into the attestation evidence and the verifier's `binary_hash` check (approved Wasm builds).

use crate::{Error, integrity};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({ world: "offline-rule", path: "../wit" });

use exports::difme::rules::limit::{Decision, Payment};

/// The offline-limit rule built from edge/rules/offline-limit by edge/rules/build.sh.
pub const OFFLINE_LIMIT_WASM: &[u8] = include_bytes!("../rules/offline_limit.wasm");
/// Its pinned Blake3 digest, written next to it by the build script.
pub const OFFLINE_LIMIT_B3: &str = include_str!("../rules/offline_limit.wasm.b3");

const FUEL_PER_CHECK: u64 = 5_000_000;
const MEMORY_LIMIT: usize = 16 << 20;

struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

/// What the host tells the rule about a payment.
#[derive(Clone, Debug)]
pub struct RuleInput {
    pub amount_minor: i64,
    pub currency: String,
    pub offline_spent: i64,
    pub rights_available: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleDecision {
    Allow,
    Deny(String),
}

pub struct RuleEngine {
    engine: Engine,
    pre: OfflineRulePre<Host>,
    sha256: String,
    blake3: String,
    description: String,
}

impl RuleEngine {
    /// The bundled offline-limit rule.
    pub fn offline_limit() -> Result<Self, Error> {
        Self::load(OFFLINE_LIMIT_WASM, OFFLINE_LIMIT_B3.trim())
    }

    /// Loads a rule component after checking it against its pinned Blake3 digest.
    pub fn load(wasm: &[u8], pinned_b3: &str) -> Result<Self, Error> {
        integrity::verify_pinned(wasm, pinned_b3)?;
        let mut config = Config::new();
        config.wasm_component_model(true).consume_fuel(true);
        let engine = Engine::new(&config).map_err(rule_err)?;
        let component = Component::from_binary(&engine, wasm).map_err(rule_err)?;
        let mut linker: Linker<Host> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(rule_err)?;
        let pre = OfflineRulePre::new(linker.instantiate_pre(&component).map_err(rule_err)?).map_err(rule_err)?;
        let mut me = RuleEngine { engine, pre, sha256: integrity::sha256_hex(wasm), blake3: integrity::hex_digest(wasm), description: String::new() };
        let (mut store, rule) = me.instantiate()?;
        me.description = rule.difme_rules_limit().call_describe(&mut store).map_err(rule_err)?;
        Ok(me)
    }

    fn instantiate(&self) -> Result<(Store<Host>, OfflineRule), Error> {
        let host = Host {
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).instances(8).tables(8).memories(4).build(),
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|h| &mut h.limits);
        store.set_fuel(FUEL_PER_CHECK).map_err(rule_err)?;
        let rule = self.pre.instantiate(&mut store).map_err(rule_err)?;
        Ok((store, rule))
    }

    /// Runs the rule in a fresh sandbox.
    pub fn check(&self, input: &RuleInput) -> Result<RuleDecision, Error> {
        let (mut store, rule) = self.instantiate()?;
        let payment = Payment {
            amount_minor: input.amount_minor,
            currency: input.currency.clone(),
            offline_spent: input.offline_spent,
            rights_available: input.rights_available,
        };
        Ok(match rule.difme_rules_limit().call_check(&mut store, &payment).map_err(rule_err)? {
            Decision::Allow => RuleDecision::Allow,
            Decision::Deny(reason) => RuleDecision::Deny(reason),
        })
    }

    /// SHA-256 (hex) of the component: the verifier's `wasm_module_sha256`.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn blake3(&self) -> &str {
        &self.blake3
    }

    /// The rule's self-description, e.g. "offline-limit/0.1.0 per-payment=50000 cumulative=200000".
    pub fn description(&self) -> &str {
        &self.description
    }
}

fn rule_err(e: impl std::fmt::Display) -> Error {
    Error::Rule(format!("{e:#}"))
}
