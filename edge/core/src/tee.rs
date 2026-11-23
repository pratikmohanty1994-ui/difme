//! Trusted execution: a `Tee` trait the wallet uses to sign payment intents and attestation evidence, and a
//! software implementation standing in for Android StrongBox/KeyMint in the emulator (owner decision 2026-11-17:
//! "simulated TEE").
//!
//! On a device, the Kotlin keystore plugin backs `Tee` with an `AndroidKeyStore` EC P-256 key generated with
//! `setIsStrongBoxBacked(true)` (falling back to the TEE KeyMint), and the private key never leaves hardware. The
//! software key store keeps the same contract — the private key is created inside it, only the public key and
//! signatures come out — but the key sits in app storage, so its `security_level` is `Software` and the attestation
//! token says so.
//!
//! Evidence format (what services/attestation appraises): an EAT (RFC 9711) as CWT claims in a COSE_Sign1 (RFC 9052),
//! ES256, tagged. Claim 10 (`nonce`) is the verifier's challenge — the one claim it checks; the rest describe the
//! device for policy and audit.

use crate::{Error, integrity};
use coset::cbor::Value as Cbor;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::Serialize;

/// CWT/EAT claim keys (RFC 8392, RFC 9711).
pub mod claims {
    pub const IAT: i64 = 6;
    pub const NONCE: i64 = 10;
    pub const UEID: i64 = 256;
    pub const DBGSTAT: i64 = 263;
    pub const EAT_PROFILE: i64 = 265;
    pub const SWNAME: i64 = 270;
    pub const SWVERSION: i64 = 271;
    /// Private-use claims (negative keys): key protection level, sandboxed rule digest, payment intent digest.
    pub const SECURITY_LEVEL: i64 = -70_001;
    pub const RULE_SHA256: i64 = -70_002;
    pub const INTENT_B3: i64 = -70_003;
}

pub const EAT_PROFILE: &str = "tag:difme.dev,2026:edge-eat/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityLevel {
    /// Software key store (emulator, desktop, tests).
    Software,
    /// KeyMint in the TEE.
    TrustedEnvironment,
    /// StrongBox secure element.
    StrongBox,
}

impl SecurityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "SOFTWARE",
            Self::TrustedEnvironment => "TRUSTED_ENVIRONMENT",
            Self::StrongBox => "STRONGBOX",
        }
    }
}

/// The signing half of a hardware key store. Implementations never expose the private key.
pub trait Tee: Send + Sync {
    fn device_id(&self) -> &str;
    fn security_level(&self) -> SecurityLevel;
    /// SEC1 uncompressed P-256 public key: what the verifier registers per device.
    fn public_key_sec1(&self) -> Vec<u8>;
    /// ECDSA P-256 / SHA-256 signature, raw `r || s` (64 bytes), as COSE ES256 requires.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Software key store standing in for StrongBox/KeyMint.
pub struct SoftwareTee {
    device_id: String,
    key: SigningKey,
}

impl SoftwareTee {
    /// Creates a fresh key inside the store.
    pub fn generate(device_id: &str) -> Result<Self, Error> {
        loop {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| Error::Tee(format!("no OS randomness: {e}")))?;
            if let Ok(key) = SigningKey::from_slice(&seed) {
                return Ok(SoftwareTee { device_id: device_id.to_string(), key });
            }
        }
    }

    /// Deterministic key for tests and reproducible demos only.
    pub fn from_seed(device_id: &str, seed: [u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(&seed).map_err(|e| Error::Tee(e.to_string()))?;
        Ok(SoftwareTee { device_id: device_id.to_string(), key })
    }

    /// Persists the key store (Blake3-sealed). Hardware key stores have no equivalent: their keys are not exportable.
    pub fn export_sealed(&self) -> Vec<u8> {
        let mut body = self.key.to_bytes().to_vec();
        body.extend_from_slice(self.device_id.as_bytes());
        integrity::seal(&body)
    }

    pub fn import_sealed(blob: &[u8]) -> Result<Self, Error> {
        let body = integrity::unseal(blob)?;
        if body.len() <= 32 {
            return Err(Error::Tee("sealed key store is too short".into()));
        }
        let (key, id) = body.split_at(32);
        let device_id = std::str::from_utf8(id).map_err(|e| Error::Tee(e.to_string()))?;
        Self::from_seed(device_id, key.try_into().expect("32 bytes"))
    }
}

impl Tee for SoftwareTee {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Software
    }

    fn public_key_sec1(&self) -> Vec<u8> {
        self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: Signature = self.key.sign(message);
        Ok(sig.to_vec())
    }
}

/// What the payer authorizes. Canonical CBOR (integer keys in ascending order) is what gets signed and hashed.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIntent {
    /// UUIDv7; also the hub idempotency key.
    pub id: String,
    pub wallet_id: String,
    pub payer: String,
    pub payee: String,
    pub amount_minor: i64,
    pub currency: String,
    pub created_ms: i64,
}

impl PaymentIntent {
    pub fn new(wallet_id: &str, payer: &str, payee: &str, amount_minor: i64, currency: &str) -> Self {
        PaymentIntent {
            id: uuid::Uuid::now_v7().to_string(),
            wallet_id: wallet_id.into(),
            payer: payer.into(),
            payee: payee.into(),
            amount_minor,
            currency: currency.into(),
            created_ms: crate::wallet::now_ms(),
        }
    }

    pub fn canonical(&self) -> Vec<u8> {
        let map = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Text(self.id.clone())),
            (Cbor::Integer(2.into()), Cbor::Text(self.wallet_id.clone())),
            (Cbor::Integer(3.into()), Cbor::Text(self.payer.clone())),
            (Cbor::Integer(4.into()), Cbor::Text(self.payee.clone())),
            (Cbor::Integer(5.into()), Cbor::Integer(self.amount_minor.into())),
            (Cbor::Integer(6.into()), Cbor::Text(self.currency.clone())),
            (Cbor::Integer(7.into()), Cbor::Integer(self.created_ms.into())),
        ]);
        let mut out = Vec::new();
        coset::cbor::into_writer(&map, &mut out).expect("CBOR to a Vec");
        out
    }

    pub fn digest_hex(&self) -> String {
        integrity::hex_digest(&self.canonical())
    }
}

fn sign1(tee: &dyn Tee, payload: Vec<u8>, content_type: &str) -> Result<Vec<u8>, Error> {
    let protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).content_type(content_type.to_string()).build();
    let unprotected = HeaderBuilder::new().key_id(tee.device_id().as_bytes().to_vec()).build();
    let mut err = None;
    let token = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .create_signature(b"", |data| tee.sign(data).unwrap_or_else(|e| { err = Some(e); Vec::new() }))
        .build();
    if let Some(e) = err {
        return Err(e);
    }
    token.to_tagged_vec().map_err(|e| Error::Tee(format!("COSE encoding: {e:?}")))
}

/// Signs a payment intent: COSE_Sign1 over its canonical CBOR.
pub fn sign_intent(tee: &dyn Tee, intent: &PaymentIntent) -> Result<Vec<u8>, Error> {
    sign1(tee, intent.canonical(), "application/vnd.difme.payment-intent+cbor")
}

/// Inputs for one attestation token.
#[derive(Clone, Debug, Default)]
pub struct Evidence<'a> {
    /// The verifier's challenge (`AttestationVerifierService.Challenge`).
    pub nonce: &'a [u8],
    /// SHA-256 (hex) of the sandboxed rule component that judged the payment.
    pub rule_sha256: &'a str,
    /// Blake3 (hex) of the payment intent this evidence vouches for, if any.
    pub intent_b3: Option<&'a str>,
}

/// Produces an EAT the verifier can appraise.
pub fn attest(tee: &dyn Tee, evidence: &Evidence<'_>) -> Result<Vec<u8>, Error> {
    // UEID type 0x01 (RAND): the Blake3 of the device public key, so it is stable per key and reveals nothing else.
    let mut ueid = vec![0x01];
    ueid.extend_from_slice(&blake3::hash(&tee.public_key_sec1()).as_bytes()[..32]);
    let mut c = vec![
        (Cbor::Integer(claims::IAT.into()), Cbor::Integer((crate::wallet::now_ms() / 1000).into())),
        (Cbor::Integer(claims::NONCE.into()), Cbor::Bytes(evidence.nonce.to_vec())),
        (Cbor::Integer(claims::UEID.into()), Cbor::Bytes(ueid)),
        // dbgstat 3 = disabled-fully-since-boot on hardware; the software store cannot vouch for that, so 0 (enabled).
        (Cbor::Integer(claims::DBGSTAT.into()), Cbor::Integer(if tee.security_level() == SecurityLevel::Software { 0 } else { 3 }.into())),
        (Cbor::Integer(claims::EAT_PROFILE.into()), Cbor::Text(EAT_PROFILE.into())),
        (Cbor::Integer(claims::SWNAME.into()), Cbor::Text("difme-edge".into())),
        (Cbor::Integer(claims::SWVERSION.into()), Cbor::Array(vec![Cbor::Text(env!("CARGO_PKG_VERSION").into())])),
        (Cbor::Integer(claims::SECURITY_LEVEL.into()), Cbor::Text(tee.security_level().as_str().into())),
        (Cbor::Integer(claims::RULE_SHA256.into()), Cbor::Text(evidence.rule_sha256.into())),
    ];
    if let Some(d) = evidence.intent_b3 {
        c.push((Cbor::Integer(claims::INTENT_B3.into()), Cbor::Text(d.into())));
    }
    let mut payload = Vec::new();
    coset::cbor::into_writer(&Cbor::Map(c), &mut payload).map_err(|e| Error::Tee(e.to_string()))?;
    sign1(tee, payload, "application/eat+cwt")
}

/// Verifies a COSE_Sign1 from this module against a SEC1 public key and returns its payload. The device uses it to
/// self-check evidence before sending it; the hub-side verifier does the authoritative appraisal.
pub fn verify_sign1(token: &[u8], public_key_sec1: &[u8]) -> Result<Vec<u8>, Error> {
    let key = VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|e| Error::Tee(e.to_string()))?;
    let s = CoseSign1::from_tagged_slice(token).or_else(|_| CoseSign1::from_slice(token)).map_err(|e| Error::Tee(format!("{e:?}")))?;
    s.verify_signature(b"", |sig, data| {
        let sig = Signature::from_slice(sig).map_err(|_| ())?;
        key.verify(data, &sig).map_err(|_| ())
    })
    .map_err(|_| Error::Tee("COSE_Sign1 signature does not verify".into()))?;
    s.payload.ok_or_else(|| Error::Tee("COSE_Sign1 has no payload".into()))
}

/// Reads one integer-keyed claim from a CWT payload.
pub fn claim(payload: &[u8], key: i64) -> Option<Cbor> {
    let value: Cbor = coset::cbor::from_reader(payload).ok()?;
    value.as_map()?.iter().find_map(|(k, v)| (k.as_integer().map(i128::from) == Some(key as i128)).then(|| v.clone()))
}
