//! Attested key release (ADR-026; owner 2026-11-24: all keys only in the emulated TEE): the notary's Ed25519 seed never
//! comes from a Kubernetes Secret, an environment variable or a file in a cluster. At start the notary attests to
//! Trustee's KBS (protocol 0.4.0, as services/hsm's KbsClient) and fetches `difme/notary/seed`, returned as JWE
//! (RSA-OAEP-256 + A256GCM) to an ephemeral RSA key bound into the evidence. First start only (resource not found): the
//! seed is generated here and stored through OpenBao's create-only `notary-bootstrap` role, which can neither read nor
//! overwrite it. Development TEE: Trustee's emulated "sample" TEE, whose svn stands in for the measurement.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64U};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey};
use sha2::{Digest, Sha256, Sha384};

pub const PROTOCOL: &str = "0.4.0";
pub const SEED_RESOURCE: &str = "difme/notary/seed";

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into()
}

/// Client for Trustee's Key Broker Service with the emulated TEE's evidence.
pub struct Kbs {
    base: String,
    svn: String,
    agent: ureq::Agent,
    key: Option<RsaPrivateKey>,
    cookie: Option<String>,
}

impl Kbs {
    pub fn new(base: &str, svn: &str) -> Self {
        Kbs { base: base.trim_end_matches('/').to_string(), svn: svn.to_string(), agent: agent(), key: None, cookie: None }
    }

    /// RFC 8785 canonical runtime data (keys sorted, no whitespace; all values are base64 strings).
    pub fn runtime_data(nonce: &str, n: &[u8], e: &[u8]) -> (String, String) {
        let pubkey = format!(r#"{{"alg":"RSA-OAEP-256","e":"{}","kty":"RSA","n":"{}"}}"#, B64U.encode(e), B64U.encode(n));
        let canonical = format!(r#"{{"additional-evidence":"","nonce":"{nonce}","tee-pubkey":{pubkey}}}"#);
        (pubkey, canonical)
    }

    fn attest(&mut self) -> Result<(), String> {
        let mut auth = self.agent.post(format!("{}/kbs/v0/auth", self.base)).header("content-type", "application/json")
            .send(format!(r#"{{"version":"{PROTOCOL}","tee":"sample","extra-params":{{}}}}"#))
            .map_err(|e| format!("KBS auth: {e}"))?;
        let status = auth.status().as_u16();
        let cookie = auth.headers().get("set-cookie").and_then(|v| v.to_str().ok()).map(|c| c.split(';').next().unwrap_or("").to_string());
        let body = auth.body_mut().read_to_string().map_err(|e| e.to_string())?;
        if status != 200 { return Err(format!("KBS auth: HTTP {status} {}", &body[..body.len().min(200)])); }
        let nonce = serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v["nonce"].as_str().map(String::from))
            .ok_or("KBS auth: no nonce")?;
        let cookie = cookie.ok_or("KBS sent no session cookie")?;
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 3072).map_err(|e| e.to_string())?;
        let (pubkey, canonical) = Self::runtime_data(&nonce, &key.n().to_bytes_be(), &key.e().to_bytes_be());
        let report_data = B64.encode(Sha384::digest(canonical.as_bytes()));
        let evidence = format!(r#"{{"svn":"{}","report_data":"{report_data}"}}"#, self.svn);
        let attest_body = format!(
            r#"{{"runtime-data":{{"nonce":"{nonce}","tee-pubkey":{pubkey}}},"tee-evidence":{{"primary_evidence":{evidence},"additional_evidence":""}}}}"#
        );
        let mut att = self.agent.post(format!("{}/kbs/v0/attest", self.base)).header("content-type", "application/json")
            .header("cookie", &cookie).send(attest_body).map_err(|e| format!("KBS attest: {e}"))?;
        if att.status().as_u16() != 200 {
            let b = att.body_mut().read_to_string().unwrap_or_default();
            return Err(format!("KBS attest: HTTP {} {}", att.status().as_u16(), &b[..b.len().min(200)]));
        }
        self.key = Some(key);
        self.cookie = Some(cookie);
        Ok(())
    }

    /// A resource ("repository/type/tag"), decrypted in memory; None when it does not exist (404).
    pub fn resource(&mut self, path: &str) -> Result<Option<Vec<u8>>, String> {
        if self.cookie.is_none() { self.attest()?; }
        let mut r = self.agent.get(format!("{}/kbs/v0/resource/{path}", self.base)).header("cookie", self.cookie.as_deref().unwrap_or(""))
            .call().map_err(|e| format!("KBS resource {path}: {e}"))?;
        let status = r.status().as_u16();
        let body = r.body_mut().read_to_string().map_err(|e| e.to_string())?;
        match status {
            200 => decrypt(self.key.as_ref().ok_or("not attested")?, &body).map(Some),
            404 => Ok(None),
            s => Err(format!("KBS resource {path}: HTTP {s} {}", &body[..body.len().min(200)])),
        }
    }
}

/// Flattened JWE, RSA-OAEP-256 + A256GCM, decrypted with the TEE key.
pub fn decrypt(key: &RsaPrivateKey, jwe: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let v: serde_json::Value = serde_json::from_str(jwe).map_err(|_| "KBS response is not JSON")?;
    let f = |k: &str| v[k].as_str().map(String::from);
    let (prot, ek, iv, ct, tag) = match (f("protected"), f("encrypted_key"), f("iv"), f("ciphertext"), f("tag")) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
        _ => return Err("KBS response is not a flattened JWE".into()),
    };
    let header = String::from_utf8(B64U.decode(&prot).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?.replace(' ', "");
    if !header.contains(r#""alg":"RSA-OAEP-256""#) || !header.contains(r#""enc":"A256GCM""#) {
        return Err(format!("unexpected JWE algorithms: {header}"));
    }
    let cek = key.decrypt(Oaep::new::<Sha256>(), &B64U.decode(&ek).map_err(|e| e.to_string())?).map_err(|_| "JWE key unwrap failed")?;
    let aad = match f("aad") {
        Some(a) if !a.is_empty() => B64U.decode(&a).map_err(|e| e.to_string())?,
        _ => prot.into_bytes(),
    };
    let mut msg = B64U.decode(&ct).map_err(|e| e.to_string())?;
    msg.extend(B64U.decode(&tag).map_err(|e| e.to_string())?);
    let gcm = aes_gcm::Aes256Gcm::new_from_slice(&cek).map_err(|_| "bad JWE content key")?;
    let nonce = B64U.decode(&iv).map_err(|e| e.to_string())?;
    if nonce.len() != 12 { return Err("bad JWE iv".into()); }
    gcm.decrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &msg, aad: &aad }).map_err(|_| "JWE decryption failed".into())
}

/// The seed: released by attestation, or (first start, bootstrap enabled) generated here and stored create-only.
pub fn notary_seed(kbs_url: &str, svn: &str, openbao: Option<&str>, role: &str, jwt_file: &str) -> Result<[u8; 32], String> {
    let mut kbs = Kbs::new(kbs_url, svn);
    if let Some(stored) = kbs.resource(SEED_RESOURCE)? {
        let raw = B64.decode(String::from_utf8_lossy(&stored).trim()).map_err(|_| "stored seed is not base64")?;
        return raw.try_into().map_err(|_| "stored seed is not 32 bytes".to_string());
    }
    let addr = openbao.ok_or("notary seed not in the key release store, and bootstrap not enabled")?;
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    let jwt = std::fs::read_to_string(jwt_file).map_err(|e| format!("service account token: {e}"))?;
    let agent = agent();
    let mut login = agent.post(format!("{addr}/v1/auth/kubernetes/login"))
        .send(serde_json::json!({"role": role, "jwt": jwt.trim()}).to_string()).map_err(|e| format!("OpenBao login: {e}"))?;
    let lb = login.body_mut().read_to_string().map_err(|e| e.to_string())?;
    let token = serde_json::from_str::<serde_json::Value>(&lb).ok().and_then(|v| v["auth"]["client_token"].as_str().map(String::from))
        .ok_or_else(|| format!("OpenBao login ({role}) refused"))?;
    let r = agent.post(format!("{addr}/v1/kbs/{SEED_RESOURCE}")).header("X-Vault-Token", &token)
        .send(serde_json::json!({"data": B64.encode(seed)}).to_string()).map_err(|e| format!("OpenBao create: {e}"))?;
    if !matches!(r.status().as_u16(), 200 | 204) {
        return Err(format!("OpenBao create kbs/{SEED_RESOURCE}: HTTP {} (exists already? then the KBS should have released it)", r.status().as_u16()));
    }
    eprintln!("notary: first start, Ed25519 seed generated inside the notary and stored create-only");
    Ok(seed)
}
