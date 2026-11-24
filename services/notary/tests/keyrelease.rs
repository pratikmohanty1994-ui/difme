//! Attested key release against a fake KBS + OpenBao (one tiny HTTP server): the seed comes back as JWE to the key bound
//! into the evidence, and on first start it is generated inside the notary and stored create-only.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64U};
use difme_notary::keyrelease::{Kbs, notary_seed};
use rsa::{BigUint, Oaep, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

struct Fake { stored: Option<Vec<u8>>, pubkey: Option<RsaPublicKey>, created: Vec<String>, report_ok: bool }

fn serve(state: Arc<Mutex<Fake>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let (mut len, mut h) = (0usize, String::new());
            loop {
                h.clear();
                r.read_line(&mut h).unwrap();
                if h == "\r\n" || h.is_empty() { break; }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") { len = v.trim().parse().unwrap(); }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let path = line.split(' ').nth(1).unwrap().to_string();
            let mut st = state.lock().unwrap();
            let (code, extra, out) = if path == "/kbs/v0/auth" {
                (200, "set-cookie: kbs-session-id=abc; Path=/\r\n", r#"{"nonce":"n0nce","extra-params":""}"#.to_string())
            } else if path == "/kbs/v0/attest" {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                let pk = &v["runtime-data"]["tee-pubkey"];
                let n = B64U.decode(pk["n"].as_str().unwrap()).unwrap();
                let e = B64U.decode(pk["e"].as_str().unwrap()).unwrap();
                // the report data must bind nonce + key (RFC 8785 canonical runtime data, SHA-384)
                let (_, canonical) = Kbs::runtime_data("n0nce", &n, &e);
                st.report_ok = v["tee-evidence"]["primary_evidence"]["report_data"].as_str().unwrap() == B64.encode(Sha384::digest(canonical.as_bytes()));
                st.pubkey = Some(RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap());
                (200, "", "{}".to_string())
            } else if path == "/kbs/v0/resource/difme/notary/seed" {
                match &st.stored {
                    None => (404, "", "{}".to_string()),
                    Some(plain) => (200, "", jwe(st.pubkey.as_ref().unwrap(), plain)),
                }
            } else if path == "/v1/auth/kubernetes/login" {
                (200, "", r#"{"auth":{"client_token":"t0k"}}"#.to_string())
            } else if path == "/v1/kbs/difme/notary/seed" {
                st.created.push(body.clone());
                (204, "", String::new())
            } else { (404, "", "{}".to_string()) };
            write!(s, "HTTP/1.1 {code} X\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{out}", out.len()).unwrap();
        }
    });
    addr
}

fn jwe(pk: &RsaPublicKey, plain: &[u8]) -> String {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let prot = B64U.encode(r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#);
    let cek = [7u8; 32];
    let iv = [9u8; 12];
    let ek = pk.encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha256>(), &cek).unwrap();
    let mut ct = aes_gcm::Aes256Gcm::new_from_slice(&cek).unwrap()
        .encrypt(aes_gcm::Nonce::from_slice(&iv), Payload { msg: plain, aad: prot.as_bytes() }).unwrap();
    let tag = ct.split_off(ct.len() - 16);
    serde_json::json!({"protected": prot, "encrypted_key": B64U.encode(ek), "iv": B64U.encode(iv),
        "ciphertext": B64U.encode(ct), "tag": B64U.encode(tag)}).to_string()
}

#[test]
fn the_seed_is_released_by_attestation() {
    let seed = [42u8; 32];
    let st = Arc::new(Mutex::new(Fake { stored: Some(B64.encode(seed).into_bytes()), pubkey: None, created: vec![], report_ok: false }));
    let url = serve(st.clone());
    assert_eq!(notary_seed(&url, "1", None, "notary-bootstrap", "/nonexistent").unwrap(), seed);
    assert!(st.lock().unwrap().report_ok, "report data binds nonce and TEE key");
    assert!(st.lock().unwrap().created.is_empty());
}

#[test]
fn first_start_generates_inside_and_stores_create_only() {
    let st = Arc::new(Mutex::new(Fake { stored: None, pubkey: None, created: vec![], report_ok: false }));
    let url = serve(st.clone());
    // without bootstrap: refuse rather than invent a key
    assert!(notary_seed(&url, "1", None, "notary-bootstrap", "/nonexistent").is_err());
    let jwt = std::env::temp_dir().join("notary-test-jwt");
    std::fs::write(&jwt, "eyJ.test.jwt").unwrap();
    let seed = notary_seed(&url, "1", Some(&url), "notary-bootstrap", jwt.to_str().unwrap()).unwrap();
    let created = st.lock().unwrap().created.clone();
    assert_eq!(created.len(), 1);
    let stored: serde_json::Value = serde_json::from_str(&created[0]).unwrap();
    assert_eq!(B64.decode(stored["data"].as_str().unwrap()).unwrap(), seed.to_vec());
}
