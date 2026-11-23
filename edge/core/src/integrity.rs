//! Blake3 integrity for everything the device keeps at rest or loads from disk: the wallet document, the sealed key
//! store and the rule components. A sealed blob is `MAGIC || blake3(body) || body`; unsealing recomputes the digest
//! and refuses a blob that was truncated, corrupted or edited. This is integrity, not confidentiality: on Android the
//! file sits in app-private storage and the keys never leave StrongBox/KeyMint (see tee.rs).

use crate::Error;

const MAGIC: &[u8; 8] = b"DIFMEB3\x01";
pub const DIGEST_LEN: usize = 32;

/// Blake3 digest as lowercase hex.
pub fn hex_digest(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn seal(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + DIGEST_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out.extend_from_slice(body);
    out
}

pub fn unseal(blob: &[u8]) -> Result<&[u8], Error> {
    let header = MAGIC.len() + DIGEST_LEN;
    if blob.len() < header || &blob[..MAGIC.len()] != MAGIC {
        return Err(Error::Integrity("not a sealed blob".into()));
    }
    let (digest, body) = blob[MAGIC.len()..].split_at(DIGEST_LEN);
    // blake3::Hash's PartialEq is constant-time.
    if blake3::hash(body) != blake3::Hash::from_bytes(digest.try_into().expect("32 bytes")) {
        return Err(Error::Integrity("Blake3 digest mismatch".into()));
    }
    Ok(body)
}

/// Checks `data` against a pinned Blake3 digest (hex).
pub fn verify_pinned(data: &[u8], expected_hex: &str) -> Result<(), Error> {
    let expected = blake3::Hash::from_hex(expected_hex).map_err(|e| Error::Integrity(format!("bad pinned digest: {e}")))?;
    if blake3::hash(data) == expected {
        Ok(())
    } else {
        Err(Error::Integrity(format!("Blake3 digest {} does not match the pinned {expected_hex}", hex_digest(data))))
    }
}

/// SHA-256 as lowercase hex: the verifier's `binary_hash` check compares this form (SLSA provenance digests).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::Integrity("odd-length hex".into()));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| Error::Integrity(e.to_string()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trips_and_detects_tampering() {
        let blob = seal(b"wallet bytes");
        assert_eq!(unseal(&blob).unwrap(), b"wallet bytes");
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(unseal(&bad).is_err());
        assert!(unseal(&blob[..blob.len() - 1]).is_err());
        assert!(unseal(b"short").is_err());
    }

    #[test]
    fn pinned_digest() {
        let d = hex_digest(b"rule");
        verify_pinned(b"rule", &d).unwrap();
        assert!(verify_pinned(b"rulf", &d).is_err());
    }
}
