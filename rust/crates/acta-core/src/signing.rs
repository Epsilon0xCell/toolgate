//! DSSE-style typed-envelope signing.
//!
//! Author: Gavin Blacklock
//!
//! Signatures are computed and verified over the Pre-Auth-Encoding
//! (PAE) of the payload type and the exact transmitted payload bytes.
//! A verifier never re-serialises a payload and verifies the
//! re-serialisation (blueprint rule D1).
//!
//! The production scheme is Ed25519 (RFC 8032, deterministic nonce, so
//! signing needs no randomness). The HMAC-SHA256 implementation in
//! this module exists only for the Python prototype compatibility
//! path in [`crate::legacy`]: the prototype used HMAC as a placeholder
//! behind its signer interface, and its fixtures are signed with it.

use crate::error::{ActaError, Result};
use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Build the DSSE Pre-Auth-Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, where LEN is
/// the ASCII decimal byte length.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let mut out = Vec::with_capacity(payload.len() + type_bytes.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(type_bytes.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_bytes);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// SHA-256 digest of bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Lowercase hex encoding, used for hashes at format boundaries.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode a 64-character lowercase hex hash, as used by the Python
/// prototype at its boundaries.
pub fn hex_decode_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || text != text.to_lowercase() {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// True if the value is a 64 character lowercase hex string, matching
/// the Python prototype's `is_hash_hex`.
pub fn is_hash_hex(value: &str) -> bool {
    hex_decode_32(value).is_some()
}

/// A signer signs PAE bytes for one key identifier. Callers depend on
/// this trait, never on a concrete scheme.
pub trait Signer {
    /// The key identifier carried in envelope signature entries.
    fn key_id(&self) -> &str;
    /// Sign the PAE of the payload type and the exact payload bytes.
    fn sign_pae(&self, payload_type: &str, payload: &[u8]) -> Vec<u8>;
    /// Verify a signature over the PAE of the exact payload bytes.
    fn verify_pae(&self, payload_type: &str, payload: &[u8], signature: &[u8]) -> bool;
}

/// Ed25519 signer and verifier backed by a full keypair.
pub struct Ed25519Signer {
    key_id: String,
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Build from a 32-byte seed. Key generation and custody live
    /// outside this crate; tests use fixed seeds so builds and test
    /// runs are deterministic.
    pub fn from_seed(key_id: impl Into<String>, seed: &[u8; 32]) -> Self {
        Ed25519Signer {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte verifying (public) key.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_pae(&self, payload_type: &str, payload: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(&pae(payload_type, payload));
        signature.to_bytes().to_vec()
    }

    fn verify_pae(&self, payload_type: &str, payload: &[u8], signature: &[u8]) -> bool {
        verify_ed25519(
            &self.signing_key.verifying_key(),
            payload_type,
            payload,
            signature,
        )
    }
}

/// Verify an Ed25519 signature over the PAE of the exact bytes,
/// against a standalone verifying key (the stranger's case: no
/// signing key is present at verification time).
pub fn verify_ed25519(
    verifying_key: &VerifyingKey,
    payload_type: &str,
    payload: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key
        .verify(&pae(payload_type, payload), &signature)
        .is_ok()
}

/// Parse a 32-byte verifying key.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        ActaError::InvalidEnvelope("verifying key is not 32 bytes".into())
    })?;
    VerifyingKey::from_bytes(&array)
        .map_err(|e| ActaError::InvalidEnvelope(format!("invalid verifying key: {e}")))
}

/// A pinned trust set: the verifying keys a verifier operator
/// trusts, keyed by key id, supplied from outside the data being
/// verified (a trust file, or the charter key set).
///
/// Audit finding C1: verification must never take its verifying key
/// from the untrusted envelope itself. A signature counts only when
/// it verifies under the pinned key for its claimed key id, and an
/// envelope that carries a different key for a pinned key id is
/// rejected, not believed.
#[derive(Debug, Clone, Default)]
pub struct TrustSet {
    keys: std::collections::BTreeMap<String, VerifyingKey>,
}

impl TrustSet {
    /// An empty trust set, which trusts nothing.
    pub fn new() -> Self {
        TrustSet {
            keys: std::collections::BTreeMap::new(),
        }
    }

    /// Pin one key from its 32 raw bytes.
    pub fn insert(&mut self, key_id: impl Into<String>, key_bytes: &[u8]) -> Result<()> {
        let key = verifying_key_from_bytes(key_bytes)?;
        self.keys.insert(key_id.into(), key);
        Ok(())
    }

    /// Build from (key id, 32-byte key) pairs.
    pub fn from_pairs(pairs: &[(&str, &[u8])]) -> Result<Self> {
        let mut set = TrustSet::new();
        for (key_id, bytes) in pairs {
            set.insert(*key_id, bytes)?;
        }
        Ok(set)
    }

    /// A trust set pinning exactly one signer's key.
    pub fn from_signer(signer: &Ed25519Signer) -> Self {
        let mut set = TrustSet::new();
        let key = signer.signing_key.verifying_key();
        set.keys.insert(signer.key_id.clone(), key);
        set
    }

    /// The pinned key for a key id, if pinned.
    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    /// Number of pinned keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no key is pinned.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Parse a trust file: a JSON object
    /// `{"keys": [{"key_id": "...", "verifying_key_hex": "<64 hex>"}]}`
    /// where `verifying_key_base64` may replace the hex field.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        use base64::Engine;
        let entries = value
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ActaError::InvalidEnvelope(
                    "trust set must be an object with a keys array".into(),
                )
            })?;
        let mut set = TrustSet::new();
        for entry in entries {
            let key_id = entry
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ActaError::InvalidEnvelope("trust entry has no key_id".into())
                })?;
            let bytes = if let Some(hex) = entry.get("verifying_key_hex") {
                let hex = hex.as_str().ok_or_else(|| {
                    ActaError::InvalidEnvelope(
                        "verifying_key_hex must be a string".into(),
                    )
                })?;
                hex_decode_32(hex)
                    .ok_or_else(|| {
                        ActaError::InvalidEnvelope(
                            "verifying_key_hex is not a 64 character hex key".into(),
                        )
                    })?
                    .to_vec()
            } else if let Some(b64) = entry.get("verifying_key_base64") {
                let b64 = b64.as_str().ok_or_else(|| {
                    ActaError::InvalidEnvelope(
                        "verifying_key_base64 must be a string".into(),
                    )
                })?;
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| {
                        ActaError::InvalidEnvelope(
                            "verifying_key_base64 is not valid base64".into(),
                        )
                    })?
            } else {
                return Err(ActaError::InvalidEnvelope(
                    "trust entry has neither verifying_key_hex nor \
                     verifying_key_base64"
                        .into(),
                ));
            };
            set.insert(key_id, &bytes)?;
        }
        if set.is_empty() {
            return Err(ActaError::InvalidEnvelope(
                "trust set pins no keys".into(),
            ));
        }
        Ok(set)
    }
}

/// HMAC-SHA256, implemented directly on the sha2 crate. Used only by
/// the legacy compatibility path for the Python prototype's
/// placeholder-signed fixtures; never for native Acta receipts.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend(key_block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(key_block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HMAC-SHA256 signer matching the Python prototype's placeholder
/// scheme byte for byte: it signs the same PAE and compares with
/// constant-time equality, as `hmac.compare_digest` does.
pub struct HmacSigner {
    key_id: String,
    secret: Vec<u8>,
}

impl HmacSigner {
    /// Build from the shared secret bytes and a key identifier.
    pub fn new(key_id: impl Into<String>, secret: Vec<u8>) -> Self {
        HmacSigner {
            key_id: key_id.into(),
            secret,
        }
    }
}

impl Signer for HmacSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_pae(&self, payload_type: &str, payload: &[u8]) -> Vec<u8> {
        hmac_sha256(&self.secret, &pae(payload_type, payload)).to_vec()
    }

    fn verify_pae(&self, payload_type: &str, payload: &[u8], signature: &[u8]) -> bool {
        let expected = self.sign_pae(payload_type, payload);
        expected.len() == signature.len()
            && expected
                .iter()
                .zip(signature.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_layout_matches_dsse() {
        assert_eq!(
            pae("type", b"body"),
            b"DSSEv1 4 type 4 body".to_vec()
        );
    }

    #[test]
    fn ed25519_round_trip_and_tamper() {
        let signer = Ed25519Signer::from_seed("k1", &[7u8; 32]);
        let sig = signer.sign_pae("t", b"payload");
        assert!(signer.verify_pae("t", b"payload", &sig));
        assert!(!signer.verify_pae("t", b"payloae", &sig));
        assert!(!signer.verify_pae("u", b"payload", &sig));
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        // RFC 4231 test case 1: key is 20 bytes of 0x0b, data "Hi There".
        let out = hmac_sha256(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            hex_encode(&out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
