//! Python prototype compatibility path.
//!
//! Author: Gavin Blacklock
//!
//! The Python prototype in `code/` is the semantic reference for this
//! crate. Its wire format differs from the native format in three
//! explicit ways, and this module exists so the conformance runner
//! can apply the prototype's fixtures exactly as written instead of
//! pretending the formats are the same:
//!
//! 1. Encoding: the prototype hashes and signs canonical JSON (sorted
//!    keys, no insignificant whitespace, UTF-8). The native format
//!    uses deterministic CBOR. This module reproduces the prototype's
//!    canonical JSON byte for byte for JSON values whose numbers are
//!    integers; anything else is [`ActaError::UnsupportedJsonValue`].
//! 2. Hash: the prototype's receipt hash is the plain SHA-256 of the
//!    canonical JSON payload. The native hash is domain-separated
//!    over CBOR. Same chain semantics, different bytes.
//! 3. Signatures: the prototype signs with an HMAC-SHA256 placeholder
//!    behind its signer interface. This module verifies those
//!    signatures with the shared fixture secret. Native receipts use
//!    Ed25519 and never this path.
//!
//! Check order and failure codes mirror `acta/receipts.py`
//! `verify_chain` in the prototype, so a verdict here and a verdict
//! there are directly comparable.

use crate::error::{ActaError, Result};
use crate::signing::{hex_encode, is_hash_hex, sha256, HmacSigner, Signer};
use serde_json::Value;
use std::collections::BTreeMap;

/// Payload type used by the Python prototype.
pub const LEGACY_PAYLOAD_TYPE: &str = "application/vnd.acta.receipt.v0.1+json";

/// The prototype's current receipt type set (`acta/receipts.py`
/// RECEIPT_TYPES): the three core types plus the Standing derived
/// types of specification Section 16.3 and REVOCATION (Section 7.3
/// ticket T1). Anything outside this set, for example TRANSFER, must
/// reject as an unknown type, never be ignored.
const LEGACY_RECEIPT_TYPES: [&str; 8] = [
    "GRANT",
    "ACTION",
    "DENIAL",
    "BURN",
    "PROMOTION",
    "DEMOTION",
    "REVOCATION",
    "KILL-BURN",
];
const LEGACY_REASON_CODES: [&str; 5] = [
    "revoked",
    "scope",
    "manifest-mismatch",
    "budget",
    "standing-ceiling",
];
const REQUIRED_FIELDS: [&str; 12] = [
    "receipt_version",
    "receipt_id",
    "receipt_type",
    "sequence",
    "timestamp",
    "delegator",
    "agent",
    "scope_granted",
    "action",
    "result_hash",
    "effects",
    "prior_receipt_hash",
];

/// Canonical JSON bytes, byte-identical to the prototype's
/// `canonical_bytes`: object keys sorted, separators `,` and `:`,
/// non-ASCII text emitted as raw UTF-8, strings escaped the way
/// Python's `json.dumps` with `ensure_ascii=False` escapes them.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(ActaError::UnsupportedJsonValue(format!(
                    "non-integer number {n} cannot be encoded byte-identically"
                )));
            }
        }
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort by key. serde_json's default map is already a
            // BTreeMap; sorting again here makes the order explicit
            // and independent of build features.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (key, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_json_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// The signed payload view of a prototype receipt: every field except
/// `receipt_hash` and `envelope`.
pub fn legacy_payload_view(receipt: &Value) -> Value {
    match receipt {
        Value::Object(map) => {
            let kept: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "receipt_hash" && k.as_str() != "envelope")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Value::Object(kept)
        }
        other => other.clone(),
    }
}

/// Recompute a prototype receipt hash.
pub fn legacy_receipt_hash(receipt: &Value) -> Result<String> {
    Ok(hex_encode(&sha256(&canonical_json_bytes(
        &legacy_payload_view(receipt),
    )?)))
}

/// Outcome of a legacy chain verification, with the first failure
/// located, mirroring the prototype's VerificationResult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyVerdict {
    /// True when the chain verified.
    pub ok: bool,
    /// Index of the first failing receipt, when any.
    pub failure_index: Option<usize>,
    /// Stable failure code, when any.
    pub failure_code: Option<String>,
    /// Human-readable detail.
    pub message: String,
}

fn fail(index: usize, code: &str, message: String) -> LegacyVerdict {
    LegacyVerdict {
        ok: false,
        failure_index: Some(index),
        failure_code: Some(code.to_string()),
        message,
    }
}

/// Verify a prototype-format receipt chain, with the prototype's
/// HMAC placeholder verifier. `secret` is the shared fixture secret;
/// the prototype reads it from its fixture secret file.
pub fn verify_legacy_chain(
    receipts: &[Value],
    secret: &[u8],
    expected_key_id: Option<&str>,
    expected_head: Option<&str>,
    expected_length: Option<usize>,
) -> LegacyVerdict {
    let verifier = HmacSigner::new(expected_key_id.unwrap_or(""), secret.to_vec());
    let genesis = "0".repeat(64);
    let mut previous_hash = genesis.clone();
    let mut seen_receipt_ids: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let obj = match receipt {
            Value::Object(map) => map,
            _ => {
                return fail(
                    index,
                    "INVALID_RECEIPT",
                    "receipt is not a JSON object".into(),
                )
            }
        };
        // Receipt identities are unique (Section 16.10, decision
        // 19), checked first in the loop as the prototype checks
        // it: a chain carrying two receipts with one receipt_id
        // is invalid (third re-audit finding T2).
        if let Some(receipt_id) = obj.get("receipt_id").and_then(Value::as_str) {
            if !seen_receipt_ids.insert(receipt_id) {
                return fail(
                    index,
                    "DUPLICATE_RECEIPT_ID",
                    format!(
                        "receipt_id {receipt_id} duplicates an earlier \
                         receipt in this chain; receipt identities are unique"
                    ),
                );
            }
        }
        for field in REQUIRED_FIELDS {
            if !obj.contains_key(field) {
                return fail(
                    index,
                    "INVALID_RECEIPT",
                    format!("missing required field: {field}"),
                );
            }
        }
        let receipt_type = obj.get("receipt_type").and_then(Value::as_str).unwrap_or("");
        if !LEGACY_RECEIPT_TYPES.contains(&receipt_type) {
            return fail(
                index,
                "INVALID_RECEIPT",
                format!("unknown receipt_type: {receipt_type}"),
            );
        }
        let agent_ok = obj
            .get("agent")
            .and_then(Value::as_object)
            .map(|a| {
                a.contains_key("id")
                    && a.contains_key("model")
                    && a.contains_key("model_version")
            })
            .unwrap_or(false);
        if !agent_ok {
            return fail(
                index,
                "INVALID_RECEIPT",
                "agent must carry id, model and model_version".into(),
            );
        }
        let action_ok = obj
            .get("action")
            .and_then(Value::as_object)
            .map(|a| {
                a.contains_key("name")
                    && a.get("arguments_hash")
                        .and_then(Value::as_str)
                        .map(is_hash_hex)
                        .unwrap_or(false)
            })
            .unwrap_or(false);
        if !action_ok {
            return fail(
                index,
                "INVALID_RECEIPT",
                "action must carry a name and a hex arguments_hash".into(),
            );
        }
        for field in ["result_hash", "prior_receipt_hash"] {
            let value = obj.get(field).and_then(Value::as_str).unwrap_or("");
            if !is_hash_hex(value) {
                return fail(
                    index,
                    "INVALID_RECEIPT",
                    format!("{field} must be a hex hash"),
                );
            }
        }
        if receipt_type == "DENIAL" {
            let code = obj.get("reason_code").and_then(Value::as_str);
            if !code.map(|c| LEGACY_REASON_CODES.contains(&c)).unwrap_or(false) {
                return fail(
                    index,
                    "DENIAL_REASON_MISSING",
                    format!(
                        "DENIAL receipt has no valid reason_code (got {code:?}); \
                         a denial without a reason code is non-conforming"
                    ),
                );
            }
        }
        let sequence = obj.get("sequence").and_then(Value::as_u64);
        if sequence != Some(index as u64) {
            return fail(
                index,
                "REORDERED",
                format!(
                    "sequence is {:?}, expected {index}; the chain is \
                     reordered or has a gap",
                    obj.get("sequence")
                ),
            );
        }
        if obj.get("prior_receipt_hash").and_then(Value::as_str) != Some(previous_hash.as_str()) {
            return fail(
                index,
                "CHAIN_BREAK",
                "prior_receipt_hash does not match the hash of the previous receipt".into(),
            );
        }
        let recorded_hash = obj.get("receipt_hash").and_then(Value::as_str).unwrap_or("");
        match legacy_receipt_hash(receipt) {
            Ok(recomputed) if recomputed == recorded_hash => {}
            Ok(_) => {
                return fail(
                    index,
                    "TAMPERED",
                    "recomputed hash does not match the recorded receipt_hash; \
                     a signed field was altered"
                        .into(),
                )
            }
            Err(e) => return fail(index, e.code(), e.to_string()),
        }
        let envelope = obj.get("envelope").and_then(Value::as_object);
        let envelope = match envelope {
            Some(e) if e.get("payload_type").and_then(Value::as_str) == Some(LEGACY_PAYLOAD_TYPE) => e,
            _ => {
                return fail(
                    index,
                    "INVALID_ENVELOPE",
                    "missing or mistyped DSSE envelope".into(),
                )
            }
        };
        use base64::Engine;
        let payload_b64 = envelope.get("payload").and_then(Value::as_str).unwrap_or("");
        let payload_bytes = match base64::engine::general_purpose::STANDARD.decode(payload_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return fail(
                    index,
                    "INVALID_ENVELOPE",
                    "envelope payload is not valid base64".into(),
                )
            }
        };
        match canonical_json_bytes(&legacy_payload_view(receipt)) {
            Ok(expected) if expected == payload_bytes => {}
            Ok(_) => {
                return fail(
                    index,
                    "TAMPERED",
                    "envelope payload bytes do not match the receipt fields".into(),
                )
            }
            Err(e) => return fail(index, e.code(), e.to_string()),
        }
        let empty: Vec<Value> = Vec::new();
        let signatures = envelope
            .get("signatures")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        if signatures.is_empty() {
            return fail(index, "UNSIGNED", "envelope carries no signatures".into());
        }
        if let Some(expected) = expected_key_id {
            if !signatures
                .iter()
                .any(|s| s.get("key_id").and_then(Value::as_str) == Some(expected))
            {
                return fail(
                    index,
                    "KEY_ID_MISMATCH",
                    format!("no signature from expected key id {expected}"),
                );
            }
        }
        let any_valid = signatures.iter().any(|sig| {
            if let Some(expected) = expected_key_id {
                if sig.get("key_id").and_then(Value::as_str) != Some(expected) {
                    return false;
                }
            }
            let sig_b64 = sig.get("signature").and_then(Value::as_str).unwrap_or("");
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
                Ok(bytes) => verifier.verify_pae(LEGACY_PAYLOAD_TYPE, &payload_bytes, &bytes),
                Err(_) => false,
            }
        });
        if !any_valid {
            return fail(
                index,
                "SIGNATURE_INVALID",
                "envelope signature does not verify".into(),
            );
        }
        previous_hash = recorded_hash.to_string();
    }
    if let Some(expected) = expected_length {
        if receipts.len() != expected {
            let code = if receipts.len() < expected {
                "TRUNCATED"
            } else {
                "LENGTH_MISMATCH"
            };
            return LegacyVerdict {
                ok: false,
                failure_index: Some(receipts.len()),
                failure_code: Some(code.to_string()),
                message: format!(
                    "chain has {} receipts, expected {expected}",
                    receipts.len()
                ),
            };
        }
    }
    if let Some(expected) = expected_head {
        if previous_hash != expected {
            return LegacyVerdict {
                ok: false,
                failure_index: Some(receipts.len()),
                failure_code: Some("TRUNCATED".to_string()),
                message: format!(
                    "chain head {previous_hash} does not match the expected \
                     head {expected}; the chain is truncated or substituted"
                ),
            };
        }
    }
    LegacyVerdict {
        ok: true,
        failure_index: None,
        failure_code: None,
        message: format!("chain verified: {} receipts", receipts.len()),
    }
}

/// Group legacy helpers by fixture kind for the conformance runner:
/// scope attenuation over plain JSON values, used only for the
/// prototype's charter fixture. Full charter validation belongs to
/// institutio-core, which is outside this workspace; see the
/// conformance runner documentation for the adaptation note.
pub fn scope_exceeds(child: &Value, parent: &Value) -> bool {
    for field in ["tools", "resources", "operations"] {
        let child_set: Vec<&str> = child
            .get(field)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let parent_set: Vec<&str> = parent
            .get(field)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if child_set.iter().any(|item| !parent_set.contains(item)) {
            return true;
        }
    }
    if let (Some(child_limits), Some(parent_limits)) = (
        child.get("limits").and_then(Value::as_object),
        parent.get("limits").and_then(Value::as_object),
    ) {
        for (key, value) in child_limits {
            let child_amount = value.as_i64().unwrap_or(0);
            let parent_amount = parent_limits
                .get(key)
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if child_amount > parent_amount {
                return true;
            }
        }
    }
    let _ = BTreeMap::<String, Value>::new();
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_and_compacts() {
        let value = serde_json::json!({"b": 1, "a": [true, null, "x"]});
        assert_eq!(
            canonical_json_bytes(&value).unwrap(),
            br#"{"a":[true,null,"x"],"b":1}"#.to_vec()
        );
    }

    #[test]
    fn canonical_json_rejects_floats() {
        let value = serde_json::json!({"a": 1.5});
        assert!(canonical_json_bytes(&value).is_err());
    }

    #[test]
    fn test_t2_duplicate_receipt_id_rejected() {
        // Third re-audit finding T2 (repair round 4): the
        // prototype path applies decision 19 as the prototype
        // does: a chain carrying two receipts with one
        // receipt_id is rejected as DUPLICATE_RECEIPT_ID. Both
        // receipts below are fully valid and hash-linked; only
        // the duplicated identity is wrong.
        use base64::Engine;
        let secret = b"legacy-test-secret";
        let signer = HmacSigner::new("acta-test-key-1", secret.to_vec());
        let genesis = "0".repeat(64);
        let make = |sequence: u64, prior: &str| -> Value {
            let mut receipt = serde_json::json!({
                "receipt_version": "0.1",
                "receipt_id": "dup-id",
                "receipt_type": "ACTION",
                "sequence": sequence,
                "timestamp": 1_763_900_000_i64 + sequence as i64,
                "delegator": "seat-founder",
                "agent": {"id": "agent-1", "model": "m", "model_version": "1"},
                "scope_granted": "tools=[read]",
                "action": {"name": "repo.read", "arguments_hash": "a".repeat(64)},
                "result_hash": "b".repeat(64),
                "effects": {},
                "prior_receipt_hash": prior,
            });
            let hash = legacy_receipt_hash(&receipt).unwrap();
            receipt["receipt_hash"] = Value::String(hash);
            let payload = canonical_json_bytes(&legacy_payload_view(&receipt)).unwrap();
            let signature = signer.sign_pae(LEGACY_PAYLOAD_TYPE, &payload);
            receipt["envelope"] = serde_json::json!({
                "payload_type": LEGACY_PAYLOAD_TYPE,
                "payload": base64::engine::general_purpose::STANDARD.encode(&payload),
                "signatures": [{
                    "key_id": "acta-test-key-1",
                    "signature": base64::engine::general_purpose::STANDARD
                        .encode(signature),
                }],
            });
            receipt
        };
        let first = make(0, &genesis);
        let head = first["receipt_hash"].as_str().unwrap().to_string();
        let second = make(1, &head);
        let verdict = verify_legacy_chain(
            &[first, second],
            secret,
            Some("acta-test-key-1"),
            None,
            None,
        );
        assert!(!verdict.ok, "{}", verdict.message);
        assert_eq!(
            verdict.failure_code.as_deref(),
            Some("DUPLICATE_RECEIPT_ID")
        );
    }
}
