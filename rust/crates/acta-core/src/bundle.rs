//! JSON transport form for native receipt bundles.
//!
//! Author: Gavin Blacklock
//!
//! JSON here is only a transport wrapper: the signed payload travels
//! as base64 of the exact deterministic CBOR bytes, and the body a
//! verifier checks is decoded from those bytes, never re-serialised
//! from the JSON. Pretty-printing the wrapper therefore cannot
//! invalidate a receipt, and altering the base64 payload is tampering
//! that verification detects.

use crate::cbor;
use crate::error::{ActaError, Result};
use crate::receipt::{Envelope, Receipt, SignedReceipt, SignatureEntry};
use base64::Engine;
use serde_json::{json, Map, Value};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Bundle format marker for the native CBOR transport form.
pub const BUNDLE_FORMAT: &str = "acta-cbor-v1";

/// Serialise one signed receipt to its transport JSON form.
pub fn signed_receipt_to_json(signed: &SignedReceipt) -> Value {
    let signatures: Vec<Value> = signed
        .envelope
        .signatures
        .iter()
        .map(|entry| {
            json!({
                "key_id": entry.key_id,
                "signature": B64.encode(&entry.signature),
                "verifying_key": B64.encode(&entry.verifying_key),
            })
        })
        .collect();
    json!({
        "receipt_hash": signed.receipt_hash,
        "envelope": {
            "payload_type": signed.envelope.payload_type,
            "payload": B64.encode(&signed.envelope.payload),
            "signatures": signatures,
        }
    })
}

/// Parse one signed receipt from its transport JSON form. The body is
/// decoded from the envelope payload bytes (the exact transmitted
/// bytes), and the recorded hash is carried, not recomputed here;
/// recomputation is verification's job.
pub fn signed_receipt_from_json(value: &Value) -> Result<SignedReceipt> {
    let obj = value
        .as_object()
        .ok_or_else(|| ActaError::InvalidReceipt("receipt entry is not an object".into()))?;
    let receipt_hash = obj
        .get("receipt_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| ActaError::InvalidReceipt("receipt_hash missing".into()))?
        .to_string();
    let envelope = obj
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or_else(|| ActaError::InvalidEnvelope("envelope missing".into()))?;
    let payload_type = envelope
        .get("payload_type")
        .and_then(Value::as_str)
        .ok_or_else(|| ActaError::InvalidEnvelope("payload_type missing".into()))?
        .to_string();
    let payload = decode_b64(envelope, "payload")?;
    let body_value = cbor::decode(&payload)?;
    let body = Receipt::from_cbor(&body_value)?;
    let mut signatures = Vec::new();
    if let Some(entries) = envelope.get("signatures").and_then(Value::as_array) {
        for entry in entries {
            let entry_obj: &Map<String, Value> = entry.as_object().ok_or_else(|| {
                ActaError::InvalidEnvelope("signature entry is not an object".into())
            })?;
            signatures.push(SignatureEntry {
                key_id: entry_obj
                    .get("key_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                signature: decode_b64(entry_obj, "signature")?,
                verifying_key: decode_b64(entry_obj, "verifying_key")?,
            });
        }
    }
    Ok(SignedReceipt {
        body,
        receipt_hash,
        envelope: Envelope {
            payload_type,
            payload,
            signatures,
        },
    })
}

fn decode_b64(obj: &Map<String, Value>, field: &str) -> Result<Vec<u8>> {
    let text = obj
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ActaError::InvalidEnvelope(format!("{field} missing")))?;
    B64.decode(text).map_err(|_| {
        ActaError::InvalidEnvelope(format!("{field} is not valid base64"))
    })
}

/// Serialise a whole chain as a bundle JSON document.
pub fn bundle_to_json(receipts: &[SignedReceipt]) -> Value {
    json!({
        "bundle_version": crate::receipt::RECEIPT_VERSION,
        "format": BUNDLE_FORMAT,
        "receipts": receipts.iter().map(signed_receipt_to_json).collect::<Vec<_>>(),
    })
}

/// Parse a bundle JSON document into signed receipts.
pub fn bundle_from_json(value: &Value) -> Result<Vec<SignedReceipt>> {
    let receipts = match value {
        Value::Object(map) => map
            .get("receipts")
            .and_then(Value::as_array)
            .ok_or_else(|| ActaError::InvalidReceipt("bundle has no receipts list".into()))?,
        Value::Array(items) => items,
        _ => return Err(ActaError::InvalidReceipt("bundle is not an object".into())),
    };
    receipts.iter().map(signed_receipt_from_json).collect()
}
