//! Native hash-chain verification.
//!
//! Author: Gavin Blacklock
//!
//! Mirrors the Python prototype's `verify_chain` check order and
//! failure codes, over the native CBOR format: structure, sequence,
//! prior-hash linkage, recomputed hash, envelope payload bytes,
//! signature presence, expected key, signature validity, and finally
//! truncation against an externally supplied head or length.
//! Truncation is only detectable against an expectation from outside
//! the chain, for example an anchored ledger head; that is why those
//! parameters exist, in both implementations.

use crate::error::{ActaError, Result};
use crate::receipt::{SignedReceipt, PAYLOAD_TYPE};
use crate::signing::{verify_ed25519, TrustSet};
use crate::cbor;

/// Outcome of a successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict {
    /// Number of receipts verified.
    pub length: usize,
    /// Hex hash of the last receipt, or the genesis hash when empty.
    pub head: String,
}

/// Verify a native chain against a pinned trust set. On failure
/// the error carries the index of the first failing receipt in its
/// message and a stable code.
///
/// The trust set is the verifier operator's own input (a trust
/// file, or the charter key set): a signature counts only when it
/// verifies under the pinned key for its claimed key id. The
/// verifying key carried inside the envelope is never trusted
/// (audit finding C1); if it differs from the pinned key for its
/// key id, the receipt is rejected as UNTRUSTED_KEY.
pub fn verify_chain(
    receipts: &[SignedReceipt],
    trust: &TrustSet,
    expected_head: Option<&str>,
    expected_length: Option<usize>,
) -> Result<ChainVerdict> {
    if receipts.is_empty() {
        // Re-audit minor r5: an empty bundle is not a verified
        // chain and must not return the same verdict as one.
        return Err(ActaError::InvalidReceipt(
            "empty chain: no receipts to verify".into(),
        ));
    }
    let mut previous_hash = crate::receipt::GENESIS_HASH.to_string();
    let mut seen_receipt_ids: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();
    for (index, signed) in receipts.iter().enumerate() {
        let body = &signed.body;
        let at = |e: ActaError| add_index(e, index, &body.receipt_id);
        body.validate_structure().map_err(at)?;
        // Receipt identities are unique (Section 16.10, decision
        // 19): a chain carrying two receipts with one receipt_id
        // is invalid and is rejected at verification, as the
        // Python prototype rejects it. This tree once accepted
        // such a chain (third re-audit finding T2).
        if !seen_receipt_ids.insert(body.receipt_id.as_str()) {
            return Err(at(ActaError::DuplicateReceiptId(format!(
                "receipt_id {} appears more than once in the chain; \
                 receipt identities are unique",
                body.receipt_id
            ))));
        }
        if body.sequence != index as u64 {
            return Err(at(ActaError::Reordered(format!(
                "sequence is {}, expected {index}; the chain is reordered or has a gap",
                body.sequence
            ))));
        }
        if body.prior_receipt_hash != previous_hash {
            return Err(at(ActaError::ChainBreak(
                "prior_receipt_hash does not match the hash of the previous receipt".into(),
            )));
        }
        if body.compute_hash() != signed.receipt_hash {
            return Err(at(ActaError::Tampered(
                "recomputed hash does not match the recorded receipt_hash; \
                 a signed field was altered"
                    .into(),
            )));
        }
        let envelope = &signed.envelope;
        if envelope.payload_type != PAYLOAD_TYPE {
            return Err(at(ActaError::InvalidEnvelope(
                "missing or mistyped DSSE envelope".into(),
            )));
        }
        // The envelope must carry the exact transmitted bytes of this
        // body, and those bytes must decode to this same body. The
        // signature check below runs over the envelope bytes as
        // received, never over a re-serialisation.
        if envelope.payload != body.canonical_bytes() {
            return Err(at(ActaError::Tampered(
                "envelope payload bytes do not match the receipt fields".into(),
            )));
        }
        let decoded = cbor::decode(&envelope.payload).map_err(at)?;
        let reparsed = crate::receipt::Receipt::from_cbor(&decoded).map_err(at)?;
        if reparsed != *body {
            return Err(at(ActaError::Tampered(
                "envelope payload decodes to a different receipt".into(),
            )));
        }
        if envelope.signatures.is_empty() {
            return Err(at(ActaError::Unsigned(
                "envelope carries no signatures".into(),
            )));
        }
        let mut saw_pinned_key = false;
        let mut any_valid = false;
        for entry in &envelope.signatures {
            let Some(pinned) = trust.get(&entry.key_id) else {
                continue;
            };
            saw_pinned_key = true;
            if entry.verifying_key != pinned.to_bytes().to_vec() {
                return Err(at(ActaError::UntrustedKey(format!(
                    "envelope carries a verifying key for key id {} that \
                     differs from the pinned key in the trust set",
                    entry.key_id
                ))));
            }
            if verify_ed25519(
                pinned,
                &envelope.payload_type,
                &envelope.payload,
                &entry.signature,
            ) {
                any_valid = true;
            }
        }
        if !saw_pinned_key {
            return Err(at(ActaError::UntrustedKey(
                "no signature from any key in the pinned trust set".into(),
            )));
        }
        if !any_valid {
            return Err(at(ActaError::SignatureInvalid(
                "envelope signature does not verify under the pinned key".into(),
            )));
        }
        previous_hash = signed.receipt_hash.clone();
    }
    if let Some(expected) = expected_length {
        if receipts.len() != expected {
            return Err(ActaError::Truncated(format!(
                "chain has {} receipts, expected {expected}",
                receipts.len()
            )));
        }
    }
    if let Some(expected) = expected_head {
        if previous_hash != expected {
            return Err(ActaError::Truncated(format!(
                "chain head {previous_hash} does not match the expected head {expected}; \
                 the chain is truncated or substituted"
            )));
        }
    }
    Ok(ChainVerdict {
        length: receipts.len(),
        head: previous_hash,
    })
}

fn add_index(error: ActaError, index: usize, receipt_id: &str) -> ActaError {
    let detail = error.to_string();
    let message = format!("receipt {index} ({receipt_id}): {detail}");
    match error {
        ActaError::Reordered(_) => ActaError::Reordered(message),
        ActaError::DuplicateReceiptId(_) => ActaError::DuplicateReceiptId(message),
        ActaError::ChainBreak(_) => ActaError::ChainBreak(message),
        ActaError::Tampered(_) => ActaError::Tampered(message),
        ActaError::InvalidEnvelope(_) => ActaError::InvalidEnvelope(message),
        ActaError::Unsigned(_) => ActaError::Unsigned(message),
        ActaError::KeyIdMismatch(_) => ActaError::KeyIdMismatch(message),
        ActaError::SignatureInvalid(_) => ActaError::SignatureInvalid(message),
        ActaError::UntrustedKey(_) => ActaError::UntrustedKey(message),
        ActaError::DenialReasonMissing(_) => ActaError::DenialReasonMissing(message),
        ActaError::InvalidReceipt(_) => ActaError::InvalidReceipt(message),
        other => other,
    }
}

/// Hash of the last receipt in a chain, or the genesis hash.
pub fn chain_head(receipts: &[SignedReceipt]) -> String {
    receipts
        .last()
        .map(|r| r.receipt_hash.clone())
        .unwrap_or_else(|| crate::receipt::GENESIS_HASH.to_string())
}
