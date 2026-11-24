//! Typed errors for acta-core.
//!
//! Author: Gavin Blacklock
//!
//! Every validation failure is a named variant. In particular a DENIAL
//! receipt without a valid reason code fails with
//! [`ActaError::DenialReasonMissing`], mirroring the Python prototype's
//! `DENIAL_REASON_MISSING` failure code, so the failure is a typed,
//! matchable value rather than a string a caller might ignore.

use std::fmt;

/// Failure codes that intentionally match the Python prototype's
/// verification failure codes, so conformance verdicts compare equal
/// across implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActaError {
    /// CBOR input is not in deterministic (canonical) form, or is
    /// otherwise malformed. The decoder rejects; it never repairs.
    NonCanonicalCbor(String),
    /// CBOR input ended early.
    UnexpectedEof,
    /// Trailing bytes after a complete CBOR item.
    TrailingBytes,
    /// A CBOR type this format does not admit (floats, tags, breaks).
    UnsupportedCborType(String),
    /// A receipt field is missing, mistyped, or out of bounds.
    InvalidReceipt(String),
    /// A receipt type string is not GRANT, ACTION, or DENIAL.
    UnknownReceiptType(String),
    /// A DENIAL receipt carries no reason code, or one outside the
    /// v0.1 set of specification Section 3.5.
    DenialReasonMissing(String),
    /// A reason code was supplied on a non-DENIAL receipt.
    ReasonCodeOnNonDenial,
    /// Sequence numbers do not match chain positions: the chain is
    /// reordered or has a gap.
    Reordered(String),
    /// Two receipts in one chain carry the same receipt_id.
    /// Receipt identities are unique (specification Section
    /// 16.10, decision 19); the Python prototype rejects the same
    /// chain with the same code.
    DuplicateReceiptId(String),
    /// A prior_receipt_hash does not match the previous receipt hash.
    ChainBreak(String),
    /// A recomputed hash, or the envelope payload bytes, do not match
    /// what was recorded: a signed field was altered.
    Tampered(String),
    /// The DSSE envelope is missing, mistyped, or malformed.
    InvalidEnvelope(String),
    /// The envelope carries no signatures.
    Unsigned(String),
    /// No signature from the expected key identifier.
    KeyIdMismatch(String),
    /// A signature does not verify over the PAE of the exact bytes.
    SignatureInvalid(String),
    /// A signature entry names a key the verifier's pinned trust set
    /// does not contain, or carries a verifying key that differs
    /// from the pinned key for its key id (audit finding C1).
    UntrustedKey(String),
    /// The chain head or length does not match an externally supplied
    /// expectation: the chain is truncated or substituted.
    Truncated(String),
    /// Canonical-JSON compatibility path hit a value it cannot encode
    /// byte-identically (for example a non-integer number).
    UnsupportedJsonValue(String),
}

impl ActaError {
    /// Stable machine-readable code, aligned with the Python prototype
    /// where a corresponding failure exists there.
    pub fn code(&self) -> &'static str {
        match self {
            ActaError::NonCanonicalCbor(_) => "NON_CANONICAL_CBOR",
            ActaError::UnexpectedEof => "UNEXPECTED_EOF",
            ActaError::TrailingBytes => "TRAILING_BYTES",
            ActaError::UnsupportedCborType(_) => "UNSUPPORTED_CBOR_TYPE",
            ActaError::InvalidReceipt(_) => "INVALID_RECEIPT",
            ActaError::UnknownReceiptType(_) => "INVALID_RECEIPT",
            ActaError::DenialReasonMissing(_) => "DENIAL_REASON_MISSING",
            ActaError::ReasonCodeOnNonDenial => "INVALID_RECEIPT",
            ActaError::Reordered(_) => "REORDERED",
            ActaError::DuplicateReceiptId(_) => "DUPLICATE_RECEIPT_ID",
            ActaError::ChainBreak(_) => "CHAIN_BREAK",
            ActaError::Tampered(_) => "TAMPERED",
            ActaError::InvalidEnvelope(_) => "INVALID_ENVELOPE",
            ActaError::Unsigned(_) => "UNSIGNED",
            ActaError::KeyIdMismatch(_) => "KEY_ID_MISMATCH",
            ActaError::SignatureInvalid(_) => "SIGNATURE_INVALID",
            ActaError::UntrustedKey(_) => "UNTRUSTED_KEY",
            ActaError::Truncated(_) => "TRUNCATED",
            ActaError::UnsupportedJsonValue(_) => "UNSUPPORTED_JSON_VALUE",
        }
    }
}

impl fmt::Display for ActaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            ActaError::NonCanonicalCbor(s)
            | ActaError::UnsupportedCborType(s)
            | ActaError::InvalidReceipt(s)
            | ActaError::UnknownReceiptType(s)
            | ActaError::DenialReasonMissing(s)
            | ActaError::Reordered(s)
            | ActaError::DuplicateReceiptId(s)
            | ActaError::ChainBreak(s)
            | ActaError::Tampered(s)
            | ActaError::InvalidEnvelope(s)
            | ActaError::Unsigned(s)
            | ActaError::KeyIdMismatch(s)
            | ActaError::SignatureInvalid(s)
            | ActaError::UntrustedKey(s)
            | ActaError::Truncated(s)
            | ActaError::UnsupportedJsonValue(s) => s.as_str(),
            ActaError::UnexpectedEof => "unexpected end of CBOR input",
            ActaError::TrailingBytes => "trailing bytes after CBOR item",
            ActaError::ReasonCodeOnNonDenial => {
                "reason_code is only valid on DENIAL receipts"
            }
        };
        write!(f, "{}: {}", self.code(), detail)
    }
}

impl std::error::Error for ActaError {}

/// Result alias used throughout acta-core.
pub type Result<T> = std::result::Result<T, ActaError>;
