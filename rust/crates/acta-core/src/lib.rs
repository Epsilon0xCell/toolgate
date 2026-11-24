//! acta-core: the Acta receipt core.
//!
//! Author: Gavin Blacklock
//!
//! One library implements the receipt model, deterministic CBOR,
//! DSSE-style envelope signing with Ed25519, and hash-chain
//! verification, so the CLI, the offline verifier, ToolGate, and
//! Institutio tooling all call the same code (specification
//! Section 3.2).
//!
//! Determinism rules enforced here: integer arithmetic only (no
//! floating point type exists in this crate's public types and clippy
//! denies float arithmetic workspace-wide), BTreeMap wherever
//! iteration order could matter, no wall clock, no randomness, no
//! environment access in normative code.
//!
//! The [`legacy`] module is the documented compatibility path for the
//! Python prototype's canonical-JSON and HMAC-placeholder format; it
//! exists for conformance testing and is never used for native
//! receipts.

#![deny(missing_docs)]

pub mod bundle;
pub mod cbor;
pub mod chain;
pub mod error;
pub mod legacy;
pub mod receipt;
pub mod signing;

pub use chain::{chain_head, verify_chain, ChainVerdict};
pub use error::{ActaError, Result};
pub use receipt::{
    build_receipt, Action, Agent, DenialReason, Effects, Envelope, Receipt, ReceiptDraft,
    ReceiptType, SignedReceipt, SignatureEntry, GENESIS_HASH, PAYLOAD_TYPE, RECEIPT_VERSION,
};
pub use signing::{Ed25519Signer, Signer, TrustSet};
