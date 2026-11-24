//! The Acta receipt model and the native (CBOR) signed receipt.
//!
//! Author: Gavin Blacklock
//!
//! Field semantics match the Python prototype (`acta/receipts.py`) and
//! specification Section 3.1: delegator identity, agent and model and
//! version, the scope granted, the action and its arguments hash, the
//! result hash, effects (artifacts changed, external calls,
//! sub-delegations), an integer timestamp, and the prior-receipt hash
//! that forms the append-only chain.
//!
//! Encoding differs from the prototype by design, and the difference
//! is explicit: the prototype hashed canonical JSON; the native format
//! hashes deterministic CBOR with a domain tag per receipt type
//! (blueprint rules D1 and D7), so a native receipt hash and a
//! prototype receipt hash over the same fields are different bytes
//! with the same meaning. The conformance runner documents this per
//! fixture.

use crate::cbor::{self, CborValue};
use crate::error::{ActaError, Result};
use crate::signing::{hex_encode, is_hash_hex, sha256, Signer};
use std::collections::BTreeMap;

/// Receipt format version produced by this crate.
pub const RECEIPT_VERSION: &str = "0.1";

/// DSSE payload type for native CBOR receipts.
pub const PAYLOAD_TYPE: &str = "application/vnd.acta.receipt.v1+cbor";

/// The hash of the (nonexistent) receipt before the first in a chain.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Receipt types in v0.1, identical to the Python prototype's
/// RECEIPT_TYPES set. An exhaustive enum, so adding a type is a
/// deliberate, compiler-checked act. BURN, PROMOTION, DEMOTION, and
/// KILL-BURN are the Standing derived types of specification
/// Section 16.3: they record the output of a computation or an act
/// and confer nothing by themselves. REVOCATION is the receipt form
/// of the revocation act (Section 7.3 ticket T1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    /// A grant of authority.
    Grant,
    /// An action taken under a grant.
    Action,
    /// A denied action. Must carry a reason code.
    Denial,
    /// A recorded Standing burn, derived from a DENIAL.
    Burn,
    /// A recorded Standing promotion.
    Promotion,
    /// A recorded Standing demotion.
    Demotion,
    /// A revocation act, effective at its sequence number.
    Revocation,
    /// The kill burn that zeroes a seat's Standing in every class.
    KillBurn,
}

impl ReceiptType {
    /// The wire string, identical to the Python prototype's.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReceiptType::Grant => "GRANT",
            ReceiptType::Action => "ACTION",
            ReceiptType::Denial => "DENIAL",
            ReceiptType::Burn => "BURN",
            ReceiptType::Promotion => "PROMOTION",
            ReceiptType::Demotion => "DEMOTION",
            ReceiptType::Revocation => "REVOCATION",
            ReceiptType::KillBurn => "KILL-BURN",
        }
    }

    /// Parse the wire string; anything else is a typed error.
    pub fn from_wire(text: &str) -> Result<Self> {
        match text {
            "GRANT" => Ok(ReceiptType::Grant),
            "ACTION" => Ok(ReceiptType::Action),
            "DENIAL" => Ok(ReceiptType::Denial),
            "BURN" => Ok(ReceiptType::Burn),
            "PROMOTION" => Ok(ReceiptType::Promotion),
            "DEMOTION" => Ok(ReceiptType::Demotion),
            "REVOCATION" => Ok(ReceiptType::Revocation),
            "KILL-BURN" => Ok(ReceiptType::KillBurn),
            other => Err(ActaError::UnknownReceiptType(format!(
                "unknown receipt_type: {other}"
            ))),
        }
    }

    /// Domain tag for the native receipt hash (blueprint rule D7).
    /// Domain separation prevents a BURN being reinterpreted as a
    /// DEMOTION, and so on across the whole set.
    fn domain_tag(&self) -> &'static str {
        match self {
            ReceiptType::Grant => "acta/v1/receipt/GRANT",
            ReceiptType::Action => "acta/v1/receipt/ACTION",
            ReceiptType::Denial => "acta/v1/receipt/DENIAL",
            ReceiptType::Burn => "acta/v1/receipt/BURN",
            ReceiptType::Promotion => "acta/v1/receipt/PROMOTION",
            ReceiptType::Demotion => "acta/v1/receipt/DEMOTION",
            ReceiptType::Revocation => "acta/v1/receipt/REVOCATION",
            ReceiptType::KillBurn => "acta/v1/receipt/KILL-BURN",
        }
    }
}

/// Denial reason codes, specification Section 3.5 v0.1 set. The first
/// four are the Provable Kill set of ticket T2; `standing-ceiling` is
/// the Standing ground of Section 16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    /// The delegation was revoked.
    Revoked,
    /// The attempt exceeded the granted scope.
    Scope,
    /// The tool manifest did not match its pin.
    ManifestMismatch,
    /// The budget was exhausted.
    Budget,
    /// The attempt exceeded the seat's Standing ceiling.
    StandingCeiling,
}

impl DenialReason {
    /// The wire string, identical to the Python prototype's.
    pub fn as_str(&self) -> &'static str {
        match self {
            DenialReason::Revoked => "revoked",
            DenialReason::Scope => "scope",
            DenialReason::ManifestMismatch => "manifest-mismatch",
            DenialReason::Budget => "budget",
            DenialReason::StandingCeiling => "standing-ceiling",
        }
    }

    /// Parse the wire string; anything else is not a valid code.
    pub fn from_wire(text: &str) -> Option<Self> {
        match text {
            "revoked" => Some(DenialReason::Revoked),
            "scope" => Some(DenialReason::Scope),
            "manifest-mismatch" => Some(DenialReason::ManifestMismatch),
            "budget" => Some(DenialReason::Budget),
            "standing-ceiling" => Some(DenialReason::StandingCeiling),
            _ => None,
        }
    }
}

/// The acting agent: identity, model name, model version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// Agent identity.
    pub id: String,
    /// Model name.
    pub model: String,
    /// Model version.
    pub model_version: String,
}

/// The action taken or attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// Tool or action name.
    pub name: String,
    /// Hex SHA-256 of the arguments. The hash is always present even
    /// when raw arguments are included by local policy (the prototype
    /// does not include them, and neither does this model).
    pub arguments_hash: String,
}

/// What an action changed or created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effects {
    /// Files and artifacts changed, as references.
    pub artifacts_changed: Vec<String>,
    /// External calls made, as references.
    pub external_calls: Vec<String>,
    /// Sub-delegations created, as references.
    pub sub_delegations: Vec<String>,
}

/// An unsigned receipt body. All fields the signature and the chain
/// hash commit to live here; the hash and the envelope live in
/// [`SignedReceipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Specification version that produced the receipt.
    pub receipt_version: String,
    /// Unique identifier for this receipt.
    pub receipt_id: String,
    /// GRANT, ACTION, or DENIAL.
    pub receipt_type: ReceiptType,
    /// Position in the chain, starting at 0.
    pub sequence: u64,
    /// Integer seconds, supplied by the caller. This crate never
    /// reads the wall clock.
    pub timestamp: i64,
    /// Identity of the principal who delegated the action.
    pub delegator: String,
    /// The acting agent.
    pub agent: Agent,
    /// The capability scope in force, byte-identical to the value
    /// enforcement checked (specification Section 3.3).
    pub scope_granted: String,
    /// The action taken or attempted.
    pub action: Action,
    /// Hex SHA-256 of the result or outcome.
    pub result_hash: String,
    /// Effects of the action.
    pub effects: Effects,
    /// Hex hash of the previous receipt, or the genesis hash.
    pub prior_receipt_hash: String,
    /// Reason code. Required on DENIAL, forbidden elsewhere.
    pub reason_code: Option<DenialReason>,
    /// Policy verdict record for enforcement receipts, as a CBOR map.
    /// Kept as a value so layer namespaces (toolgate.*, institutio.*)
    /// travel without the core schema knowing their fields.
    pub verdict: Option<CborValue>,
}

impl Receipt {
    /// Validate the structural rules that do not depend on chain
    /// position: types, hash formats, and the DENIAL reason rule.
    /// A DENIAL without a valid reason code cannot pass this check,
    /// and the builder below refuses to construct one, so the
    /// non-conforming state is unrepresentable through the builder.
    pub fn validate_structure(&self) -> Result<()> {
        match (self.receipt_type, self.reason_code) {
            (ReceiptType::Denial, None) => {
                return Err(ActaError::DenialReasonMissing(format!(
                    "DENIAL receipt {} has no reason_code; a denial \
                     without a reason code is non-conforming",
                    self.receipt_id
                )));
            }
            (ReceiptType::Denial, Some(_)) => {}
            (_, Some(_)) => return Err(ActaError::ReasonCodeOnNonDenial),
            (_, None) => {}
        }
        for (label, value) in [
            ("action.arguments_hash", &self.action.arguments_hash),
            ("result_hash", &self.result_hash),
            ("prior_receipt_hash", &self.prior_receipt_hash),
        ] {
            if !is_hash_hex(value) {
                return Err(ActaError::InvalidReceipt(format!(
                    "{label} must be a 64 character lowercase hex hash"
                )));
            }
        }
        if self.agent.id.is_empty()
            || self.agent.model.is_empty()
            || self.agent.model_version.is_empty()
        {
            return Err(ActaError::InvalidReceipt(
                "agent must carry id, model and model_version".into(),
            ));
        }
        Ok(())
    }

    /// The receipt body as a deterministic-CBOR-ready value.
    pub fn to_cbor(&self) -> CborValue {
        let mut map = BTreeMap::new();
        let text = |s: &str| CborValue::Text(s.to_string());
        map.insert("receipt_version".into(), text(&self.receipt_version));
        map.insert("receipt_id".into(), text(&self.receipt_id));
        map.insert("receipt_type".into(), text(self.receipt_type.as_str()));
        map.insert("sequence".into(), CborValue::Int(self.sequence as i64));
        map.insert("timestamp".into(), CborValue::Int(self.timestamp));
        map.insert("delegator".into(), text(&self.delegator));
        let mut agent = BTreeMap::new();
        agent.insert("id".into(), text(&self.agent.id));
        agent.insert("model".into(), text(&self.agent.model));
        agent.insert("model_version".into(), text(&self.agent.model_version));
        map.insert("agent".into(), CborValue::Map(agent));
        map.insert("scope_granted".into(), text(&self.scope_granted));
        let mut action = BTreeMap::new();
        action.insert("name".into(), text(&self.action.name));
        action.insert("arguments_hash".into(), text(&self.action.arguments_hash));
        map.insert("action".into(), CborValue::Map(action));
        map.insert("result_hash".into(), text(&self.result_hash));
        let list = |items: &Vec<String>| {
            CborValue::Array(items.iter().map(|s| text(s)).collect())
        };
        let mut effects = BTreeMap::new();
        effects.insert("artifacts_changed".into(), list(&self.effects.artifacts_changed));
        effects.insert("external_calls".into(), list(&self.effects.external_calls));
        effects.insert("sub_delegations".into(), list(&self.effects.sub_delegations));
        map.insert("effects".into(), CborValue::Map(effects));
        map.insert("prior_receipt_hash".into(), text(&self.prior_receipt_hash));
        if let Some(reason) = self.reason_code {
            map.insert("reason_code".into(), text(reason.as_str()));
        }
        if let Some(verdict) = &self.verdict {
            map.insert("verdict".into(), verdict.clone());
        }
        CborValue::Map(map)
    }

    /// Parse a receipt body from a decoded CBOR value. Unknown fields
    /// reject: forward compatibility must reject, not ignore
    /// (blueprint rule D6 and fixture doctrine).
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(map) = value else {
            return Err(ActaError::InvalidReceipt("receipt body is not a map".into()));
        };
        const KNOWN: &[&str] = &[
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
            "reason_code",
            "verdict",
        ];
        for key in map.keys() {
            if !KNOWN.contains(&key.as_str()) {
                return Err(ActaError::InvalidReceipt(format!(
                    "unknown receipt field: {key}"
                )));
            }
        }
        let get_text = |key: &str| -> Result<String> {
            match map.get(key) {
                Some(CborValue::Text(t)) => Ok(t.clone()),
                _ => Err(ActaError::InvalidReceipt(format!(
                    "field {key} missing or not text"
                ))),
            }
        };
        let get_int = |key: &str| -> Result<i64> {
            match map.get(key) {
                Some(CborValue::Int(n)) => Ok(*n),
                _ => Err(ActaError::InvalidReceipt(format!(
                    "field {key} missing or not an integer"
                ))),
            }
        };
        let receipt_type = ReceiptType::from_wire(&get_text("receipt_type")?)?;
        let reason_code = match map.get("reason_code") {
            None => None,
            Some(CborValue::Text(t)) => Some(DenialReason::from_wire(t).ok_or_else(|| {
                ActaError::DenialReasonMissing(format!(
                    "DENIAL reason_code {t:?} is not in the v0.1 set"
                ))
            })?),
            Some(_) => {
                return Err(ActaError::InvalidReceipt(
                    "reason_code is not text".into(),
                ))
            }
        };
        let agent = match map.get("agent") {
            Some(CborValue::Map(a)) => Agent {
                id: text_field(a, "id")?,
                model: text_field(a, "model")?,
                model_version: text_field(a, "model_version")?,
            },
            _ => return Err(ActaError::InvalidReceipt("agent missing or not a map".into())),
        };
        let action = match map.get("action") {
            Some(CborValue::Map(a)) => Action {
                name: text_field(a, "name")?,
                arguments_hash: text_field(a, "arguments_hash")?,
            },
            _ => return Err(ActaError::InvalidReceipt("action missing or not a map".into())),
        };
        let effects = match map.get("effects") {
            Some(CborValue::Map(e)) => Effects {
                artifacts_changed: text_list(e, "artifacts_changed")?,
                external_calls: text_list(e, "external_calls")?,
                sub_delegations: text_list(e, "sub_delegations")?,
            },
            _ => return Err(ActaError::InvalidReceipt("effects missing or not a map".into())),
        };
        let sequence = get_int("sequence")?;
        if sequence < 0 {
            return Err(ActaError::InvalidReceipt("sequence is negative".into()));
        }
        let receipt = Receipt {
            receipt_version: get_text("receipt_version")?,
            receipt_id: get_text("receipt_id")?,
            receipt_type,
            sequence: sequence as u64,
            timestamp: get_int("timestamp")?,
            delegator: get_text("delegator")?,
            agent,
            scope_granted: get_text("scope_granted")?,
            action,
            result_hash: get_text("result_hash")?,
            effects,
            prior_receipt_hash: get_text("prior_receipt_hash")?,
            reason_code,
            verdict: map.get("verdict").cloned(),
        };
        receipt.validate_structure()?;
        Ok(receipt)
    }

    /// Canonical deterministic CBOR bytes of this body.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_cbor())
    }

    /// Native receipt hash: SHA-256 over the domain tag for the
    /// receipt type, the raw prior hash bytes, and the canonical CBOR
    /// body (blueprint rule D7, domain separation).
    pub fn compute_hash(&self) -> String {
        let prior_raw = crate::signing::hex_decode_32(&self.prior_receipt_hash)
            .unwrap_or([0u8; 32]);
        let mut input = Vec::new();
        input.extend_from_slice(self.receipt_type.domain_tag().as_bytes());
        input.push(0);
        input.extend_from_slice(&prior_raw);
        input.extend_from_slice(&self.canonical_bytes());
        hex_encode(&sha256(&input))
    }
}

fn text_field(map: &BTreeMap<String, CborValue>, key: &str) -> Result<String> {
    match map.get(key) {
        Some(CborValue::Text(t)) => Ok(t.clone()),
        _ => Err(ActaError::InvalidReceipt(format!(
            "field {key} missing or not text"
        ))),
    }
}

fn text_list(map: &BTreeMap<String, CborValue>, key: &str) -> Result<Vec<String>> {
    match map.get(key) {
        Some(CborValue::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    CborValue::Text(t) => out.push(t.clone()),
                    _ => {
                        return Err(ActaError::InvalidReceipt(format!(
                            "field {key} contains a non-text entry"
                        )))
                    }
                }
            }
            Ok(out)
        }
        _ => Err(ActaError::InvalidReceipt(format!(
            "field {key} missing or not an array"
        ))),
    }
}

/// One entry in a DSSE envelope's signature list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    /// Signer key identifier.
    pub key_id: String,
    /// Raw signature bytes over the PAE.
    pub signature: Vec<u8>,
    /// The signer's Ed25519 verifying key, carried so a stranger can
    /// verify offline with no key directory. Trust in the key itself
    /// comes from the charter that names it, not from this field.
    pub verifying_key: Vec<u8>,
}

/// A DSSE-style typed envelope: the exact payload bytes, their type,
/// and the signatures over their PAE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Payload type, versioned and specific, never generic.
    pub payload_type: String,
    /// The exact payload bytes as transmitted. Verification checks
    /// these bytes; it never re-derives them from a parsed form for
    /// the signature check.
    pub payload: Vec<u8>,
    /// One or more signatures over the PAE of the payload.
    pub signatures: Vec<SignatureEntry>,
}

/// A receipt body plus its chain hash and envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    /// The receipt body.
    pub body: Receipt,
    /// Hex native receipt hash (see [`Receipt::compute_hash`]).
    pub receipt_hash: String,
    /// The DSSE envelope over the body's canonical CBOR bytes.
    pub envelope: Envelope,
}

/// Inputs for building one receipt. Mirrors the Python prototype's
/// `build_receipt` arguments.
#[derive(Debug, Clone)]
pub struct ReceiptDraft {
    /// Unique identifier for this receipt.
    pub receipt_id: String,
    /// GRANT, ACTION, or DENIAL.
    pub receipt_type: ReceiptType,
    /// Position in the chain.
    pub sequence: u64,
    /// Integer seconds, caller supplied.
    pub timestamp: i64,
    /// Delegating principal identity.
    pub delegator: String,
    /// Acting agent.
    pub agent: Agent,
    /// Scope in force.
    pub scope_granted: String,
    /// Action name.
    pub action_name: String,
    /// Hex arguments hash.
    pub arguments_hash: String,
    /// Hex result hash.
    pub result_hash: String,
    /// Hex hash of the previous receipt, or the genesis hash.
    pub prior_receipt_hash: String,
    /// Effects; defaults to empty lists.
    pub effects: Effects,
    /// Reason code; required for DENIAL.
    pub reason_code: Option<DenialReason>,
    /// Optional verdict value.
    pub verdict: Option<CborValue>,
}

/// Build and sign one receipt. Raises a typed error on bad input; a
/// DENIAL without a valid reason code cannot be built.
pub fn build_receipt(
    signer: &dyn Signer,
    verifying_key: Vec<u8>,
    draft: ReceiptDraft,
) -> Result<SignedReceipt> {
    let mut body = Receipt {
        receipt_version: RECEIPT_VERSION.to_string(),
        receipt_id: draft.receipt_id,
        receipt_type: draft.receipt_type,
        sequence: draft.sequence,
        timestamp: draft.timestamp,
        delegator: draft.delegator,
        agent: draft.agent,
        scope_granted: draft.scope_granted,
        action: Action {
            name: draft.action_name,
            arguments_hash: draft.arguments_hash,
        },
        result_hash: draft.result_hash,
        effects: draft.effects,
        prior_receipt_hash: draft.prior_receipt_hash,
        reason_code: draft.reason_code,
        verdict: draft.verdict,
    };
    if body.receipt_type == ReceiptType::Denial && body.verdict.is_none() {
        let reason = body
            .reason_code
            .map(|r| r.as_str().to_string())
            .unwrap_or_default();
        let mut verdict = BTreeMap::new();
        verdict.insert("decision".into(), CborValue::Text("deny".into()));
        verdict.insert("reason_code".into(), CborValue::Text(reason));
        body.verdict = Some(CborValue::Map(verdict));
    }
    body.validate_structure()?;
    let receipt_hash = body.compute_hash();
    let payload = body.canonical_bytes();
    let signature = signer.sign_pae(PAYLOAD_TYPE, &payload);
    Ok(SignedReceipt {
        body,
        receipt_hash,
        envelope: Envelope {
            payload_type: PAYLOAD_TYPE.to_string(),
            payload,
            signatures: vec![SignatureEntry {
                key_id: signer.key_id().to_string(),
                signature,
                verifying_key,
            }],
        },
    })
}
