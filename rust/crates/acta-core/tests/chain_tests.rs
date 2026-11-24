//! Unit and integration tests for the native receipt chain.
//!
//! Author: Gavin Blacklock

use acta_core::receipt::{Action, Agent, Effects};
use acta_core::{
    build_receipt, verify_chain, ActaError, DenialReason, Ed25519Signer, ReceiptDraft,
    ReceiptType, Signer, TrustSet, GENESIS_HASH,
};

fn trust() -> TrustSet {
    TrustSet::from_signer(&signer())
}

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("acta-test-key-1", &[3u8; 32])
}

fn draft(sequence: u64, prior: &str, receipt_type: ReceiptType) -> ReceiptDraft {
    ReceiptDraft {
        receipt_id: format!("r-{sequence:04}"),
        receipt_type,
        sequence,
        timestamp: 1_763_900_000 + sequence as i64,
        delegator: "seat-founder".into(),
        agent: Agent {
            id: "agent-operator-1".into(),
            model: "model-x".into(),
            model_version: "1.0".into(),
        },
        scope_granted: "tools=[read,write];resources=[repo];ops=[call]".into(),
        action_name: "repo.write_file".into(),
        arguments_hash: "a".repeat(64),
        result_hash: "b".repeat(64),
        prior_receipt_hash: prior.to_string(),
        effects: Effects {
            artifacts_changed: vec!["repo/file.txt".into()],
            external_calls: vec![],
            sub_delegations: vec![],
        },
        reason_code: if receipt_type == ReceiptType::Denial {
            Some(DenialReason::Revoked)
        } else {
            None
        },
        verdict: None,
    }
}

fn build_chain(length: u64) -> Vec<acta_core::SignedReceipt> {
    let signer = signer();
    let key = signer.verifying_key_bytes().to_vec();
    let mut prior = GENESIS_HASH.to_string();
    let mut chain = Vec::new();
    for sequence in 0..length {
        let receipt = build_receipt(&signer, key.clone(), draft(sequence, &prior, ReceiptType::Action))
            .unwrap();
        prior = receipt.receipt_hash.clone();
        chain.push(receipt);
    }
    chain
}

#[test]
fn valid_chain_verifies() {
    let chain = build_chain(4);
    let verdict = verify_chain(&chain, &trust(), None, None).unwrap();
    assert_eq!(verdict.length, 4);
    assert_eq!(verdict.head, chain[3].receipt_hash);
}

#[test]
fn denial_without_reason_code_cannot_be_built() {
    let signer = signer();
    let mut d = draft(0, GENESIS_HASH, ReceiptType::Denial);
    d.reason_code = None;
    let err = build_receipt(&signer, signer.verifying_key_bytes().to_vec(), d).unwrap_err();
    assert_eq!(err.code(), "DENIAL_REASON_MISSING");
    assert!(matches!(err, ActaError::DenialReasonMissing(_)));
}

#[test]
fn every_reason_code_builds() {
    let signer = signer();
    for reason in [
        DenialReason::Revoked,
        DenialReason::Scope,
        DenialReason::ManifestMismatch,
        DenialReason::Budget,
        DenialReason::StandingCeiling,
    ] {
        let mut d = draft(0, GENESIS_HASH, ReceiptType::Denial);
        d.reason_code = Some(reason);
        assert!(build_receipt(&signer, signer.verifying_key_bytes().to_vec(), d).is_ok());
    }
}

#[test]
fn reason_code_on_action_is_rejected() {
    let signer = signer();
    let mut d = draft(0, GENESIS_HASH, ReceiptType::Action);
    d.reason_code = Some(DenialReason::Scope);
    assert!(build_receipt(&signer, signer.verifying_key_bytes().to_vec(), d).is_err());
}

#[test]
fn tampered_body_is_detected() {
    let mut chain = build_chain(3);
    chain[1].body.action = Action {
        name: "repo.delete_file".into(),
        arguments_hash: "a".repeat(64),
    };
    let err = verify_chain(&chain, &trust(), None, None).unwrap_err();
    assert_eq!(err.code(), "TAMPERED");
}

#[test]
fn wrong_key_is_detected() {
    // The trust set pins a different key under a different id: the
    // chain's signatures come from no pinned key (audit finding C1).
    let chain = build_chain(2);
    let other = Ed25519Signer::from_seed("some-other-key", &[4u8; 32]);
    let err = verify_chain(&chain, &TrustSet::from_signer(&other), None, None)
        .unwrap_err();
    assert_eq!(err.code(), "UNTRUSTED_KEY");
}

#[test]
fn truncation_is_detected_against_head() {
    let chain = build_chain(3);
    let head = chain[2].receipt_hash.clone();
    let err = verify_chain(&chain[..2], &trust(), Some(&head), None).unwrap_err();
    assert_eq!(err.code(), "TRUNCATED");
}

#[test]
fn bundle_transport_round_trip() {
    let chain = build_chain(3);
    let json = acta_core::bundle::bundle_to_json(&chain);
    let parsed = acta_core::bundle::bundle_from_json(&json).unwrap();
    assert_eq!(parsed, chain);
    assert!(verify_chain(&parsed, &trust(), None, None).is_ok());
}

#[test]
fn signer_trait_is_scheme_agnostic() {
    // The Signer trait is the seam the prototype's design promised:
    // callers sign and verify PAE bytes without naming a scheme.
    let signer = signer();
    let sig = signer.sign_pae("t", b"bytes");
    assert!(signer.verify_pae("t", b"bytes", &sig));
}
