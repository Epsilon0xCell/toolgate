//! Regression tests for the 2026-11-23 independent audit repair round.
//!
//! Author: Gavin Blacklock
//!
//! Each test is named for the audit finding it closes and encodes
//! the audit's own attack: it fails on the pre-repair behaviour and
//! passes on the repaired behaviour.

use acta_core::receipt::{Agent, Effects};
use acta_core::{
    build_receipt, verify_chain, Ed25519Signer, ReceiptDraft, ReceiptType, SignedReceipt,
    TrustSet, GENESIS_HASH,
};

fn draft(sequence: u64, prior: &str) -> ReceiptDraft {
    ReceiptDraft {
        receipt_id: format!("r-{sequence:04}"),
        receipt_type: ReceiptType::Action,
        sequence,
        timestamp: 1_763_900_000 + sequence as i64,
        delegator: "seat-founder".into(),
        agent: Agent {
            id: "agent-operator-1".into(),
            model: "model-x".into(),
            model_version: "1.0".into(),
        },
        scope_granted: "tools=[read];resources=[repo];ops=[call]".into(),
        action_name: "repo.read_file".into(),
        arguments_hash: "a".repeat(64),
        result_hash: "b".repeat(64),
        prior_receipt_hash: prior.to_string(),
        effects: Effects::default(),
        reason_code: None,
        verdict: None,
    }
}

fn build_chain(signer: &Ed25519Signer, length: u64) -> Vec<SignedReceipt> {
    let key = signer.verifying_key_bytes().to_vec();
    let mut prior = GENESIS_HASH.to_string();
    let mut chain = Vec::new();
    for sequence in 0..length {
        let receipt = build_receipt(signer, key.clone(), draft(sequence, &prior)).unwrap();
        prior = receipt.receipt_hash.clone();
        chain.push(receipt);
    }
    chain
}

fn real_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed("acta-test-key-1", &[3u8; 32])
}

#[test]
fn test_c1_forged_key_rejected() {
    // The audit's attack, verbatim in structure: a complete chain
    // signed by an attacker's Ed25519 key whose key_id string copies
    // the expected value. Pre-repair, verify_chain and the shipped
    // CLI both accepted it, because the verifying key was taken
    // from the envelope itself.
    let attacker = Ed25519Signer::from_seed("acta-test-key-1", &[99u8; 32]);
    let forged = build_chain(&attacker, 3);
    let trust = TrustSet::from_signer(&real_signer());
    let err = verify_chain(&forged, &trust, None, None).unwrap_err();
    assert_eq!(err.code(), "UNTRUSTED_KEY");
}

#[test]
fn test_c1_chain_verifies_only_under_pinned_key() {
    let chain = build_chain(&real_signer(), 3);
    let trust = TrustSet::from_signer(&real_signer());
    let verdict = verify_chain(&chain, &trust, None, None).unwrap();
    assert_eq!(verdict.length, 3);
}

#[test]
fn test_c1_unpinned_key_id_rejected() {
    let stranger = Ed25519Signer::from_seed("some-other-key", &[5u8; 32]);
    let chain = build_chain(&stranger, 2);
    let trust = TrustSet::from_signer(&real_signer());
    let err = verify_chain(&chain, &trust, None, None).unwrap_err();
    assert_eq!(err.code(), "UNTRUSTED_KEY");
}

#[test]
fn test_c1_empty_trust_set_rejects_everything() {
    let chain = build_chain(&real_signer(), 1);
    let err = verify_chain(&chain, &TrustSet::new(), None, None).unwrap_err();
    assert_eq!(err.code(), "UNTRUSTED_KEY");
}

#[test]
fn test_t2_duplicate_receipt_id_rejected() {
    // Third re-audit finding T2 (repair round 4): two fully
    // signed, hash-linked receipts carrying the same receipt_id
    // ("dup-id", sequences 0 and 1) were accepted by verify_chain
    // pre-repair. Section 16.10 decision 19 makes receipt
    // identities unique, and the Python prototype rejects the
    // same chain as DUPLICATE_RECEIPT_ID.
    let signer = real_signer();
    let key = signer.verifying_key_bytes().to_vec();
    let mut first_draft = draft(0, GENESIS_HASH);
    first_draft.receipt_id = "dup-id".into();
    let first = build_receipt(&signer, key.clone(), first_draft).unwrap();
    let mut second_draft = draft(1, &first.receipt_hash);
    second_draft.receipt_id = "dup-id".into();
    let second = build_receipt(&signer, key, second_draft).unwrap();
    let trust = TrustSet::from_signer(&signer);
    let err = verify_chain(&[first, second], &trust, None, None).unwrap_err();
    assert_eq!(err.code(), "DUPLICATE_RECEIPT_ID");
}
