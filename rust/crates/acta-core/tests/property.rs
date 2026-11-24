//! Property-style tests over generated chains (proptest).
//!
//! Author: Gavin Blacklock
//!
//! Invariants under test:
//! 1. Every generated well-formed chain verifies.
//! 2. Any single-byte tamper with a signed payload is detected.
//! 3. Reordering a chain of length at least 2 is detected.
//!
//! Generation is deterministic under proptest's recorded seeds, and
//! failing cases shrink to a minimal chain before reporting.

use acta_core::{
    build_receipt, verify_chain, Agent, Ed25519Signer, Effects, ReceiptDraft, ReceiptType,
    SignedReceipt, TrustSet, GENESIS_HASH,
};

fn trust_for(salt: u8) -> TrustSet {
    TrustSet::from_signer(&Ed25519Signer::from_seed("acta-test-key-1", &[salt; 32]))
}
use proptest::prelude::*;

fn build_chain(length: usize, salt: u8) -> Vec<SignedReceipt> {
    let signer = Ed25519Signer::from_seed("acta-test-key-1", &[salt; 32]);
    let key = signer.verifying_key_bytes().to_vec();
    let mut prior = GENESIS_HASH.to_string();
    let mut chain = Vec::with_capacity(length);
    for sequence in 0..length {
        let draft = ReceiptDraft {
            receipt_id: format!("r-{sequence:04}"),
            receipt_type: ReceiptType::Action,
            sequence: sequence as u64,
            timestamp: 1_763_900_000 + sequence as i64,
            delegator: "seat-founder".into(),
            agent: Agent {
                id: "agent-operator-1".into(),
                model: "model-x".into(),
                model_version: "1.0".into(),
            },
            scope_granted: "tools=[read];resources=[repo];ops=[call]".into(),
            action_name: format!("tool.call_{sequence}"),
            arguments_hash: format!("{:064x}", sequence + 1),
            result_hash: format!("{:064x}", sequence + 101),
            prior_receipt_hash: prior.clone(),
            effects: Effects::default(),
            reason_code: None,
            verdict: None,
        };
        let receipt = build_receipt(&signer, key.clone(), draft).unwrap();
        prior = receipt.receipt_hash.clone();
        chain.push(receipt);
    }
    chain
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn generated_chains_verify(len in 0usize..10, salt in 1u8..8) {
        let chain = build_chain(len, salt);
        if len == 0 {
            // Re-audit minor r5: an empty chain verifies nothing
            // and is rejected, not passed.
            let error = verify_chain(&chain, &trust_for(salt), None, None).unwrap_err();
            prop_assert!(error.to_string().contains("empty chain"), "{error}");
            return Ok(());
        }
        let verdict = verify_chain(&chain, &trust_for(salt), None, None).unwrap();
        prop_assert_eq!(verdict.length, len);
    }

    #[test]
    fn single_byte_payload_tamper_is_detected(
        len in 1usize..8,
        salt in 1u8..8,
        index_seed in 0usize..64,
        byte_seed in 0usize..512,
    ) {
        let mut chain = build_chain(len, salt);
        let index = index_seed % len;
        let payload_len = chain[index].envelope.payload.len();
        let byte_index = byte_seed % payload_len;
        chain[index].envelope.payload[byte_index] ^= 0x01;
        // The body no longer matches the envelope bytes, or the
        // signature no longer verifies: either way, detection.
        prop_assert!(verify_chain(&chain, &trust_for(salt), None, None).is_err());
    }

    #[test]
    fn reordering_is_detected(len in 2usize..10, salt in 1u8..8) {
        let mut chain = build_chain(len, salt);
        chain.swap(0, 1);
        prop_assert!(verify_chain(&chain, &trust_for(salt), None, None).is_err());
    }

    #[test]
    fn single_byte_signature_tamper_is_detected(
        len in 1usize..8,
        salt in 1u8..8,
        index_seed in 0usize..64,
    ) {
        let mut chain = build_chain(len, salt);
        let index = index_seed % len;
        chain[index].envelope.signatures[0].signature[0] ^= 0x01;
        let result = verify_chain(&chain, &trust_for(salt), None, None);
        prop_assert!(result.is_err());
        prop_assert_eq!(result.unwrap_err().code(), "SIGNATURE_INVALID");
    }
}
