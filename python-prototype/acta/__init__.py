"""Acta: signed, hash-chained, replayable receipts for agent actions.

Author: Gavin Blacklock
No receipt, no trust.
"""

from .canonical import canonical_bytes, is_hash_hex, sha256_hex
from .receipts import (
    DENIAL_REASON_CODES,
    DERIVED_RECEIPT_TYPES,
    GENESIS_HASH,
    PAYLOAD_TYPE,
    RECEIPT_TYPES,
    RECEIPT_VERSION,
    VerificationResult,
    assemble_receipt,
    build_receipt,
    bundle_dict,
    chain_head,
    compute_receipt_hash,
    validate_receipt_structure,
    verify_chain,
)
from .signing import Ed25519Signer, HmacSigner, Signer, pae

__all__ = [
    "DENIAL_REASON_CODES",
    "DERIVED_RECEIPT_TYPES",
    "GENESIS_HASH",
    "PAYLOAD_TYPE",
    "RECEIPT_TYPES",
    "RECEIPT_VERSION",
    "Ed25519Signer",
    "HmacSigner",
    "Signer",
    "VerificationResult",
    "assemble_receipt",
    "build_receipt",
    "bundle_dict",
    "canonical_bytes",
    "chain_head",
    "compute_receipt_hash",
    "is_hash_hex",
    "pae",
    "sha256_hex",
    "validate_receipt_structure",
    "verify_chain",
]
