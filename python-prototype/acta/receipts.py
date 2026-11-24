"""Acta receipt core: receipt construction, hash chaining, verification.

Author: Gavin Blacklock

Implements the v0.1 receipt fields of the combined specification
(Section 3.1): delegator identity, agent and model and version,
capability and policy scope granted, tool or action and arguments hash,
result hash, artifacts changed and sub-delegations, timestamps, and the
prior-receipt hash that forms the append-only chain.

Receipt types in v0.1 foundation code: GRANT, ACTION, DENIAL, plus
the Standing derived types of specification Section 16.3 (BURN,
PROMOTION, DEMOTION, KILL-BURN) and REVOCATION, the receipt form of
the revocation act of specification Section 7.3 ticket T1 (a signed
event naming the revoked delegation-manifest id, effective at its
sequence number). Derived receipts record the output of a computation
or an act; they confer nothing by themselves.
A DENIAL receipt must carry a reason code from DENIAL_REASON_CODES; a
DENIAL without a valid reason code fails validation, on construction
and on verification.
"""

import copy

from .canonical import canonical_bytes, is_hash_hex, sha256_hex
from .signing import b64decode, b64encode

RECEIPT_VERSION = "0.1"
PAYLOAD_TYPE = "application/vnd.acta.receipt.v0.1+json"
GENESIS_HASH = "0" * 64

RECEIPT_TYPES = (
    "GRANT",
    "ACTION",
    "DENIAL",
    "BURN",
    "PROMOTION",
    "DEMOTION",
    "REVOCATION",
    "KILL-BURN",
)

# Derived receipt types of specification Section 16.3 and 16.6. They
# record a recomputation or a kill event; they mint and burn nothing
# by themselves (the DENIAL they derive from does the burning).
DERIVED_RECEIPT_TYPES = ("BURN", "PROMOTION", "DEMOTION", "KILL-BURN")

# The v0.1 reason code set of specification Section 3.5. The first four
# are the Provable Kill set of ticket T2; standing-ceiling is the
# Standing ground added by specification Section 16.
DENIAL_REASON_CODES = (
    "revoked",
    "scope",
    "manifest-mismatch",
    "budget",
    "standing-ceiling",
)

_REQUIRED_FIELDS = (
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
)


class VerificationResult:
    """Outcome of a chain verification."""

    def __init__(self, ok, failure_index=None, failure_code=None, message=""):
        self.ok = ok
        self.failure_index = failure_index
        self.failure_code = failure_code
        self.message = message

    def __repr__(self):
        if self.ok:
            return "VerificationResult(ok=True)"
        return (
            "VerificationResult(ok=False, failure_index=%r, "
            "failure_code=%r, message=%r)"
            % (self.failure_index, self.failure_code, self.message)
        )


def payload_dict(receipt):
    """The signed payload view of a receipt dict.

    Excludes the receipt hash and the envelope itself. Everything else
    is signed, so altering any signed field after signing is detected.
    """
    return {
        key: value
        for key, value in receipt.items()
        if key not in ("receipt_hash", "envelope")
    }


def compute_receipt_hash(receipt):
    return sha256_hex(canonical_bytes(payload_dict(receipt)))


def assemble_receipt(payload, signer):
    """Assemble a full receipt (hash plus envelope) from a payload dict.

    Low-level helper. build_receipt validates before calling this; the
    fixture generator also calls this directly to craft deliberately
    non-conforming receipts for negative tests.
    """
    receipt = copy.deepcopy(payload)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    payload_bytes = canonical_bytes(payload_dict(receipt))
    signature = signer.sign(PAYLOAD_TYPE, payload_bytes)
    receipt["envelope"] = {
        "payload_type": PAYLOAD_TYPE,
        "payload": b64encode(payload_bytes),
        "signatures": [{"key_id": signer.key_id, "signature": signature}],
    }
    return receipt


def build_receipt(
    signer,
    receipt_id,
    receipt_type,
    sequence,
    timestamp,
    delegator,
    agent,
    scope_granted,
    action_name,
    arguments_hash,
    result_hash,
    prior_receipt_hash,
    effects=None,
    reason_code=None,
    verdict=None,
    sub_delegations=None,
    action_extra=None,
    receipt_extra=None,
):
    """Build and sign one receipt. Raises ValueError on bad input.

    agent: dict with keys id, model, model_version.
    timestamp: integer seconds, supplied by the caller. This module
    never reads the wall clock.
    """
    if receipt_type not in RECEIPT_TYPES:
        raise ValueError("unknown receipt_type: %r" % (receipt_type,))
    if receipt_type == "DENIAL":
        if reason_code not in DENIAL_REASON_CODES:
            raise ValueError(
                "DENIAL receipt requires a reason_code in %s, got %r"
                % (list(DENIAL_REASON_CODES), reason_code)
            )
    elif reason_code is not None:
        raise ValueError("reason_code is only valid on DENIAL receipts")
    if not isinstance(sequence, int) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if not isinstance(timestamp, int):
        raise ValueError("timestamp must be integer seconds")
    for label, value in (
        ("arguments_hash", arguments_hash),
        ("result_hash", result_hash),
        ("prior_receipt_hash", prior_receipt_hash),
    ):
        if not is_hash_hex(value):
            raise ValueError("%s must be a 64 character hex hash" % label)
    if not isinstance(agent, dict) or not all(
        key in agent for key in ("id", "model", "model_version")
    ):
        raise ValueError("agent must carry id, model and model_version")

    effects = copy.deepcopy(effects) if effects else {}
    effects.setdefault("artifacts_changed", [])
    effects.setdefault("external_calls", [])
    effects.setdefault(
        "sub_delegations", list(sub_delegations) if sub_delegations else []
    )

    action = {"name": action_name, "arguments_hash": arguments_hash}
    if action_extra:
        for key, value in action_extra.items():
            if key in action:
                raise ValueError("action_extra may not overwrite %r" % key)
            action[key] = copy.deepcopy(value)
    payload = {
        "receipt_version": RECEIPT_VERSION,
        "receipt_id": receipt_id,
        "receipt_type": receipt_type,
        "sequence": sequence,
        "timestamp": timestamp,
        "delegator": delegator,
        "agent": copy.deepcopy(agent),
        "scope_granted": scope_granted,
        "action": action,
        "result_hash": result_hash,
        "effects": effects,
        "prior_receipt_hash": prior_receipt_hash,
    }
    if receipt_extra:
        for key, value in receipt_extra.items():
            if key in payload:
                raise ValueError("receipt_extra may not overwrite %r" % key)
            payload[key] = copy.deepcopy(value)
    if reason_code is not None:
        payload["reason_code"] = reason_code
    if verdict is not None:
        payload["verdict"] = copy.deepcopy(verdict)
    if receipt_type == "DENIAL" and verdict is None:
        payload["verdict"] = {"decision": "deny", "reason_code": reason_code}
    return assemble_receipt(payload, signer)


def validate_receipt_structure(receipt):
    """Return a list of (code, message) structural problems, or []."""
    problems = []
    if not isinstance(receipt, dict):
        return [("INVALID_RECEIPT", "receipt is not a JSON object")]
    for field in _REQUIRED_FIELDS:
        if field not in receipt:
            problems.append(
                ("INVALID_RECEIPT", "missing required field: %s" % field)
            )
    if problems:
        return problems
    if receipt["receipt_type"] not in RECEIPT_TYPES:
        problems.append(
            ("INVALID_RECEIPT", "unknown receipt_type: %r" % receipt["receipt_type"])
        )
    agent = receipt["agent"]
    if not isinstance(agent, dict) or not all(
        key in agent for key in ("id", "model", "model_version")
    ):
        problems.append(
            ("INVALID_RECEIPT", "agent must carry id, model and model_version")
        )
    action = receipt["action"]
    if not isinstance(action, dict) or "name" not in action:
        problems.append(("INVALID_RECEIPT", "action must carry a name"))
    elif not is_hash_hex(action.get("arguments_hash", "")):
        problems.append(
            ("INVALID_RECEIPT", "action.arguments_hash must be a hex hash")
        )
    if not is_hash_hex(receipt["result_hash"]):
        problems.append(("INVALID_RECEIPT", "result_hash must be a hex hash"))
    if not is_hash_hex(receipt["prior_receipt_hash"]):
        problems.append(
            ("INVALID_RECEIPT", "prior_receipt_hash must be a hex hash")
        )
    if receipt["receipt_type"] == "DENIAL":
        if receipt.get("reason_code") not in DENIAL_REASON_CODES:
            problems.append(
                (
                    "DENIAL_REASON_MISSING",
                    "DENIAL receipt has no valid reason_code (got %r); "
                    "a denial without a reason code is non-conforming"
                    % (receipt.get("reason_code"),),
                )
            )
    return problems


def verify_chain(receipts, verifier=None, expected_key_id=None,
                 expected_head=None, expected_length=None):
    """Verify a receipt chain. Returns a VerificationResult.

    Detects tampering (hash, payload or signature mismatch), reordering
    (sequence and prior-hash linkage), invalid DENIAL receipts, and,
    when expected_head or expected_length are supplied, truncation.
    Truncation of a chain is only detectable against an expected head
    or length from outside the chain, for example an anchored ledger
    head; that is why those parameters exist.
    """
    if not isinstance(receipts, list):
        return VerificationResult(False, None, "INVALID_BUNDLE",
                                  "receipts must be a list")
    if verifier is None:
        # Audit finding M1: verification that silently skips
        # signatures is not verification. Fail closed: a caller who
        # wants a verdict must supply the verifier for the key set it
        # trusts. There is no unverified mode.
        return VerificationResult(
            False, None, "VERIFIER_REQUIRED",
            "verify_chain requires a verifier object; without one, "
            "envelope signatures cannot be checked and no verdict is "
            "issued",
        )
    if len(receipts) == 0:
        # Re-audit minor r5: an empty bundle is not a verified
        # chain. It must not print the same PASS as a bundle that
        # verified; emptiness is detectable without any external
        # expectation, so it is rejected outright.
        return VerificationResult(
            False, None, "EMPTY_CHAIN",
            "the bundle carries no receipts; an empty chain "
            "verifies nothing",
        )
    if expected_key_id is None:
        # Re-audit minor r4: a supplied verifier is bound to the
        # key id it carries. Without this, an envelope could claim
        # any key id at all while its signature happens to match
        # the verifier's secret: key labelling, tightened here to
        # an actual binding.
        expected_key_id = getattr(verifier, "key_id", None)
    previous_hash = GENESIS_HASH
    seen_receipt_ids = set()
    for index, receipt in enumerate(receipts):
        # Receipt identity is unique (second re-audit minor s6):
        # the countersigned outcome descriptor binds receipt_id,
        # so two receipts sharing an id would let one
        # countersignature mint twice on the same descriptor
        # identity. A chain carrying a duplicate id is invalid.
        receipt_id = receipt.get("receipt_id") if isinstance(receipt, dict) else None
        if receipt_id is not None:
            if receipt_id in seen_receipt_ids:
                return VerificationResult(
                    False, index, "DUPLICATE_RECEIPT_ID",
                    "receipt %d (%s): receipt_id duplicates an "
                    "earlier receipt in this chain; receipt "
                    "identities are unique" % (index, receipt_id),
                )
            seen_receipt_ids.add(receipt_id)
        problems = validate_receipt_structure(receipt)
        if problems:
            code, message = problems[0]
            return VerificationResult(
                False, index, code,
                "receipt %d (%s): %s"
                % (index, receipt.get("receipt_id", "?"), message),
            )
        if receipt["sequence"] != index:
            return VerificationResult(
                False, index, "REORDERED",
                "receipt %d (%s): sequence is %r, expected %d; "
                "the chain is reordered or has a gap"
                % (index, receipt["receipt_id"], receipt["sequence"], index),
            )
        if receipt["prior_receipt_hash"] != previous_hash:
            return VerificationResult(
                False, index, "CHAIN_BREAK",
                "receipt %d (%s): prior_receipt_hash does not match the "
                "hash of the previous receipt" % (index, receipt["receipt_id"]),
            )
        if compute_receipt_hash(receipt) != receipt.get("receipt_hash"):
            return VerificationResult(
                False, index, "TAMPERED",
                "receipt %d (%s): recomputed hash does not match the "
                "recorded receipt_hash; a signed field was altered"
                % (index, receipt["receipt_id"]),
            )
        envelope = receipt.get("envelope")
        if not isinstance(envelope, dict) or envelope.get("payload_type") != PAYLOAD_TYPE:
            return VerificationResult(
                False, index, "INVALID_ENVELOPE",
                "receipt %d (%s): missing or mistyped DSSE envelope"
                % (index, receipt["receipt_id"]),
            )
        try:
            envelope_payload = b64decode(envelope["payload"])
        except Exception:
            return VerificationResult(
                False, index, "INVALID_ENVELOPE",
                "receipt %d (%s): envelope payload is not valid base64"
                % (index, receipt["receipt_id"]),
            )
        if envelope_payload != canonical_bytes(payload_dict(receipt)):
            return VerificationResult(
                False, index, "TAMPERED",
                "receipt %d (%s): envelope payload bytes do not match "
                "the receipt fields" % (index, receipt["receipt_id"]),
            )
        signatures = envelope.get("signatures") or []
        if not signatures:
            return VerificationResult(
                False, index, "UNSIGNED",
                "receipt %d (%s): envelope carries no signatures"
                % (index, receipt["receipt_id"]),
            )
        if expected_key_id is not None and not any(
            sig.get("key_id") == expected_key_id for sig in signatures
        ):
            return VerificationResult(
                False, index, "KEY_ID_MISMATCH",
                "receipt %d (%s): no signature from expected key id %r"
                % (index, receipt["receipt_id"], expected_key_id),
            )
        if verifier is not None:
            matched = [
                sig for sig in signatures
                if expected_key_id is None or sig.get("key_id") == expected_key_id
            ]
            if not any(
                verifier.verify(PAYLOAD_TYPE, envelope_payload, sig["signature"])
                for sig in matched
            ):
                return VerificationResult(
                    False, index, "SIGNATURE_INVALID",
                    "receipt %d (%s): envelope signature does not verify"
                    % (index, receipt["receipt_id"]),
                )
        previous_hash = receipt["receipt_hash"]
    if expected_length is not None and len(receipts) != expected_length:
        code = "TRUNCATED" if len(receipts) < expected_length else "LENGTH_MISMATCH"
        return VerificationResult(
            False, len(receipts), code,
            "chain has %d receipts, expected %d" % (len(receipts), expected_length),
        )
    if expected_head is not None and previous_hash != expected_head:
        return VerificationResult(
            False, len(receipts), "TRUNCATED",
            "chain head %s does not match the expected head %s; "
            "the chain is truncated or substituted" % (previous_hash, expected_head),
        )
    return VerificationResult(True, message="chain verified: %d receipts" % len(receipts))


def chain_head(receipts):
    """Hash of the last receipt, or the genesis hash for an empty chain."""
    if not receipts:
        return GENESIS_HASH
    return receipts[-1]["receipt_hash"]


def bundle_dict(receipts):
    return {"bundle_version": RECEIPT_VERSION, "receipts": receipts}
