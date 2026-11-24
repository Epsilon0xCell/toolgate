"""Deterministic encoding and hashing helpers for Acta.

Author: Gavin Blacklock
"""

import hashlib
import json


def canonical_bytes(obj):
    """Encode a JSON value deterministically.

    Sorted keys, no insignificant whitespace, UTF-8 output. Verification
    never depends on wall-clock time or dict insertion order.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data):
    """Return the SHA-256 hex digest of bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def is_hash_hex(value):
    """True if value is a 64 character lowercase hex string."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()
