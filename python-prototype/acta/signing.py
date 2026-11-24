"""DSSE-style typed-envelope signing for Acta.

Author: Gavin Blacklock

The signature is computed over a Pre-Auth-Encoding (PAE) of the payload
type and the exact payload bytes, following the DSSE protocol. Verifiers
check the bytes as received; they never re-serialise a payload and sign
the re-serialisation.

PLACEHOLDER SIGNATURE SCHEME: v0.1 foundation code uses HMAC-SHA256
behind the Signer interface because the Python standard library ships
no asymmetric signature algorithm. Real asymmetric signing (Ed25519,
per the specification key identity model) is a later swap behind this
same interface: callers depend on Signer, never on HMAC directly.

Ed25519 is now also present, as Ed25519Signer below: a pure-Python
RFC 8032 implementation built on hashlib, standard library only. It
exists so a countersignature produced by this prototype verifies in
the Rust implementation and vice versa (second re-audit finding S1):
the two trees sign the same descriptor bytes with the same scheme,
not merely with schemes of the same name. It is not constant-time
and is not the production key path; custody and speed belong to the
Rust core. Its correctness is pinned by the RFC 8032 test vector in
the test suite.
"""

import base64
import hashlib
import hmac


def pae(payload_type, payload):
    """Build the DSSE Pre-Auth-Encoding for a payload type and bytes."""
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def b64encode(data):
    return base64.b64encode(data).decode("ascii")


def b64decode(text):
    return base64.b64decode(text.encode("ascii"))


class Signer:
    """Signature interface. Implementations sign and verify PAE bytes."""

    key_id = None

    def sign(self, payload_type, payload):
        raise NotImplementedError

    def verify(self, payload_type, payload, signature_b64):
        raise NotImplementedError


# --- Ed25519 (RFC 8032), pure Python over hashlib. ---

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_BY = (4 * pow(5, -1, _Q)) % _Q
_BX = pow((_BY * _BY - 1) * pow(_D * _BY * _BY + 1, -1, _Q) % _Q,
          (_Q + 3) // 8, _Q)
if (_BX * _BX - (_BY * _BY - 1) * pow(_D * _BY * _BY + 1, -1, _Q)) % _Q != 0:
    _BX = (_BX * _I) % _Q
if _BX & 1:
    # The base point's x coordinate is the even root (its encoding
    # is 0x586666...66, sign bit clear).
    _BX = _Q - _BX
_B = (_BX % _Q, _BY)


def _ed_add(point1, point2):
    x1, y1 = point1
    x2, y2 = point2
    common = _D * x1 * x2 * y1 * y2 % _Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + common, -1, _Q) % _Q,
        (y1 * y2 + x1 * x2) * pow(1 - common, -1, _Q) % _Q,
    )


def _ed_mul(point, scalar):
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_encode(point):
    x, y = point
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _ed_decode(data):
    if len(data) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = sum(b << (8 * i) for i, b in enumerate(data)) & ((1 << 255) - 1)
    sign = (data[31] >> 7) & 1
    x = pow((y * y - 1) * pow(_D * y * y + 1, -1, _Q) % _Q,
            (_Q + 3) // 8, _Q)
    if (x * x - (y * y - 1) * pow(_D * y * y + 1, -1, _Q)) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1 != sign:
        x = _Q - x
    return (x, y)


def _ed_clamp(digest32):
    scalar = int.from_bytes(digest32, "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


def ed25519_public_key(seed):
    """The 32-byte verifying key for a 32-byte seed."""
    digest = hashlib.sha512(seed).digest()
    return _ed_encode(_ed_mul(_B, _ed_clamp(digest[:32])))


def ed25519_sign(seed, message):
    """The 64-byte RFC 8032 signature of message under seed."""
    digest = hashlib.sha512(seed).digest()
    scalar = _ed_clamp(digest[:32])
    public = _ed_encode(_ed_mul(_B, scalar))
    nonce = int.from_bytes(
        hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    encoded_r = _ed_encode(_ed_mul(_B, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + message).digest(),
        "little") % _L
    s_value = (nonce + challenge * scalar) % _L
    return encoded_r + s_value.to_bytes(32, "little")


def ed25519_verify(public, message, signature):
    """True when signature is a valid RFC 8032 signature."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        point_a = _ed_decode(public)
        point_r = _ed_decode(signature[:32])
    except Exception:
        return False
    s_value = int.from_bytes(signature[32:], "little")
    if s_value >= _L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(),
        "little") % _L
    return _ed_mul(_B, s_value) == _ed_add(
        point_r, _ed_mul(point_a, challenge))


class Ed25519Signer(Signer):
    """Ed25519 signer and verifier behind the Signer interface.

    sign and verify operate over the DSSE PAE of the payload, as
    with HmacSigner, so signatures are interchangeable with the
    Rust implementation's Ed25519 signatures over the same PAE
    (finding S1). A verify-only instance is built with seed=None
    and a verifying key.
    """

    def __init__(self, seed=None, key_id=None, verifying_key=None):
        if seed is not None:
            if len(seed) != 32:
                raise ValueError("Ed25519 seed must be 32 bytes")
            self._seed = bytes(seed)
            self._public = ed25519_public_key(self._seed)
        elif verifying_key is not None:
            self._seed = None
            self._public = bytes(verifying_key)
        else:
            raise ValueError("Ed25519Signer needs a seed or a verifying key")
        self.key_id = key_id

    def verifying_key_bytes(self):
        return self._public

    def sign(self, payload_type, payload):
        if self._seed is None:
            raise ValueError("this Ed25519Signer is verify-only")
        return b64encode(ed25519_sign(self._seed, pae(payload_type, payload)))

    def verify(self, payload_type, payload, signature_b64):
        try:
            signature = b64decode(signature_b64)
        except Exception:
            return False
        return ed25519_verify(self._public, pae(payload_type, payload),
                              signature)


class HmacSigner(Signer):
    """HMAC-SHA256 placeholder signer. See module docstring."""

    def __init__(self, secret, key_id):
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not secret:
            raise ValueError("secret must not be empty")
        self._secret = secret
        self.key_id = key_id

    def sign(self, payload_type, payload):
        mac = hmac.new(self._secret, pae(payload_type, payload), hashlib.sha256)
        return b64encode(mac.digest())

    def verify(self, payload_type, payload, signature_b64):
        expected = self.sign(payload_type, payload)
        return hmac.compare_digest(expected, signature_b64)
