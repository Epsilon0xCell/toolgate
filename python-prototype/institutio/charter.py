"""Institutio charter loading, validation, and the charter hash chain.

Author: Gavin Blacklock

Implements the v0.1 charter schema of the combined specification
(Section 6.3): seats and roles, delegated-authority manifests that can
only attenuate, budgets, amendment and succession rules, and the kill
switch. A charter history is a hash chain of charters: every amendment
names the hash of the charter it supersedes (Section 6.5).

Scope representation in v0.1 foundation code: a scope is a JSON object
with three set dimensions (tools, resources, operations), each a list
of strings, and a limits dimension, a map of limit name to integer
maximum. Attenuation is checked dimension by dimension.
"""

import copy
import json

from acta.canonical import canonical_bytes, sha256_hex
from acta.signing import b64decode, b64encode

from .standing import validate_standing_policy

CHARTER_VERSION = "0.1"
CHARTER_PAYLOAD_TYPE = "application/vnd.institutio.charter.v0.1+json"

SET_DIMENSIONS = ("tools", "resources", "operations")
ON_LIMIT_ACTIONS = ("refuse", "escalate")


class CharterValidationError(ValueError):
    """Raised by load_charter when a charter fails validation."""

    def __init__(self, errors):
        self.errors = errors
        super().__init__("charter validation failed: " + "; ".join(errors))


def scope_subset_errors(child, parent, where):
    """Errors where child scope exceeds parent scope, dimension by dimension.

    A child delegation wider than its parent in any dimension is an
    attenuation violation and must fail validation.
    """
    errors = []
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return ["%s: scope must be a JSON object" % where]
    for key in child:
        if key not in SET_DIMENSIONS and key != "limits":
            errors.append(
                "%s: unknown scope dimension %s; a scope carries only "
                "tools, resources, operations and limits, and an "
                "unrecognised dimension is never silently ignored "
                "(re-audit minor r6)" % (where, key)
            )
    for dim in SET_DIMENSIONS:
        child_values = child.get(dim, [])
        parent_values = parent.get(dim, [])
        if not isinstance(child_values, list) or not isinstance(parent_values, list):
            errors.append("%s: scope dimension %s must be a list" % (where, dim))
            continue
        for value in child_values:
            if value not in parent_values:
                errors.append(
                    "%s: %s exceeds parent: %r is not granted by the parent scope"
                    % (where, dim, value)
                )
    child_limits = child.get("limits", {})
    parent_limits = parent.get("limits", {})
    if not isinstance(child_limits, dict) or not isinstance(parent_limits, dict):
        errors.append("%s: scope limits must be a JSON object" % where)
        return errors
    for name, parent_max in parent_limits.items():
        if isinstance(parent_max, bool) or not isinstance(parent_max, int):
            errors.append(
                "%s: limit %s must be a non-negative integer" % (where, name)
            )
            continue
        if name not in child_limits:
            errors.append(
                "%s: limits exceeds parent: parent caps %s at %r but the "
                "child sets no cap" % (where, name, parent_max)
            )
        elif (isinstance(child_limits[name], bool)
              or not isinstance(child_limits[name], int)
              or child_limits[name] > parent_max):
            errors.append(
                "%s: limits exceeds parent: child cap for %s is %r, "
                "parent cap is %r" % (where, name, child_limits.get(name), parent_max)
            )
    for name, value in child_limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(
                "%s: limit %s must be a non-negative integer" % (where, name)
            )
    return errors


def charter_payload(charter):
    """The signed and hashed view of a charter (no hash, no envelope)."""
    return {
        key: value
        for key, value in charter.items()
        if key not in ("charter_hash", "envelope")
    }


def compute_charter_hash(charter):
    return sha256_hex(canonical_bytes(charter_payload(charter)))


def sign_charter(charter, signer):
    """Return a copy of the charter with its hash and DSSE envelope."""
    signed = copy.deepcopy(charter)
    signed.pop("charter_hash", None)
    signed.pop("envelope", None)
    signed["charter_hash"] = compute_charter_hash(signed)
    payload_bytes = canonical_bytes(charter_payload(signed))
    signed["envelope"] = {
        "payload_type": CHARTER_PAYLOAD_TYPE,
        "payload": b64encode(payload_bytes),
        "signatures": [
            {"key_id": signer.key_id,
             "signature": signer.sign(CHARTER_PAYLOAD_TYPE, payload_bytes)}
        ],
    }
    return signed


def _check_delegation_loops(manifests, errors):
    """Detect cycles in the parent-manifest chain and delegation graph."""
    by_id = {m.get("manifest_id"): m for m in manifests}
    for manifest in manifests:
        seen = set()
        node = manifest
        while node is not None and node.get("parent_manifest_id"):
            parent_id = node["parent_manifest_id"]
            if parent_id in seen:
                errors.append(
                    "manifest %s: delegation loop through parent manifests"
                    % manifest.get("manifest_id")
                )
                break
            seen.add(parent_id)
            node = by_id.get(parent_id)
    graph = {}
    for manifest in manifests:
        graph.setdefault(manifest.get("grantor_seat"), set()).add(
            manifest.get("grantee_seat")
        )
    visiting, done = set(), set()

    def visit(seat):
        if seat in visiting:
            errors.append("delegation loop involving seat %s" % seat)
            return
        if seat in done:
            return
        visiting.add(seat)
        for nxt in graph.get(seat, ()):
            visit(nxt)
        visiting.discard(seat)
        done.add(seat)

    for seat in list(graph):
        visit(seat)


def _signature_errors(charter, verifiers, authorized_key_ids):
    """Signature errors for one charter (audit finding C2).

    A charter is valid only when its DSSE envelope carries a
    signature that verifies, under the signer interface, against a
    key in the authorised key set, over the exact charter payload
    bytes. verifiers maps key_id to a Signer for the keys the
    validator trusts; without a verifier for an authorised key the
    signature cannot be checked and validation fails closed.
    """
    envelope = charter.get("envelope")
    if not isinstance(envelope, dict):
        return ["charter is not signed: no DSSE envelope"]
    if envelope.get("payload_type") != CHARTER_PAYLOAD_TYPE:
        return ["charter envelope has a missing or mistyped payload_type"]
    try:
        payload_bytes = b64decode(envelope["payload"])
    except Exception:
        return ["charter envelope payload is not valid base64"]
    if payload_bytes != canonical_bytes(charter_payload(charter)):
        return ["charter envelope payload does not match the charter contents"]
    signatures = envelope.get("signatures") or []
    if not signatures:
        return ["charter envelope carries no signatures"]
    if not verifiers:
        return [
            "charter signature cannot be verified: no verifier "
            "supplied for the charter key set"
        ]
    if not authorized_key_ids:
        return [
            "the authorised key set for this charter is empty; no "
            "key is authorised, and validation fails closed rather "
            "than falling back to a key set the document declares "
            "for itself (re-audit finding C2)"
        ]
    for entry in signatures:
        key_id = entry.get("key_id")
        if key_id not in authorized_key_ids:
            continue
        verifier = verifiers.get(key_id)
        if verifier is not None and verifier.verify(
            CHARTER_PAYLOAD_TYPE, payload_bytes, entry.get("signature", "")
        ):
            return []
    return [
        "charter signature does not verify under any authorised key "
        "(authorised: %s)" % ", ".join(sorted(authorized_key_ids))
    ]


def validate_charter(charter, verifiers=None, authorized_key_ids=None,
                     pinned_founder_key_ids=None):
    """Validate one charter dict. Returns a list of error strings.

    verifiers maps key_id to a Signer for the keys the validator
    trusts; the charter's signature is verified against it (audit
    finding C2). The authorised key set is a trust anchor supplied
    by the caller, never read out of the untrusted charter itself
    (re-audit finding C2): pass authorized_key_ids explicitly, or
    pinned_founder_key_ids, the pinned founder key set against
    which a founding charter is checked. With neither, the
    signature check fails closed. validate_charter_chain passes
    the predecessor's authorised set for amendments, as established
    by the verified predecessor.
    """
    errors = []
    if not isinstance(charter, dict):
        return ["charter is not a JSON object"]
    for field in (
        "charter_version", "org", "seats", "authority_manifests",
        "budgets", "amendment", "succession", "kill_switch",
        "standing_policy", "anchoring",
    ):
        if field not in charter:
            errors.append("missing required field: %s" % field)
    if errors:
        return errors

    org = charter["org"]
    if not isinstance(org, dict) or not all(
        key in org for key in ("name", "charter_id", "founder_key_id", "founded")
    ):
        errors.append(
            "org must carry name, charter_id, founder_key_id and founded")

    if authorized_key_ids is None:
        if pinned_founder_key_ids is not None:
            authorized_key_ids = set(pinned_founder_key_ids)
        else:
            errors.append(
                "charter signature cannot be authorised: the caller "
                "supplied no pinned key set, and the charter's own "
                "declarations are not a trust anchor "
                "(re-audit finding C2)")
            authorized_key_ids = set()
    errors.extend(_signature_errors(charter, verifiers, authorized_key_ids))
    for error in validate_standing_policy(charter["standing_policy"]):
        errors.append("standing_policy: %s" % error)

    seats = {}
    for seat in charter["seats"]:
        seat_id = seat.get("seat_id")
        if not seat_id:
            errors.append("seat without a seat_id")
            continue
        if seat_id in seats:
            errors.append("duplicate seat_id: %s" % seat_id)
        seats[seat_id] = seat
        if "scope" not in seat:
            errors.append("seat %s: missing scope" % seat_id)
    for seat in charter["seats"]:
        reports_to = seat.get("reports_to")
        if reports_to is not None and reports_to not in seats:
            errors.append(
                "seat %s: reports_to names unknown seat %s"
                % (seat.get("seat_id"), reports_to)
            )

    manifests = charter["authority_manifests"]
    manifest_ids = set()
    for manifest in manifests:
        manifest_id = manifest.get("manifest_id")
        if not manifest_id:
            errors.append("authority manifest without a manifest_id")
            continue
        if manifest_id in manifest_ids:
            errors.append("duplicate manifest_id: %s" % manifest_id)
        manifest_ids.add(manifest_id)
    by_id = {m.get("manifest_id"): m for m in manifests}

    for manifest in manifests:
        manifest_id = manifest.get("manifest_id", "?")
        grantor = manifest.get("grantor_seat")
        grantee = manifest.get("grantee_seat")
        if grantor not in seats:
            errors.append("manifest %s: unknown grantor seat %s" % (manifest_id, grantor))
            continue
        if grantee not in seats and not manifest.get("grantee_external"):
            errors.append("manifest %s: unknown grantee seat %s" % (manifest_id, grantee))
        if "scope" not in manifest:
            errors.append("manifest %s: missing scope" % manifest_id)
            continue
        errors.extend(
            scope_subset_errors(
                manifest["scope"], seats[grantor].get("scope", {}),
                "manifest %s scope vs grantor seat %s" % (manifest_id, grantor),
            )
        )
        if grantee in seats:
            errors.extend(
                scope_subset_errors(
                    manifest["scope"], seats[grantee].get("scope", {}),
                    "manifest %s scope vs grantee seat %s"
                    % (manifest_id, grantee),
                )
            )
        issued = manifest.get("issued_at")
        expires = manifest.get("expires_at")
        if not isinstance(issued, int):
            errors.append("manifest %s: issued_at must be integer seconds" % manifest_id)
        if expires is not None and (not isinstance(expires, int) or expires <= issued):
            errors.append("manifest %s: expires_at must be after issued_at" % manifest_id)
        parent_id = manifest.get("parent_manifest_id")
        if parent_id is not None:
            parent = by_id.get(parent_id)
            if parent is None:
                errors.append(
                    "manifest %s: unknown parent manifest %s" % (manifest_id, parent_id)
                )
            else:
                if not parent.get("sub_delegation_allowed"):
                    errors.append(
                        "manifest %s: parent manifest %s does not permit "
                        "sub-delegation" % (manifest_id, parent_id)
                    )
                if manifest.get("grantor_seat") != parent.get("grantee_seat"):
                    errors.append(
                        "manifest %s: grantor must be the grantee of its "
                        "parent manifest %s" % (manifest_id, parent_id)
                    )
                errors.extend(
                    scope_subset_errors(
                        manifest["scope"], parent.get("scope", {}),
                        "manifest %s scope vs parent manifest %s"
                        % (manifest_id, parent_id),
                    )
                )
    _check_delegation_loops(manifests, errors)

    budget_ids = set()
    for budget in charter["budgets"]:
        budget_id = budget.get("budget_id")
        if not budget_id:
            errors.append("budget without a budget_id")
            continue
        budget_ids.add(budget_id)
        if not isinstance(budget.get("amount"), int) or budget["amount"] < 0:
            errors.append("budget %s: amount must be a non-negative integer" % budget_id)
        if not budget.get("unit"):
            errors.append("budget %s: missing unit" % budget_id)
        if budget.get("on_limit") not in ON_LIMIT_ACTIONS:
            errors.append(
                "budget %s: on_limit must be one of %s"
                % (budget_id, list(ON_LIMIT_ACTIONS))
            )
        if budget.get("seat_id") is not None and budget["seat_id"] not in seats:
            errors.append(
                "budget %s: unknown seat %s" % (budget_id, budget["seat_id"])
            )
    for manifest in manifests:
        ref = manifest.get("budget_ref")
        if ref is not None and ref not in budget_ids:
            errors.append(
                "manifest %s: budget_ref names unknown budget %s"
                % (manifest.get("manifest_id"), ref)
            )

    succession = charter["succession"]
    entries = succession if isinstance(succession, list) else []
    if isinstance(succession, dict):
        entries = succession.get("entries", [])
    for entry in entries:
        if entry.get("seat") not in seats:
            errors.append("succession: unknown seat %s" % entry.get("seat"))
        successor = entry.get("successor_seat")
        if successor is not None and successor not in seats:
            errors.append("succession: unknown successor seat %s" % successor)

    # Frozen-field grammar (second re-audit minor s1): a
    # frozen_fields entry names a top-level charter field. A
    # dotted entry such as "kill_switch.authorized_key_ids" was
    # accepted silently and froze nothing, because the chain check
    # compares top-level payload keys. It is a validation error,
    # as is any entry that is not a top-level field of this
    # charter: a freeze that does not exist must not look like one.
    amendment = charter.get("amendment") or {}
    top_level = set(charter_payload(charter))
    for entry in amendment.get("frozen_fields") or []:
        if not isinstance(entry, str) or "." in entry:
            errors.append(
                "amendment.frozen_fields entry %r is not a "
                "top-level field name; dotted paths freeze nothing "
                "and are rejected" % (entry,))
        elif entry not in top_level:
            errors.append(
                "amendment.frozen_fields entry %r names no "
                "top-level field of this charter; it would freeze "
                "nothing and is rejected" % (entry,))

    kill_switch = charter["kill_switch"]
    if not isinstance(kill_switch, dict) or not kill_switch.get("authorized_key_ids"):
        errors.append("kill_switch must name at least one authorized key id")
    recovery = (kill_switch or {}).get("recovery_seat")
    if recovery is not None and recovery not in seats:
        errors.append("kill_switch: unknown recovery seat %s" % recovery)

    if "charter_hash" in charter:
        if charter["charter_hash"] != compute_charter_hash(charter):
            errors.append("charter_hash does not match the charter contents")
    return errors


def validate_charter_chain(charters, verifiers=None, founder_key_ids=None):
    """Validate a charter history: each charter valid, hashes linked.

    The founding charter carries no predecessor_charter_hash. Every
    later charter must name the hash of the charter it supersedes.
    The founding charter is verified against founder_key_ids, a
    pinned founder key set supplied by the caller from outside the
    documents (re-audit finding C2); with none supplied, the chain
    fails closed. An amendment must be signed by a key the
    predecessor's amendment rules authorise, as established by the
    verified predecessor; a predecessor whose amendment rules name
    no authorised keys authorises no amendment at all, and there is
    no fallback to a key set the amendment declares for itself.

    Frozen fields are cumulative (re-audit finding M6): the frozen
    set is the union of every predecessor's frozen_fields, the
    frozen_fields list itself may only grow (an amendment that
    drops a previously frozen field is rejected at that step, so
    the two-step unfreeze fails at step 1), and org.founded, a fact
    about the organisation rather than a term of it, may never be
    rewritten by any amendment. Returns a list of error strings.
    """
    errors = []
    previous_hash = None
    previous = None
    frozen_union = set()
    for index, charter in enumerate(charters):
        if index == 0:
            authorized = set(founder_key_ids) if founder_key_ids else set()
            if not founder_key_ids:
                errors.append(
                    "charter 0: no pinned founder key set supplied by "
                    "the caller; the founding charter's own "
                    "declarations are not a trust anchor "
                    "(re-audit finding C2)")
        else:
            prev_amendment = (previous or {}).get("amendment") or {}
            authorized = set(prev_amendment.get("authorized_key_ids") or [])
        for error in validate_charter(
                charter, verifiers=verifiers, authorized_key_ids=authorized):
            errors.append("charter %d: %s" % (index, error))
        predecessor = charter.get("predecessor_charter_hash")
        if index == 0:
            if predecessor is not None:
                errors.append(
                    "charter 0: founding charter must not name a predecessor"
                )
        elif predecessor != previous_hash:
            errors.append(
                "charter %d: predecessor_charter_hash does not match the "
                "hash of charter %d; the amendment chain is broken"
                % (index, index - 1)
            )
        if previous is not None:
            current_payload = charter_payload(charter)
            previous_payload = charter_payload(previous)
            for field in sorted(frozen_union):
                if current_payload.get(field) != previous_payload.get(field):
                    errors.append(
                        "charter %d: amendment rewrites frozen field "
                        "%s, frozen by an earlier charter in this chain"
                        % (index, field)
                    )
            current_frozen = set(
                ((charter.get("amendment") or {}).get("frozen_fields") or []))
            dropped = frozen_union - current_frozen
            if dropped:
                errors.append(
                    "charter %d: amendment drops frozen field(s) %s "
                    "from frozen_fields; the freeze list itself is "
                    "frozen and may only grow"
                    % (index, ", ".join(sorted(dropped)))
                )
            if (current_payload.get("org") or {}).get("founded") != (
                    previous_payload.get("org") or {}).get("founded"):
                errors.append(
                    "charter %d: amendment rewrites org.founded, "
                    "which no amendment may alter" % index)
        frozen_union |= set(
            ((charter.get("amendment") or {}).get("frozen_fields") or []))
        previous_hash = compute_charter_hash(charter)
        previous = charter
    return errors


def load_charter(path, verifiers=None, pinned_founder_key_ids=None):
    """Load a charter JSON file and validate it. Raises on failure."""
    with open(path, "r", encoding="utf-8") as handle:
        charter = json.load(handle)
    errors = validate_charter(
        charter, verifiers=verifiers,
        pinned_founder_key_ids=pinned_founder_key_ids)
    if errors:
        raise CharterValidationError(errors)
    return charter


def example_charter():
    """A minimal valid charter, used by tests and the fixture generator."""
    return {
        "charter_version": CHARTER_VERSION,
        "org": {
            "name": "Example Firm",
            "charter_id": "org-example-0001",
            "founded": "2026-11-23",
            "founder_key_id": "founder-root-key-1",
        },
        "seats": [
            {
                "seat_id": "founder",
                "title": "Founder",
                "role": "root",
                "occupant_key_id": "founder-root-key-1",
                "reports_to": None,
                "scope": {
                    "tools": ["read", "write", "exec"],
                    "resources": ["repo", "ledger"],
                    "operations": ["call", "delegate", "revoke"],
                    "limits": {"external_calls": 100, "spend_units": 1000},
                },
            },
            {
                "seat_id": "operator",
                "title": "Operator",
                "role": "worker",
                "occupant_key_id": "operator-key-1",
                "reports_to": "founder",
                "scope": {
                    "tools": ["read", "write"],
                    "resources": ["repo"],
                    "operations": ["call", "delegate"],
                    "limits": {"external_calls": 10, "spend_units": 100},
                },
            },
            {
                "seat_id": "helper",
                "title": "Helper",
                "role": "worker",
                "occupant_key_id": "helper-key-1",
                "reports_to": "operator",
                "scope": {
                    "tools": ["read"],
                    "resources": ["repo"],
                    "operations": ["call"],
                    "limits": {"external_calls": 2, "spend_units": 10},
                },
            },
        ],
        "authority_manifests": [
            {
                "manifest_id": "m-founder-operator",
                "grantor_seat": "founder",
                "grantee_seat": "operator",
                "scope": {
                    "tools": ["read", "write"],
                    "resources": ["repo"],
                    "operations": ["call", "delegate"],
                    "limits": {"external_calls": 10, "spend_units": 100},
                },
                "issued_at": 1763900000,
                "expires_at": 1766500000,
                "sub_delegation_allowed": True,
                "budget_ref": "b-operator",
            },
            {
                "manifest_id": "m-operator-helper",
                "grantor_seat": "operator",
                "grantee_seat": "helper",
                "parent_manifest_id": "m-founder-operator",
                "scope": {
                    "tools": ["read"],
                    "resources": ["repo"],
                    "operations": ["call"],
                    "limits": {"external_calls": 2, "spend_units": 10},
                },
                "issued_at": 1763900100,
                "expires_at": 1766500000,
                "sub_delegation_allowed": False,
            },
        ],
        "budgets": [
            {
                "budget_id": "b-operator",
                "seat_id": "operator",
                "amount": 100,
                "unit": "spend_units",
                "period": "day",
                "on_limit": "refuse",
            }
        ],
        "amendment": {
            "authorized_key_ids": ["founder-root-key-1"],
            "notice_period_seconds": 86400,
            # "amendment" is frozen so the authorised key set
            # cannot be rotated away from the founder by an
            # amendment (Section 16.10 decision 20).
            "frozen_fields": ["kill_switch", "amendment"],
        },
        "succession": [
            {"seat": "founder", "successor_seat": "operator",
             "trigger": "signed_succession_act"}
        ],
        "kill_switch": {
            "authorized_key_ids": ["founder-root-key-1"],
            "recovery_seat": "founder",
        },
        "standing_policy": {
            "standing_policy_version": "0.1",
            "epoch_seconds": 86400,
            "scope_classes": {
                "default": {
                    "mint_rate": 1,
                    "mint_cap_per_epoch": 50,
                    "half_life_seconds": 604800,
                    # Class fields live in the class object only
                    # (Section 16.10 decision 24 row (e)); this
                    # example once stated burn_unit and
                    # severe_reason_codes at policy level, where
                    # no conforming parser reads them.
                    "burn_unit": 5,
                    "severe_reason_codes": ["revoked", "scope"],
                    "burn_multipliers": {"revoked": 10, "scope": 10},
                }
            },
        },
        "anchoring": {"mechanisms": ["rfc3161", "transparency-log"]},
    }
