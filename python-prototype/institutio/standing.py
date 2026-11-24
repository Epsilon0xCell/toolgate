"""ComputeStanding: Receipt-Minted Authority, specification Section 16.

Author: Gavin Blacklock

Normative prototype implementation. Standing is never assigned. It is
computed by this pure, deterministic function of (receipt chain,
charter standing_policy, evaluation time): the same inputs produce
the same Standing vector and ceilings on any conforming run. Only
receipts from an already verified chain should be passed in; this
module does not verify signatures. All arithmetic is integer
arithmetic. No wall clock, no randomness.

The computation, per scope class, in chain order:

1. MINT (invariant I4). An ACTION receipt mints
   mint_rate * risk_weight, attenuated by hop_attenuation_ppm
   (Section 16.10 decision 6: floor(amount * ppm ** depth /
   1,000,000 ** depth)). Where the policy requires a counterparty
   countersignature for the class, an ACTION without a verified
   counterparty_sig mints zero. Mint is then clipped, in this order,
   by the per-epoch mint cap, the per-epoch diversity cap for the
   receipt's counterparty, the per-epoch diversity cap for the
   receipt's task type (its action name), and the per-epoch
   diversity cap for the receipt's subtree (Section 16.10
   decision 8).
2. BURN (invariant I5). A DENIAL receipt burns
   burn_unit * burn_multipliers[reason_code] * n * n, where n is the
   ordinal of that denial within its scope class (Section 16.10
   decision 2, the closed form; no computation-time floor is applied
   beyond it). The I5 severe floor is a policy-validation condition
   instead: validate_standing_policy rejects a policy whose severe
   burn cannot erase its epoch mint cap (audit finding M3, as
   amended by Section 16.10). A severe denial also burns
   floor(burn * correlated_burn_fraction_ppm / 1,000,000) in every
   other scope class in which the same agent has at least one
   receipt in the segment (Section 16.10 decision 7,
   correlated-class burn, I5).
3. DECAY (invariant I6). Each mint contribution decays by whole
   half-lives between its receipt time and the evaluation time
   (integer shift, exact and reproducible). Burns do not decay.
4. DERIVED RECEIPTS (Section 16.3). BURN, PROMOTION and DEMOTION
   receipts are tallied and confer nothing: the DENIAL a BURN derives
   from already burned. A KILL-BURN receipt zeroes the agent in every
   scope class from that point on (Section 16.6): accumulated mint is
   discarded, and later ACTION receipts mint nothing.
5. CEILINGS. The ceiling curve maps Standing to ceilings. The legacy
   scalar "ceiling" is the reached tier's max_budget_per_action; the
   "ceilings" dict is the highest curve tier whose min_standing the
   computed Standing reaches. A policy with no ceiling_curve states
   no ceilings, and producing them is an UNSPECIFIED_BY_SPEC error.

Effective authority (Section 16.1) is the minimum of the charter
grant, the delegation manifest, and the Standing ceiling; see
effective_authority below.

NO INVENTED DEFAULTS (second re-audit finding S3, repair round 3).
Section 16.10 assigns every numeric parameter to the policy itself.
Where a decision requires a policy field, a missing field is an
error in this computation, never a silent default: mint_rate at an
ACTION, burn_unit and the reason code's burn multiplier at a
DENIAL, half_life_seconds where mint events decay,
hop_attenuation_ppm where a delegation depth attenuates, and the
ceiling_curve where ceilings are produced. The error is raised as
a ValueError whose message begins UNSPECIFIED_BY_SPEC, the
prototype's equivalent of institutio-core's UnspecifiedBySpec.
Callers (the gate, the demo, the fixtures, the tests) state their
policies completely. What absence still means, because the
specification says so: no mint_cap_per_epoch means no cap, no
diversity cap means no cap for that dimension, no epoch_seconds
means a single epoch (decision 3; an epoch_seconds that is present
must be at least 1), and no countersign requirement means
countersignatures are not required for the class. The severe
reason codes default to ("revoked", "scope"), the codes invariant
I5 names in prose, exactly as institutio-core defaults them. The
countersign requirement itself is read from exactly one encoding,
countersign_policy {"required_for": [...]} (Section 16.10
decision 22); any other shape or field name is a validation
error. The prototype's legacy alias encodings
(hop_attenuation_percent, correlated_burn_divisor, flat diversity
keys, mint_per_action, burn_per_denial) are retired as of repair
round 4: no implementation reads them, and the accepted policy
language is exactly the Section 16.10 fields. Policy values are
type-strict: a boolean or float where an integer is required is
an error, never a coercion, as in the Rust parser. Repair round
5 (Section 16.10 decision 24, the strictness table) completed
the surface: quantity values are also sign-strict (a negative
burn manufactured Standing here, finding U1); the policy is
parsed eagerly, completely, and class-locally, with no
top-level field merging into a class and every class validated
whether or not the computation touches it (finding U2); a
stated null is a malformed value for every policy field and
receipt scalar, never an absent field (finding U3); the
witness policy is validated at computation entry with its
quorum bounds (finding S5 residue); and receipt timestamps
and identities are strict (findings U5 and the T2 residue).
Repair round 6 (fifth re-audit findings W1 to W5) closed
the residue: a stated null counterparty_id or
subtree_root_id is a validation error here, never read as
absence (W1); validate_standing_policy examines
witness_policy with the same strictness as the computation
and verification doors (W2); ceiling curve tiers must carry
all six ceiling fields plus min_standing (W3); an unknown
receipt type raises INVALID_RECEIPT instead of tallying as
nothing (W4); and an agent field that is not the agent
object is a validation error, never an AttributeError and
never a silent empty computation (W5).
- A countersignature is verified, not merely present (audit finding
  M2). Where the policy requires one, mint is full weight only when
  counterparty_sig verifies, under the signer interface, against
  the key of the named counterparty_id over the outcome descriptor
  under COUNTERPARTY_PAYLOAD_TYPE. The descriptor binds the receipt
  identity and the risk actually borne: agent id, action name,
  scope class, timestamp, risk_weight, receipt_id, arguments_hash,
  and result_hash (re-audit finding M2: a countersignature over
  fewer fields can be replayed onto another receipt or re-weighted
  at will). Callers pass counterparty_verifiers, a map of
  counterparty_id to a Signer; a required countersignature that is
  missing, unverifiable, or from an unknown counterparty mints zero.
- Receipt field locations: scope class is standing_scope_class, or
  action.scope_class, or "default"; risk_weight, counterparty_id,
  counterparty_sig, delegation_depth and subtree_root_id are read
  from the receipt first, then from its action dict.
- A receipt timestamped after the evaluation time is handled by the
  formula of Section 16.10 decision 4 itself: its decay age is
  max(0, eval_time - t), so it mints at full (undecayed) value. The
  specification fixes no monotonicity rule for receipt timestamps,
  so none is invented here (re-audit minor r2, closed by reference
  to decision 4).
"""

from acta.canonical import canonical_bytes, sha256_hex
from acta.receipts import GENESIS_HASH, RECEIPT_TYPES, chain_head

COUNTERPARTY_PAYLOAD_TYPE = "application/vnd.acta.counterparty-outcome.v0.1+json"
CHECKPOINT_PAYLOAD_TYPE = "application/vnd.institutio.checkpoint.v0.1+json"


def counterparty_outcome_bytes(agent_id, action_name, scope_class, timestamp,
                               risk_weight=None, receipt_id=None,
                               arguments_hash=None, result_hash=None):
    """The exact bytes a counterparty countersigns for an outcome.

    The descriptor binds the receipt identity and the risk weight
    (re-audit finding M2): a countersignature over these bytes
    cannot be replayed onto a different receipt, and cannot be
    re-weighted, because every field a minter could vary is inside
    the signed bytes. Fields a receipt does not carry are signed
    as null, so a countersignature made for a receipt lacking a
    receipt_id verifies only against receipts lacking one.
    """
    return canonical_bytes({
        "agent_id": agent_id,
        "action_name": action_name,
        "arguments_hash": arguments_hash,
        "receipt_id": receipt_id,
        "result_hash": result_hash,
        "risk_weight": risk_weight,
        "scope_class": scope_class,
        "timestamp": int(timestamp),
    })


def countersign_outcome(signer, agent_id, action_name, scope_class, timestamp,
                        risk_weight=None, receipt_id=None,
                        arguments_hash=None, result_hash=None):
    """Produce a counterparty countersignature with a Signer."""
    return signer.sign(
        COUNTERPARTY_PAYLOAD_TYPE,
        counterparty_outcome_bytes(
            agent_id, action_name, scope_class, timestamp,
            risk_weight=risk_weight, receipt_id=receipt_id,
            arguments_hash=arguments_hash, result_hash=result_hash),
    )


def _countersignature_verifies(receipt, action, scope_class, verifiers):
    """True only when counterparty_sig verifies for counterparty_id."""
    if not verifiers:
        return False
    counterparty_id = _field(receipt, action, "counterparty_id")
    signature = _field(receipt, action, "counterparty_sig")
    if counterparty_id is None or not signature:
        return False
    verifier = verifiers.get(counterparty_id)
    if verifier is None:
        return False
    agent_id = _agent_id(receipt)
    risk_weight = _field(receipt, action, "risk_weight", 1)
    return bool(verifier.verify(
        COUNTERPARTY_PAYLOAD_TYPE,
        counterparty_outcome_bytes(
            agent_id, action.get("name"), scope_class,
            _receipt_timestamp(receipt),
            risk_weight=risk_weight,
            receipt_id=receipt.get("receipt_id"),
            arguments_hash=action.get("arguments_hash"),
            result_hash=receipt.get("result_hash")),
        signature,
    ))

DEFAULT_SEVERE_REASON_CODES = ("revoked", "scope")

PPM = 1000000


def _strict_int(value, field):
    """An integer policy or receipt value, or an error (t3, S2).

    Booleans and floats where an integer is required are errors,
    never coercions: the Rust parser rejects both (serde's as_u64
    admits neither), and a value one tree coerces and the other
    rejects is a policy that means two things. Repair round 4
    brought this parser to the same strictness.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            "%s must be an integer, got %r; a boolean or float "
            "where an integer is required is a policy validation "
            "error, never a coercion" % (field, value))
    return value


def _strict_quantity(value, field):
    """A non-negative integer quantity (Section 16.10 decision 24).

    Decision 24 rows (a) and (b): every quantity, rate, cap,
    multiplier, weight, and timestamp is an integer and
    non-negative, or the input is malformed. The sign half is
    repair round 5 (fourth re-audit finding U1): the type check
    alone let a negative burn_unit or burn multiplier through,
    and a negative burn manufactures Standing.
    """
    value = _strict_int(value, field)
    if value < 0:
        raise ValueError(
            "%s must be non-negative, got %r; a negative quantity "
            "is a policy validation error, never computed with "
            "(Section 16.10 decision 24)" % (field, value))
    return value


def _stated(mapping, key, field):
    """The value of a stated field, rejecting a stated null.

    Decision 24 row (c): a field stated as null is a malformed
    value, never an absent field, in either implementation.
    Callers test presence with `key in mapping` first.
    """
    value = mapping[key]
    if value is None:
        raise ValueError(
            "%s is stated as null; a stated null is a malformed "
            "value, never an absent field (Section 16.10 "
            "decision 24)" % field)
    return value


def _agent_id(receipt):
    """The acting agent's id, validating the agent field's shape.

    The agent field is the specification's agent object
    {id, model, model_version}. A stated agent that is not an
    object (a bare string, a number, a stated null) is a
    validation error, never a crash and never a silent empty
    selection (fifth re-audit finding W5: this reader once
    raised AttributeError on a string agent here, while the
    Rust parser read the id as absent and computed nothing).
    An absent agent field remains absence: the receipt selects
    no agent, as before.
    """
    if "agent" not in receipt:
        return None
    agent = receipt["agent"]
    if not isinstance(agent, dict):
        raise ValueError(
            "agent must be the agent object {id, model, "
            "model_version}, got %r; an agent stated in any "
            "other shape is a malformed receipt, never a crash "
            "and never an empty computation (Section 16.10 "
            "decision 24)" % (agent,))
    return agent.get("id")


def _receipt_text_field(receipt, action, name):
    """A stated string receipt field, or None when absent.

    Read from the receipt first, then from its action dict, the
    precedence _field uses. A stated null is a malformed value,
    never absence, and a stated non-string is malformed: the
    Rust prototype parser reads both fields named by callers
    (counterparty_id, subtree_root_id) exactly this way, and
    this reader once returned the stated null, keying diversity
    accounting on the string form of None or attributing the
    receipt to the agent's own subtree (fifth re-audit
    finding W1).
    """
    for source in (receipt, action):
        if isinstance(source, dict) and name in source:
            value = _stated(source, name, name)
            if not isinstance(value, str):
                raise ValueError(
                    "%s must be a string, got %r; a stated "
                    "non-string is a malformed receipt "
                    "(Section 16.10 decision 24)" % (name, value))
            return value
    return None


def _receipt_timestamp(receipt):
    """A receipt timestamp: an integer number of seconds (U5).

    Decision 24 rows (a) and (b): a float or string timestamp is
    malformed, never coerced with int() and never defaulted to
    0, and a negative timestamp is malformed. An absent
    timestamp remains 0, as before: absence is not a stated
    value.
    """
    timestamp = receipt.get("timestamp", 0)
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
            or timestamp < 0:
        raise ValueError(
            "timestamp must be a non-negative integer number of "
            "seconds, got %r; a float or string timestamp is a "
            "malformed receipt, never coerced (Section 16.10 "
            "decision 24)" % (timestamp,))
    return timestamp


def _validate_witness_policy(standing_policy):
    """Validate witness_policy at policy load (finding S5 residue).

    Section 16.10 decision 15 fixes the form and decision 24
    row (e) requires its bounds to be checked wherever the
    policy is parsed or computed under, not only at checkpoint
    verification: the Python computation once never read the
    field at all, so seven malformed forms computed Standing
    while the Rust parser refused them. Raises ValueError on
    any malformation; returns the parsed policy or None.
    """
    if not standing_policy or "witness_policy" not in standing_policy:
        return None
    witness_policy = _stated(
        standing_policy, "witness_policy", "witness_policy")
    if not isinstance(witness_policy, dict) or set(
            witness_policy) != {"witness_key_ids", "quorum"}:
        raise ValueError(
            "witness_policy must be an object of exactly the "
            "form {witness_key_ids, quorum} (Section 16.10 "
            "decision 15); got %r" % (witness_policy,))
    allowed = witness_policy["witness_key_ids"]
    if not isinstance(allowed, list) or any(
            not isinstance(k, str) for k in allowed):
        raise ValueError(
            "witness_policy witness_key_ids must be an array of "
            "key identifier strings (Section 16.10 decision 15); "
            "got %r" % (allowed,))
    quorum = _strict_int(witness_policy["quorum"], "witness_policy quorum")
    if not 1 <= quorum <= len(allowed):
        raise ValueError(
            "witness_policy quorum %d is outside 1..=%d "
            "(Section 16.10 decision 15)" % (quorum, len(allowed)))
    return witness_policy


def _countersign_required_for(standing_policy, scope_class):
    """Whether the policy requires a countersignature for a class.

    Section 16.10 decision 22 fixes ONE encoding: the top-level
    field countersign_policy, an object {"required_for": [class
    names]}, the only key it may carry. Every other shape (a bare
    boolean or array, another inner form, the field inside a
    scope class, or a differently named field such as
    countersign_required anywhere) is a validation error here,
    never silently honoured and never silently ignored (third
    re-audit finding T1: each tree once read its own encoding and
    ignored the other's, minting at full weight where the other
    minted zero).
    """
    if not standing_policy:
        return False
    if "countersign_required" in standing_policy:
        raise ValueError(
            "countersign_required is not a conforming field name; "
            "the countersign requirement is stated only as "
            "countersign_policy (Section 16.10 decision 22)")
    classes = standing_policy.get("scope_classes") or {}
    if not isinstance(classes, dict):
        # The scope_classes type error itself is raised by
        # _class_policy; do not crash on it here first (U6).
        classes = {}
    for name, per_class in classes.items():
        if isinstance(per_class, dict) and (
                "countersign_required" in per_class
                or "countersign_policy" in per_class):
            raise ValueError(
                "the countersign requirement inside scope class %s "
                "is non-conforming; it is stated only at the top "
                "level of standing_policy as countersign_policy "
                "(Section 16.10 decision 22)" % name)
    if "countersign_policy" not in standing_policy:
        return False
    stated = _stated(
        standing_policy, "countersign_policy", "countersign_policy")
    if not isinstance(stated, dict) or set(stated) != {"required_for"}:
        raise ValueError(
            "countersign_policy must be an object of exactly the "
            "form {\"required_for\": [scope class names]} "
            "(Section 16.10 decision 22); got %r" % (stated,))
    required_for = stated["required_for"]
    if not isinstance(required_for, list) or any(
            not isinstance(name, str) for name in required_for):
        raise ValueError(
            "countersign_policy required_for must be an array of "
            "scope class name strings (Section 16.10 decision 22); "
            "got %r" % (required_for,))
    return scope_class in required_for


def _validate_curve(curve):
    """Ceiling curve tiers carry every field, strictly (t3, W3).

    Section 16.10 decision 10 fixes the tier's field set:
    min_standing plus the six ceiling outputs. A tier missing
    any field is a policy error, never a silently incomplete
    ceilings entry: this validator once checked only the
    fields present, so a tier without max_fanout computed
    here while the Rust parser, which requires all seven
    fields, refused it (fifth re-audit finding W3).
    """
    if curve is None:
        return None
    if not isinstance(curve, list):
        raise ValueError("ceiling_curve must be an array of tiers")
    for tier in curve:
        if not isinstance(tier, dict):
            raise ValueError("ceiling_curve tier is not an object")
        for field in ("min_standing", "max_budget_per_action",
                      "max_budget_per_epoch", "max_irreversibility",
                      "max_data_sensitivity", "max_delegation_depth",
                      "max_fanout"):
            if field not in tier:
                raise ValueError(
                    "ceiling_curve tier is missing %s; decision "
                    "10 fixes the tier field set, and a tier "
                    "missing a field is a policy error, never a "
                    "silently incomplete ceilings entry "
                    "(Section 16.10 decision 10)" % field)
            _strict_quantity(
                tier[field], "ceiling_curve tier %s" % field)
    return curve


def _unspecified(field, scope_class=None):
    """The prototype's UnspecifiedBySpec error (finding S3)."""
    where = " for scope class %s" % scope_class if scope_class else ""
    return ValueError(
        "UNSPECIFIED_BY_SPEC: standing_policy does not state %s%s; "
        "Section 16.10 requires the policy itself to state it, and "
        "the computation invents no default" % (field, where))


def _diversity_cap(absolute, fraction_ppm, mint_cap_per_epoch):
    """The binding diversity cap for one dimension (decision 8).

    The absolute per-epoch form and the fraction form (a fraction
    of the class mint_cap_per_epoch) are both conforming; where
    both are stated, the smaller binds. A fraction form without a
    mint cap to divide is an unspecified-by-policy error, because
    the denominator is missing.
    """
    cap = absolute
    if fraction_ppm is not None:
        if mint_cap_per_epoch is None:
            raise ValueError(
                "standing_policy states a diversity fraction cap "
                "without a mint_cap_per_epoch for the class; the "
                "denominator is missing (Section 16.10 decision 8)")
        fraction_cap = int(mint_cap_per_epoch) * int(fraction_ppm) // PPM
        cap = fraction_cap if cap is None else min(int(cap), fraction_cap)
    return cap


def _class_policy(standing_policy, scope_class):
    """Parse one class policy, class-locally (decision 24 row (e)).

    Class fields are read from the class object only: a field
    stated at the top level of standing_policy never merges
    into a class (fourth re-audit finding U2; the Rust parser
    has always read class-locally). The fields the decisions
    place at policy level are read there and only there:
    epoch_seconds (decision 3), the policy-level ceiling_curve
    (decision 21, which a class curve overrides), diversity_caps
    (decision 18), countersign_policy (decision 22), and
    witness_policy (decision 15, validated by
    _validate_witness_policy at load).

    No value is defaulted here (finding S3): a field the class
    does not state stays None, and the computation raises
    UNSPECIFIED_BY_SPEC at the exact point it needs the field,
    mirroring institutio-core. The one exception is the severe
    reason code set, which defaults to the codes invariant I5
    names in prose, as institutio-core also defaults it. Every
    stated value passes the strictness table of decision 24:
    integer, non-negative, non-null, spec-named. The retired
    prototype aliases (mint_per_action, burn_per_denial,
    hop_attenuation_percent, correlated_burn_divisor, the flat
    diversity keys, and severe_codes) are not read; the aliases
    the specification itself keeps (half_life, decision 4; a
    bare hop_attenuation of 1, decision 6) are unaffected.
    """
    policy = {
        "mint_rate": None,
        "burn_unit": None,
        "half_life_seconds": None,
        "hop_attenuation_ppm": None,
        "mint_cap_per_epoch": None,
        "epoch_seconds": None,
        "correlated_burn_fraction_ppm": None,
    }
    multipliers = {}
    severe = list(DEFAULT_SEVERE_REASON_CODES)
    countersign_required = _countersign_required_for(
        standing_policy, scope_class)
    curve = None
    policy["diversity"] = {
        "per_counterparty_absolute": None,
        "per_counterparty_fraction_ppm": None,
        "per_task_type_absolute": None,
        "per_task_type_fraction_ppm": None,
        "per_subtree_fraction_ppm": None,
        "per_subtree_absolute": None,
    }
    if standing_policy:
        if not isinstance(standing_policy, dict):
            raise ValueError("standing_policy must be a JSON object")
        if "scope_classes" in standing_policy:
            classes = _stated(
                standing_policy, "scope_classes", "scope_classes")
            if not isinstance(classes, dict):
                # Fourth re-audit observation U6: a list form
                # once crashed here with an AttributeError; it
                # is a policy error a caller can handle as one
                # (Section 16.10 decision 9).
                raise ValueError(
                    "scope_classes must be an object, a map from "
                    "class name to class policy object (Section "
                    "16.10 decision 9); got %r" % (classes,))
        else:
            classes = {}
        per_class = classes.get(scope_class, {})
        if per_class is None:
            raise ValueError(
                "scope class %s is stated as null; a stated null "
                "is a malformed value, never an absent field "
                "(Section 16.10 decision 24)" % scope_class)
        if not isinstance(per_class, dict):
            raise ValueError(
                "scope class %s is not an object" % scope_class)
        if "diversity_caps" in per_class:
            # Section 16.10 decision 18: diversity_caps lives at
            # policy level only. The per-class form is rejected
            # explicitly, never silently honoured here and ignored
            # in the other implementation.
            raise ValueError(
                "diversity_caps inside scope class %s is "
                "non-conforming: Section 16.10 decision 18 places "
                "diversity_caps at the top level of standing_policy "
                "only" % scope_class)
        if "severe_codes" in per_class:
            # Section 16.10 decision 24 row (d): the spec-named
            # field is severe_reason_codes; the severe_codes
            # alias one tree honoured is rejected in both.
            raise ValueError(
                "severe_codes inside scope class %s is not a "
                "conforming field name; the field is "
                "severe_reason_codes (Section 16.10 decision 24)"
                % scope_class)
        # epoch_seconds is a policy-level field (decision 3).
        if "epoch_seconds" in standing_policy:
            policy["epoch_seconds"] = _strict_quantity(
                _stated(standing_policy, "epoch_seconds",
                        "epoch_seconds"),
                "epoch_seconds")
        # The policy-level ceiling curve (decision 21); a class
        # curve below overrides it for this class.
        if "ceiling_curve" in standing_policy:
            curve = _validate_curve(_stated(
                standing_policy, "ceiling_curve", "ceiling_curve"))
        if "ceiling_curve" in per_class:
            curve = _validate_curve(_stated(
                per_class, "ceiling_curve",
                "scope class %s ceiling_curve" % scope_class))
        for key in (
            "mint_rate", "burn_unit", "half_life_seconds",
            "hop_attenuation_ppm", "mint_cap_per_epoch",
            "correlated_burn_fraction_ppm",
        ):
            if key in per_class:
                policy[key] = _strict_quantity(
                    _stated(per_class, key,
                            "scope class %s %s" % (scope_class, key)),
                    key)
        # Half-life alias (Section 16.10 decision 4): a bare
        # half_life is the deprecated v0.1 alias, read as seconds.
        if policy["half_life_seconds"] is None and "half_life" in per_class:
            policy["half_life_seconds"] = _strict_quantity(
                _stated(per_class, "half_life",
                        "scope class %s half_life" % scope_class),
                "half_life")
        # Hop attenuation (Section 16.10 decision 6): the policy
        # field is hop_attenuation_ppm. A bare hop_attenuation is
        # conforming only as the integer 1, read as 1,000,000 ppm.
        if "hop_attenuation_ppm" not in per_class:
            if "hop_attenuation" in per_class:
                bare = per_class["hop_attenuation"]
                if isinstance(bare, int) and not isinstance(
                        bare, bool) and bare == 1:
                    policy["hop_attenuation_ppm"] = PPM
                else:
                    raise ValueError(
                        "bare hop_attenuation is conforming only as "
                        "the integer 1 (Section 16.10 decision 6); "
                        "state hop_attenuation_ppm instead")
        if "burn_multipliers" in per_class:
            stated_multipliers = _stated(
                per_class, "burn_multipliers",
                "scope class %s burn_multipliers" % scope_class)
            if not isinstance(stated_multipliers, dict):
                raise ValueError(
                    "burn_multipliers in scope class %s must be "
                    "an object by reason code" % scope_class)
            multipliers.update(stated_multipliers)
        for code, value in multipliers.items():
            _strict_quantity(
                value, "burn_multipliers[%s]" % code)
        if "severe_reason_codes" in per_class:
            stated_severe = _stated(
                per_class, "severe_reason_codes",
                "scope class %s severe_reason_codes" % scope_class)
            if not isinstance(stated_severe, list) or any(
                    not isinstance(code, str) for code in stated_severe):
                raise ValueError(
                    "severe_reason_codes in scope class %s must "
                    "be an array of reason code strings"
                    % scope_class)
            severe = list(stated_severe)
        if "inheritance_factor_ppm" in standing_policy:
            _strict_quantity(
                _stated(standing_policy, "inheritance_factor_ppm",
                        "inheritance_factor_ppm"),
                "inheritance_factor_ppm")
        # Diversity caps (Section 16.10 decision 8): the
        # diversity_caps object at policy level only; the flat
        # prototype keys are retired (see the docstring note).
        if "diversity_caps" in standing_policy:
            caps = _stated(
                standing_policy, "diversity_caps", "diversity_caps")
            if not isinstance(caps, dict):
                raise ValueError("diversity_caps must be a JSON object")
            for form, key in (
                ("per_counterparty_absolute", "per_counterparty_per_epoch"),
                ("per_counterparty_fraction_ppm",
                 "per_counterparty_fraction_ppm"),
                ("per_task_type_absolute", "per_task_type_per_epoch"),
                ("per_task_type_fraction_ppm", "per_task_type_fraction_ppm"),
                ("per_subtree_fraction_ppm", "per_subtree_fraction_ppm"),
                ("per_subtree_absolute", "per_subtree_per_epoch"),
            ):
                if key in caps:
                    policy["diversity"][form] = _strict_quantity(
                        _stated(caps, key, "diversity_caps %s" % key),
                        "diversity_caps %s" % key)
    policy["burn_multipliers"] = multipliers
    policy["severe_reason_codes"] = severe
    policy["countersign_required"] = countersign_required
    policy["ceiling_curve"] = curve
    return policy


def _parse_policy_eager(standing_policy):
    """Parse a whole policy at load (decision 24 row (e)).

    Every class in scope_classes is parsed, whether or not the
    computation touches it, and the policy-level fields
    (countersign form, witness form and bounds, version) are
    validated, so a malformed value anywhere in the policy is
    an error before any computation. Fourth re-audit finding
    U2: this parse was once lazy and inheriting.
    """
    if standing_policy is None:
        return
    if not isinstance(standing_policy, dict):
        raise ValueError("standing_policy must be a JSON object")
    if "standing_policy_version" in standing_policy:
        version = _stated(
            standing_policy, "standing_policy_version",
            "standing_policy_version")
        if not isinstance(version, str):
            raise ValueError(
                "standing_policy_version must be a string; got %r"
                % (version,))
    if "scope_classes" in standing_policy:
        classes = _stated(
            standing_policy, "scope_classes", "scope_classes")
        if not isinstance(classes, dict):
            raise ValueError(
                "scope_classes must be an object, a map from "
                "class name to class policy object (Section "
                "16.10 decision 9); got %r" % (classes,))
        names = list(classes)
    else:
        names = []
    _validate_witness_policy(standing_policy)
    if standing_policy.get("epoch_seconds") == 0:
        raise ValueError(
            "epoch_seconds must be at least 1 when present "
            "(Section 16.10 decision 3); 0 is an error, never "
            "an absent field")
    # A sentinel parse forces the policy-level fields (epoch,
    # curve, diversity, countersign form) through validation
    # even when no class is stated or touched.
    _class_policy(standing_policy, "\x00eager")
    for name in names:
        _class_policy(standing_policy, name)


def validate_standing_policy(standing_policy):
    """Validate a standing_policy against invariant I5 (audit M3).

    The witness policy is also examined, under decision 15
    and decision 24 row (e) (finding W2). Returns a list of
    error strings. A policy is rejected when, for
    any scope class, the epoch of mint cannot be bounded by
    mint_cap_per_epoch, or when one severe denial at the policy's
    own burn_unit and severe multipliers cannot erase that cap.
    The I5 floor lives here and in the closed form for valid
    policies (Section 16.10 decision 2); compute_standing applies
    no computation-time floor beyond the closed form. This check
    makes the property static and auditable before any computation
    runs.
    """
    errors = []
    if not isinstance(standing_policy, dict):
        return ["standing_policy must be a JSON object"]
    # The witness policy is examined here with the same
    # strictness as at the computation and verification doors
    # (fifth re-audit finding W2): decision 15's form, its
    # quorum bounds, and no k alias. This function is the one
    # charter validation calls, and it once never looked at
    # witness_policy at all, so a charter carrying a quorum of
    # 0 collected no witness error from this door while the
    # Rust charter door reported it. Section 16.10 decision 24
    # row (e) names validation explicitly.
    try:
        _validate_witness_policy(standing_policy)
    except ValueError as exc:
        errors.append(str(exc))
    epoch_seconds = standing_policy.get("epoch_seconds")
    if epoch_seconds is not None and (
            isinstance(epoch_seconds, bool)
            or not isinstance(epoch_seconds, int)
            or epoch_seconds < 1):
        errors.append(
            "standing_policy epoch_seconds must be at least 1 when "
            "present (Section 16.10 decision 3); 0 is an error, "
            "never an absent field")
    classes = standing_policy.get("scope_classes") or {}
    names = sorted(classes) if classes else ["default"]
    for name in names:
        policy = _class_policy(standing_policy, name)
        diversity = policy.get("diversity") or {}
        if policy.get("mint_cap_per_epoch") is None and any(
            diversity.get(key) is not None
            for key in ("per_counterparty_fraction_ppm",
                        "per_task_type_fraction_ppm",
                        "per_subtree_fraction_ppm")
        ):
            errors.append(
                "standing_policy class %s: a diversity fraction cap "
                "is stated without a mint_cap_per_epoch; the "
                "denominator is missing (Section 16.10 decision 8)"
                % name)
        cap = policy.get("mint_cap_per_epoch")
        if cap is None:
            errors.append(
                "standing_policy class %s: mint_cap_per_epoch must be "
                "set, so an epoch of mint is bounded and the I5 burn "
                "floor is checkable" % name)
            continue
        for code in policy["severe_reason_codes"]:
            if policy["burn_unit"] is None:
                errors.append(
                    "standing_policy class %s: burn_unit must be "
                    "stated, so a severe denial's burn is computable "
                    "(Section 16.10 decision 1)" % name)
                continue
            if code not in policy["burn_multipliers"]:
                errors.append(
                    "standing_policy class %s: no burn multiplier "
                    "stated for severe reason code %s (Section "
                    "16.10 decision 1)" % (name, code))
                continue
            burn = int(policy["burn_unit"]) * int(
                policy["burn_multipliers"][code])
            if burn < int(cap):
                errors.append(
                    "standing_policy class %s: one severe denial (%s) "
                    "burns %d, less than the epoch mint cap %d; "
                    "invariant I5 requires a severe incident to erase "
                    "at least an epoch of mint" % (name, code, burn, int(cap)))
    return errors


def _field(receipt, action, name, default=None):
    if name in receipt:
        return receipt[name]
    return action.get(name, default)


def scope_class_of(receipt):
    action = receipt.get("action") or {}
    for source, key in ((receipt, "standing_scope_class"),
                        (action, "scope_class")):
        if key in source:
            value = source[key]
            if not isinstance(value, str):
                # A stated null or non-string scope class is
                # malformed, never a silent fallthrough to the
                # next location (Section 16.10 decision 24).
                raise ValueError(
                    "%s must be a scope class name string, got "
                    "%r (Section 16.10 decision 24)" % (key, value))
            if value:
                return value
    return "default"


def ceilings_for_standing(standing, policy):
    """The ceiling-curve tier a Standing value reaches (Section 16.3).

    The curve is the policy's own (finding S3): a policy without a
    ceiling_curve states no ceilings, and asking for them is an
    UNSPECIFIED_BY_SPEC error, never a default curve.
    """
    curve = policy.get("ceiling_curve")
    if not curve:
        raise _unspecified("ceiling_curve")
    tiers = sorted(curve, key=lambda tier: tier["min_standing"])
    chosen = dict(tiers[0])
    for tier in tiers:
        if standing >= int(tier["min_standing"]):
            chosen = dict(tier)
    chosen.pop("min_standing", None)
    return chosen


def burn_amount_for_denial(policy, reason_code, denial_ordinal):
    """Burn of the n-th denial in a class: the closed form of
    Section 16.10 decision 2, burn_unit * multiplier * n * n.

    No computation-time maximum or floor is applied beyond the
    closed form; the I5 severe floor is a policy-validation
    condition (validate_standing_policy), not an adjustment here.
    Exported so ToolGate can state the burn on the BURN receipt it
    emits with a denial (Section 16.5 step 4).

    Decision 1: a denial whose class states no burn_unit, or no
    multiplier for its reason code, stops here with
    UNSPECIFIED_BY_SPEC rather than inventing either value.
    """
    if policy.get("burn_unit") is None:
        raise _unspecified("burn_unit")
    multipliers = policy.get("burn_multipliers") or {}
    if reason_code not in multipliers:
        raise _unspecified(
            "burn_multipliers[%s]" % (reason_code,))
    multiplier = int(multipliers[reason_code])
    ordinal = int(denial_ordinal)
    return int(policy["burn_unit"]) * multiplier * ordinal * ordinal


class _ClassState:
    def __init__(self):
        self.mint_events = []  # (timestamp, amount) after caps
        self.minted_pre_decay = 0
        self.burned = 0
        self.actions = 0
        self.denials = 0
        self.burn_receipts = 0
        self.burn_recorded = 0
        self.promotions = 0
        self.demotions = 0
        self.killed = False
        self.epoch_mint = {}
        self.epoch_counterparty = {}
        self.epoch_task = {}
        self.epoch_subtree = {}


def _epoch_of(policy, timestamp):
    epoch_seconds = policy["epoch_seconds"]
    if epoch_seconds is None:
        return 0
    epoch_seconds = int(epoch_seconds)
    if epoch_seconds < 1:
        raise ValueError(
            "epoch_seconds must be at least 1 when present "
            "(Section 16.10 decision 3); 0 is an error, never an "
            "absent field")
    return timestamp // epoch_seconds


def _clip(amount, used, cap):
    if cap is None:
        return amount
    return max(0, min(amount, int(cap) - used))


def _killed_agent_ids(receipt):
    """Agent ids a KILL-BURN receipt burns (itself plus its subtree)."""
    ids = receipt.get("killed_agent_ids")
    if isinstance(ids, list) and ids:
        return list(ids)
    return [_agent_id(receipt)]


def compute_standing(receipts, standing_policy=None, eval_time=None,
                     agent_id=None, counterparty_verifiers=None):
    """Compute Standing per scope class. See module docstring.

    receipts: receipt dicts from a verified chain, in chain order.
    standing_policy: the charter standing_policy object, or None.
    eval_time: integer seconds to evaluate decay at; when None, the
    latest receipt timestamp is used, keeping the result a pure
    function of the inputs.
    agent_id: when given, only receipts whose agent.id matches are
    counted, so one firm chain yields a Standing vector per seat.
    A KILL-BURN receipt is also selected when it names this agent
    in its killed_agent_ids (its delegation subtree, invariant I7).
    counterparty_verifiers: map of counterparty_id to a Signer used
    to verify countersignatures where the policy requires them
    (invariant I4, audit finding M2).
    Returns {scope_class: {...}} with sorted scope class keys. An
    agent with no receipts has no entry: a copied or new agent starts
    at zero in every class (invariant I3).

    State is accumulated per (agent, scope class): a firm-wide call
    never lets one seat's kill, burn, or mint touch another seat's
    Standing (audit finding M4). The returned per-class entry sums
    the per-agent entries; with agent_id given it is that agent's
    entry alone.
    """
    # Receipt identity is unique (second re-audit minor s6, and
    # Section 16.10 decision 19): the countersigned descriptor
    # binds receipt_id, so a duplicated id would let one
    # countersignature mint twice on the same descriptor identity.
    # The computation refuses a segment carrying a duplicate, as
    # verify_chain refuses the chain.
    seen_receipt_ids = set()
    for receipt in receipts:
        receipt_id = receipt.get("receipt_id")
        if receipt_id is not None:
            if not isinstance(receipt_id, str):
                # Fourth re-audit T2 residue: a non-string
                # identity (a JSON number, say) is malformed,
                # never silently erased or carried without an
                # identity (Section 16.10 decision 24).
                raise ValueError(
                    "receipt_id must be a string, got %r; a "
                    "non-string receipt identity is a malformed "
                    "receipt, never silently erased (Section "
                    "16.10 decision 24)" % (receipt_id,))
            if receipt_id in seen_receipt_ids:
                raise ValueError(
                    "duplicate receipt_id %r in the segment; "
                    "receipt identities are unique, and a duplicate "
                    "would let one countersignature mint twice on "
                    "the same descriptor identity" % (receipt_id,))
            seen_receipt_ids.add(receipt_id)
    # The segment's acceptance surface (fifth re-audit findings
    # W1, W4, W5): every receipt is shape-checked before any
    # computation, as the Rust prototype parser checks at parse.
    # An unknown receipt type is INVALID_RECEIPT, never tallied
    # as nothing; the agent field must be the agent object; and
    # a stated null or non-string counterparty_id or
    # subtree_root_id is malformed, never read as absence.
    for receipt in receipts:
        _agent_id(receipt)
        kind = receipt.get("receipt_type")
        if kind not in RECEIPT_TYPES:
            raise ValueError(
                "INVALID_RECEIPT: unknown receipt_type %r; an "
                "unknown receipt type is a validation error, "
                "never silently tallied as nothing "
                "(Section 16.10 decision 24)" % (kind,))
        action = receipt.get("action")
        _receipt_text_field(
            receipt, action if isinstance(action, dict) else {},
            "counterparty_id")
        _receipt_text_field(
            receipt, action if isinstance(action, dict) else {},
            "subtree_root_id")
    # Decision 24 row (e): the whole policy is parsed eagerly
    # and class-locally before any computation, including its
    # witness policy (finding S5 residue) and classes this
    # segment never touches (finding U2).
    _parse_policy_eager(standing_policy)
    if eval_time is not None and (
            isinstance(eval_time, bool)
            or not isinstance(eval_time, int) or eval_time < 0):
        raise ValueError(
            "eval_time must be a non-negative integer number of "
            "seconds, got %r (Section 16.10 decision 24)"
            % (eval_time,))
    selected = []
    for receipt in receipts:
        if agent_id is not None:
            if _agent_id(receipt) != agent_id and not (
                receipt.get("receipt_type") == "KILL-BURN"
                and agent_id in _killed_agent_ids(receipt)
            ):
                continue
        selected.append(receipt)
    if eval_time is None:
        eval_time = 0
        for receipt in selected:
            eval_time = max(eval_time, _receipt_timestamp(receipt))

    states = {}
    policies = {}
    killed_agents = set()

    def state_for(agent_key, scope_class):
        key = (agent_key, scope_class)
        if key not in states:
            states[key] = _ClassState()
            policies[scope_class] = _class_policy(standing_policy, scope_class)
            if agent_key in killed_agents:
                states[key].killed = True
        return states[key]

    # The segment's scope classes per agent, computed before any
    # burn is applied: Section 16.10 decision 7 defines the classes
    # correlated with a denial as every other class in which the
    # agent has at least one receipt in the segment, including a
    # class first touched after the denial (re-audit minor r9).
    # States are created for every such pair up front, so a
    # correlated burn lands even in a class whose first receipt
    # comes later in chain order.
    segment_classes = {}
    for receipt in selected:
        agent_key = _agent_id(receipt)
        segment_classes.setdefault(agent_key, set()).add(
            scope_class_of(receipt))
        state_for(agent_key, scope_class_of(receipt))

    for receipt in selected:
        action = receipt.get("action") or {}
        scope_class = scope_class_of(receipt)
        receipt_agent = _agent_id(receipt)
        state = state_for(receipt_agent, scope_class)
        policy = policies[scope_class]
        timestamp = _receipt_timestamp(receipt)
        kind = receipt.get("receipt_type")
        if kind == "ACTION":
            state.actions += 1
            if state.killed or receipt_agent in killed_agents:
                continue
            risk_weight = _field(receipt, action, "risk_weight", 1)
            if isinstance(risk_weight, bool) or not isinstance(risk_weight, int):
                raise ValueError(
                    "risk_weight must be an integer, got %r; a "
                    "non-integer risk weight is a validation error, "
                    "never silently coerced (re-audit minor r3)"
                    % (risk_weight,))
            if risk_weight < 0:
                raise ValueError(
                    "risk_weight must be non-negative, got %r; a "
                    "negative risk weight is a validation error, "
                    "never silently computed as zero mint (third "
                    "re-audit minor t5, repair round 4)"
                    % (risk_weight,))
            depth = _field(receipt, action, "delegation_depth", 0)
            if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
                raise ValueError(
                    "delegation_depth must be a non-negative integer, "
                    "got %r; a negative depth is a validation error, "
                    "never silently treated as depth 0 "
                    "(re-audit minor r3)" % (depth,))
            if policy["mint_rate"] is None:
                raise _unspecified("mint_rate", scope_class)
            amount = int(policy["mint_rate"]) * risk_weight
            if depth > 0:
                if policy["hop_attenuation_ppm"] is None:
                    raise _unspecified(
                        "hop_attenuation_ppm", scope_class)
                ppm = int(policy["hop_attenuation_ppm"])
                if ppm < PPM:
                    amount = amount * (ppm ** depth) // (PPM ** depth)
            counterparty = _receipt_text_field(
                receipt, action, "counterparty_id")
            if counterparty is None:
                counterparty = "none"
            if policy["countersign_required"] and not _countersignature_verifies(
                receipt, action, scope_class, counterparty_verifiers
            ):
                amount = 0
            epoch = _epoch_of(policy, timestamp)
            amount = _clip(amount, state.epoch_mint.get(epoch, 0),
                           policy["mint_cap_per_epoch"])
            diversity = policy["diversity"]
            mint_cap = policy["mint_cap_per_epoch"]
            cp_key = (epoch, str(counterparty))
            amount = _clip(amount, state.epoch_counterparty.get(cp_key, 0),
                           _diversity_cap(
                               diversity["per_counterparty_absolute"],
                               diversity["per_counterparty_fraction_ppm"],
                               mint_cap))
            task_key = (epoch, str(action.get("name", "")))
            amount = _clip(amount, state.epoch_task.get(task_key, 0),
                           _diversity_cap(
                               diversity["per_task_type_absolute"],
                               diversity["per_task_type_fraction_ppm"],
                               mint_cap))
            subtree_root = _receipt_text_field(
                receipt, action, "subtree_root_id")
            if subtree_root is None:
                subtree_root = receipt_agent
            subtree_key = (epoch, str(subtree_root))
            amount = _clip(amount, state.epoch_subtree.get(subtree_key, 0),
                           _diversity_cap(
                               diversity["per_subtree_absolute"],
                               diversity["per_subtree_fraction_ppm"],
                               mint_cap))
            if amount > 0:
                state.epoch_mint[epoch] = state.epoch_mint.get(epoch, 0) + amount
                state.epoch_counterparty[cp_key] = (
                    state.epoch_counterparty.get(cp_key, 0) + amount
                )
                state.epoch_task[task_key] = (
                    state.epoch_task.get(task_key, 0) + amount
                )
                state.epoch_subtree[subtree_key] = (
                    state.epoch_subtree.get(subtree_key, 0) + amount
                )
                state.mint_events.append((timestamp, amount))
                state.minted_pre_decay += amount
        elif kind == "DENIAL":
            state.denials += 1
            reason_code = receipt.get("reason_code")
            amount = burn_amount_for_denial(policy, reason_code, state.denials)
            state.burned += amount
            if reason_code in policy["severe_reason_codes"]:
                # Correlated burn (Section 16.10 decision 7): a
                # policy fraction of the burn lands in every other
                # class the agent has a receipt in, anywhere in the
                # segment. The fraction is required exactly when a
                # correlated class exists to burn.
                correlated_classes = (
                    segment_classes.get(receipt_agent, set()) - {scope_class})
                if correlated_classes:
                    fraction = policy["correlated_burn_fraction_ppm"]
                    if fraction is None:
                        raise ValueError(
                            "standing_policy does not state "
                            "correlated_burn_fraction_ppm, which "
                            "Section 16.10 decision 7 requires when "
                            "a severe denial is processed")
                    correlated = amount * int(fraction) // PPM
                    if correlated:
                        for other_class in sorted(correlated_classes):
                            states[(receipt_agent, other_class)].burned += (
                                correlated)
        elif kind == "BURN":
            state.burn_receipts += 1
            recorded = _field(receipt, action, "burn_amount", 0)
            # A stated null burn_amount is malformed, not zero
            # (Section 16.10 decision 24 row (c)); the isinstance
            # check below rejects it, as it rejects booleans,
            # floats, strings, and negatives.
            if isinstance(recorded, bool) or not isinstance(
                    recorded, int) or recorded < 0:
                raise ValueError(
                    "burn_amount must be a non-negative integer, "
                    "got %r; a negative burn amount is a validation "
                    "error, never tallied and never silently "
                    "dropped (third re-audit minor t5, repair "
                    "round 4)" % (recorded,))
            state.burn_recorded += recorded
        elif kind == "PROMOTION":
            state.promotions += 1
        elif kind == "DEMOTION":
            state.demotions += 1
        elif kind == "KILL-BURN":
            # Invariant I7, audit finding M4: the burn applies to
            # the killed agent and its delegation subtree only,
            # never to unrelated seats sharing the chain.
            for killed_id in _killed_agent_ids(receipt):
                killed_agents.add(killed_id)
                for (other_agent, _cls), each in states.items():
                    if other_agent == killed_id:
                        each.killed = True
                        each.mint_events = []

    per_agent = {}
    for (agent_key, scope_class) in sorted(
            states, key=lambda k: (str(k[0]), k[1])):
        if agent_id is not None and agent_key != agent_id:
            # A KILL-BURN that names this agent creates a state
            # for its own author as a vehicle; that state is not
            # part of this agent's result. Before repair round 3
            # it joined the class entries and flipped the killed
            # aggregate to False on an agent the kill had zeroed
            # (found by the S4 differential case).
            continue
        state = states[(agent_key, scope_class)]
        policy = policies[scope_class]
        minted_decayed = 0
        if state.mint_events:
            if policy["half_life_seconds"] is None:
                raise _unspecified("half_life_seconds", scope_class)
            half_life = int(policy["half_life_seconds"])
            if half_life < 1:
                raise ValueError(
                    "half_life_seconds must be a positive integer "
                    "number of seconds (Section 16.10 decision 4); "
                    "0 states no decay only in a prototype this "
                    "amendment abolished")
            for timestamp, amount in state.mint_events:
                age = max(0, eval_time - timestamp)
                amount >>= age // half_life
                minted_decayed += amount
        if state.killed or agent_key in killed_agents:
            standing = 0
            minted_decayed = 0
        else:
            standing = max(0, minted_decayed - state.burned)
        per_agent.setdefault(scope_class, []).append({
            "standing": standing,
            "actions": state.actions,
            "denials": state.denials,
            "minted": state.minted_pre_decay,
            "minted_decayed": minted_decayed,
            "burned": state.burned,
            "decay_applied": state.minted_pre_decay - minted_decayed
            if not state.killed else state.minted_pre_decay,
            "burn_receipts": state.burn_receipts,
            "burn_recorded": state.burn_recorded,
            "promotions": state.promotions,
            "demotions": state.demotions,
            "killed": state.killed or agent_key in killed_agents,
        })

    result = {}
    for scope_class in sorted(per_agent):
        entries = per_agent[scope_class]
        policy = policies[scope_class]
        standing = sum(e["standing"] for e in entries)
        ceilings = ceilings_for_standing(standing, policy)
        result[scope_class] = {
            "standing": standing,
            # The legacy scalar ceiling is the reached tier's
            # per-action budget ceiling. There is no policy-wide
            # ceiling_max and no default curve (finding S3).
            "ceiling": ceilings["max_budget_per_action"],
            "ceilings": ceilings,
            "actions": sum(e["actions"] for e in entries),
            "denials": sum(e["denials"] for e in entries),
            "minted": sum(e["minted"] for e in entries),
            "minted_decayed": sum(e["minted_decayed"] for e in entries),
            "burned": sum(e["burned"] for e in entries),
            "decay_applied": sum(e["decay_applied"] for e in entries),
            "burn_receipts": sum(e["burn_receipts"] for e in entries),
            "burn_recorded": sum(e["burn_recorded"] for e in entries),
            "promotions": sum(e["promotions"] for e in entries),
            "demotions": sum(e["demotions"] for e in entries),
            "killed": all(e["killed"] for e in entries),
        }
    return result


def effective_authority(grant_limits, manifest_limits, standing_ceilings):
    """Section 16.1: the minimum of grant, manifest and Standing.

    Each input is a dict of numeric limits over shared keys. The
    result carries every key named by any input, at the smallest
    value any input gives it. A key an input does not name does not
    constrain that key.
    """
    result = {}
    for source in (grant_limits, manifest_limits, standing_ceilings):
        for key, value in (source or {}).items():
            value = int(value)
            if key not in result or value < result[key]:
                result[key] = value
    return result


def standing_policy_hash(standing_policy):
    return sha256_hex(canonical_bytes(standing_policy or {}))


def _checkpoint_core(checkpoint):
    """The signed view of a checkpoint (no cosigs, no signature)."""
    return {
        key: value for key, value in checkpoint.items()
        if key not in ("witness_cosigs", "checkpoint_sig", "integrity_hash")
    }


def _checkpoint_integrity(checkpoint):
    """Integrity hash over the checkpoint core (audit M8 residual).

    The core includes the identity fields (agent_id, org_id,
    charter_hash, eval_time), so tampering with any of them, even
    on an unwitnessed and unsigned internal checkpoint, breaks the
    integrity hash and verify_checkpoint rejects the checkpoint.
    An integrity hash is tamper-evidence, not a signature: a party
    who rewrites the whole checkpoint can recompute it, which is
    why external reliance still requires witness cosignatures
    (invariant I8).
    """
    return sha256_hex(canonical_bytes(_checkpoint_core(checkpoint)))


def build_checkpoint(receipts, standing_policy=None, eval_time=None,
                     agent_id=None, org_id=None, charter_hash=None,
                     counterparty_verifiers=None, witness_signers=(),
                     checkpoint_signer=None):
    """A StandingCheckpoint (Section 16.3) recomputed from a chain.

    A checkpoint is a claim about this computation, not an authority.
    witness_signers is a tuple of Signer objects whose cosignatures
    are attached over the checkpoint core (invariant I8);
    checkpoint_signer signs the core as the checkpoint issuer. With
    neither, witness_cosigs is empty and checkpoint_sig is None, and
    the checkpoint is labelled for internal use by its empty quorum.
    verify_checkpoint is the stranger's recompute-or-reject check
    (audit finding M8).
    """
    if eval_time is None:
        eval_time = 0
        for receipt in receipts:
            eval_time = max(eval_time, _receipt_timestamp(receipt))
    standing = compute_standing(
        receipts, standing_policy, eval_time=eval_time, agent_id=agent_id,
        counterparty_verifiers=counterparty_verifiers,
    )
    selected = [
        receipt for receipt in receipts
        if agent_id is None
        or _agent_id(receipt) == agent_id
    ]
    if selected and "receipt_hash" in selected[-1]:
        head = chain_head(selected)
    elif selected:
        # Plain receipt dicts without hashes (unit-level segments):
        # the head is the canonical hash of the last receipt.
        head = sha256_hex(canonical_bytes(selected[-1]))
    else:
        head = GENESIS_HASH
    epoch_seconds = 0
    if standing_policy:
        epoch_seconds = int(standing_policy.get("epoch_seconds", 0) or 0)
    denials_by_reason = {}
    for receipt in selected:
        if receipt.get("receipt_type") == "DENIAL":
            code = receipt.get("reason_code")
            denials_by_reason[code] = denials_by_reason.get(code, 0) + 1
    checkpoint = {
        "agent_id": agent_id,
        "org_id": org_id,
        "charter_hash": charter_hash,
        "standing_policy_hash": standing_policy_hash(standing_policy),
        "receipt_chain_head_hash": head,
        "epoch": eval_time // epoch_seconds if epoch_seconds > 0 else 0,
        "eval_time": eval_time,
        "standing_vector": {
            cls: entry["standing"] for cls, entry in standing.items()
        },
        "ceilings_vector": {
            cls: entry["ceilings"] for cls, entry in standing.items()
        },
        "mint_total": sum(e["minted"] for e in standing.values()),
        "burn_total": sum(e["burned"] for e in standing.values()),
        "decay_applied": sum(e["decay_applied"] for e in standing.values()),
        "denials_by_reason_code": denials_by_reason,
        "witness_cosigs": [],
        "checkpoint_sig": None,
    }
    checkpoint["integrity_hash"] = _checkpoint_integrity(checkpoint)
    core_bytes = canonical_bytes(_checkpoint_core(checkpoint))
    for signer in witness_signers:
        checkpoint["witness_cosigs"].append({
            "key_id": signer.key_id,
            "signature": signer.sign(CHECKPOINT_PAYLOAD_TYPE, core_bytes),
        })
    if checkpoint_signer is not None:
        checkpoint["checkpoint_sig"] = {
            "key_id": checkpoint_signer.key_id,
            "signature": checkpoint_signer.sign(
                CHECKPOINT_PAYLOAD_TYPE, core_bytes),
        }
    return checkpoint


def verify_checkpoint(checkpoint, receipts, standing_policy=None,
                      counterparty_verifiers=None, witness_verifiers=None):
    """Recompute-or-reject verification of a StandingCheckpoint.

    Section 16.7 step 3 and invariant I8 (audit finding M8). Returns
    a list of error strings; an empty list means the checkpoint is
    exactly what recomputation from the named chain produces and
    its witness quorum, where the policy requires one, verifies.

    - Every computed field (standing and ceilings vectors, mint,
      burn and decay totals, denials by reason code, policy hash,
      chain head) must equal the recomputed value; any difference
      rejects the checkpoint.
    - Where standing_policy carries a witness_policy in the
      specification's form {"witness_key_ids": [...], "quorum": k}
      (Section 16.10 decision 15), at least k cosignatures from
      distinct listed witnesses must verify under
      witness_verifiers. Without such a policy, any cosigs
      present are still verified when witness_verifiers is given.
    - A present checkpoint_sig must verify under
      witness_verifiers by its key id.
    """
    errors = []
    if not isinstance(checkpoint, dict):
        return ["checkpoint is not a JSON object"]
    if checkpoint.get("integrity_hash") != _checkpoint_integrity(checkpoint):
        errors.append(
            "checkpoint integrity_hash does not match its fields; "
            "an identity field (agent_id, org_id, charter_hash or "
            "eval_time) or a computed field was altered after the "
            "checkpoint was built")
    if receipts:
        latest = max(_receipt_timestamp(r) for r in receipts)
        eval_time = checkpoint.get("eval_time")
        if not isinstance(eval_time, int) or eval_time < latest:
            errors.append(
                "checkpoint eval_time %r precedes the end of the "
                "chain segment it names (latest receipt at %d); the "
                "evaluation time is not bound to this segment"
                % (eval_time, latest))
    # Recomputation must not be blinded by a malformed witness
    # policy (finding S5 residue): compute_standing now rejects
    # one at entry, so a checkpoint presented under one would
    # raise here instead of returning the form error this
    # function exists to report. Standing does not depend on
    # the witness policy, so recompute without it and let the
    # witness block below state the form error.
    recompute_policy = standing_policy
    if isinstance(standing_policy, dict) and (
            "witness_policy" in standing_policy):
        try:
            _validate_witness_policy(standing_policy)
        except ValueError:
            recompute_policy = {
                key: value for key, value in standing_policy.items()
                if key != "witness_policy"}
    recomputed = build_checkpoint(
        receipts, recompute_policy,
        eval_time=checkpoint.get("eval_time"),
        agent_id=checkpoint.get("agent_id"),
        org_id=checkpoint.get("org_id"),
        charter_hash=checkpoint.get("charter_hash"),
        counterparty_verifiers=counterparty_verifiers,
    )
    for field in (
        "standing_policy_hash", "receipt_chain_head_hash", "epoch",
        "standing_vector", "ceilings_vector", "mint_total",
        "burn_total", "decay_applied", "denials_by_reason_code",
    ):
        if checkpoint.get(field) != recomputed.get(field):
            errors.append(
                "checkpoint %s does not match recomputation: claimed "
                "%r, recomputed %r"
                % (field, checkpoint.get(field), recomputed.get(field)))
    core_bytes = canonical_bytes(_checkpoint_core(checkpoint))
    cosigs = checkpoint.get("witness_cosigs") or []
    witness_policy = (standing_policy or {}).get("witness_policy") or {}
    # Section 16.10 decision 15 fixes the encoding as
    # {witness_key_ids, quorum}. An earlier repair read a
    # "min_cosigs" field the specification never defined, so a
    # specification-form policy enforced no quorum at all (second
    # re-audit finding S5); the quorum is read from "quorum" only.
    # A malformed witness policy is an error, never a lenient
    # parse (third re-audit minor t6, repair round 4): no "k"
    # alias, no missing-quorum default, no string coercion, and
    # the quorum must satisfy decision 15's bounds.
    quorum = 0
    allowed = None
    if witness_policy:
        if not isinstance(witness_policy, dict) or set(
                witness_policy) - {"witness_key_ids", "quorum"}:
            errors.append(
                "witness_policy must be an object of exactly the "
                "form {witness_key_ids, quorum} (Section 16.10 "
                "decision 15); got %r" % (witness_policy,))
            witness_policy = {}
        else:
            allowed = witness_policy.get("witness_key_ids")
            raw_quorum = witness_policy.get("quorum")
            if not isinstance(allowed, list) or any(
                    not isinstance(k, str) for k in allowed):
                errors.append(
                    "witness_policy witness_key_ids must be an "
                    "array of key identifier strings (Section "
                    "16.10 decision 15); got %r" % (allowed,))
                allowed = None
            if isinstance(raw_quorum, bool) or not isinstance(
                    raw_quorum, int):
                errors.append(
                    "witness_policy quorum must be an integer "
                    "(Section 16.10 decision 15); got %r; a string "
                    "quorum is not coerced" % (raw_quorum,))
            elif allowed is not None and not (
                    1 <= raw_quorum <= len(allowed)):
                errors.append(
                    "witness_policy quorum %d is outside 1..=%d "
                    "(Section 16.10 decision 15)"
                    % (raw_quorum, len(allowed)))
            else:
                quorum = raw_quorum
    valid_witnesses = set()
    for cosig in cosigs:
        key_id = cosig.get("key_id")
        if allowed is not None and key_id not in allowed:
            errors.append("witness cosignature from unlisted key %r" % key_id)
            continue
        verifier = (witness_verifiers or {}).get(key_id)
        if verifier is None:
            errors.append("no verifier supplied for witness key %r" % key_id)
            continue
        if verifier.verify(CHECKPOINT_PAYLOAD_TYPE, core_bytes,
                           cosig.get("signature", "")):
            valid_witnesses.add(key_id)
        else:
            errors.append("witness cosignature from %r does not verify"
                          % key_id)
    if len(valid_witnesses) < quorum:
        errors.append(
            "witness quorum not met: %d valid cosignatures, policy "
            "requires %d" % (len(valid_witnesses), quorum))
    checkpoint_sig = checkpoint.get("checkpoint_sig")
    if checkpoint_sig is not None:
        verifier = (witness_verifiers or {}).get(checkpoint_sig.get("key_id"))
        if verifier is None:
            errors.append(
                "no verifier supplied for checkpoint signer key %r"
                % checkpoint_sig.get("key_id"))
        elif not verifier.verify(CHECKPOINT_PAYLOAD_TYPE, core_bytes,
                                 checkpoint_sig.get("signature", "")):
            errors.append("checkpoint signature does not verify")
    return errors


# Specification name, kept as the public entry point.
ComputeStanding = compute_standing
