"""ToolGate runtime decision path, prototype (specification Section 5
and Section 16.5).

Author: Gavin Blacklock

In-process only: no network, no MCP transport. The gate holds a
pinned tool-manifest set, a set of delegation manifests (charter
scope objects), a charter standing_policy, and its own Acta receipt
chain. Every decision emits receipts into that chain:

- ALLOW emits an ACTION receipt carrying the Standing extensions of
  Section 16.3 (scope class, risk weight computed here from the
  signed manifest, never self-declared by the agent; counterparty
  fields where supplied; delegation depth).
- DENY emits a DENIAL receipt with a reason code from the v0.1 set,
  followed by a BURN receipt stating the Standing that denial burned
  (zero where the denied seat had nothing to burn).

Decision order (Section 16.5, prototype form):
1. Manifest pin: the tool must be registered and the presented
   definition hash must equal the pinned hash, else manifest-mismatch.
2. Delegation and scope: the delegation must exist, belong to the
   acting agent, and grant the tool, the resource, and the
   operation, and must be inside its issued_at to expires_at
   window at the call time, else scope (audit finding M7).
3. Revocation: revocation state is read from the receipt chain
   itself (REVOCATION receipts). A delegation whose own manifest, or
   any ancestor manifest, is revoked is dead, else revoked. A replay
   of an authorisation already consumed by an ACTION receipt is also
   denied as revoked: the authorisation no longer stands.
4. Budget: cumulative spend under the delegation plus this call must
   stay within the delegation's spend_units limit, and the count of
   actions already taken under the delegation plus this call must
   stay within its external_calls limit, else budget (re-audit
   finding M7: the external_calls dimension was recorded but never
   enforced).
5. Standing: the seat's Standing is recomputed from the chain and
   the call must fit the ceiling curve (budget per action, budget
   per epoch, irreversibility, data sensitivity), else
   standing-ceiling, with the recomputed ceiling carried on the
   denial receipt. For a call travelling through a sub-delegation,
   its delegation depth and the fanout of the delegation that
   granted it are also checked against the granting (parent) seat's
   own Standing ceilings, not only the root grantor's (re-audit
   finding M7). The gate fails closed: Standing here is always
   recomputed, never cached.

The scope string recorded on every receipt carries every dimension
of the granted scope, limits included, byte-identical to the scope
the gate enforces (Section 3.3, audit finding M5).

Where the standing policy requires a counterparty countersignature,
the gate verifies the presented signature against the
counterparty's key (counterparty_verifiers) before recording it.
The countersignature is verified over the bound outcome descriptor
(receipt id, arguments hash, result hash, and risk weight included;
re-audit finding M2), so a signature made for one receipt cannot
be replayed onto another. A countersignature is recorded only when
a verifier is configured for the counterparty and the signature
verifies; in every other case it is not recorded at all (re-audit
minor r10), and Standing mints zero for that action on
recomputation where the policy requires a countersignature.

Delegation manifests arrive as in-process dicts. A manifest may
carry a signature (manifest_signer_key_id and manifest_sig, over
the canonical manifest payload under DELEGATION_PAYLOAD_TYPE);
when the gate is constructed with delegation_verifiers, a carried
signature is verified and a bad one is rejected at registration,
and with require_signed_delegations=True an unsigned manifest is
rejected. Without those options the gate still trusts its
in-process caller for manifest contents: that is a stated
prototype limitation, recorded in the README (re-audit finding M7).

Revocation and the kill burn are founder acts: revoke and kill_burn
require a key id in authorized_key_ids (the charter kill switch set)
and raise PermissionError otherwise. A revocation names the
delegation-manifest id and is effective at its receipt sequence
number (ticket T1). kill_burn additionally emits the KILL-BURN
receipt of Section 16.6, which zeroes the seat's Standing in the
computation itself, so post-kill attempts fail on Standing even
apart from revocation.
"""

import copy

from acta.canonical import canonical_bytes, sha256_hex
from acta.receipts import GENESIS_HASH, build_receipt, chain_head
from institutio.standing import (
    burn_amount_for_denial,
    ceilings_for_standing,
    compute_standing,
    counterparty_outcome_bytes,
    COUNTERPARTY_PAYLOAD_TYPE,
    _class_policy,
)

DELEGATION_PAYLOAD_TYPE = "application/vnd.toolgate.delegation.v0.1+json"


def delegation_payload_bytes(manifest):
    """The exact bytes a delegation manifest signature covers."""
    payload = {
        key: value for key, value in manifest.items()
        if key not in ("manifest_sig", "manifest_signer_key_id")
    }
    return canonical_bytes(payload)


def sign_delegation(signer, manifest):
    """Return a copy of the manifest carrying signer's signature."""
    signed = copy.deepcopy(manifest)
    signed.pop("manifest_sig", None)
    signed["manifest_signer_key_id"] = signer.key_id
    signed["manifest_sig"] = signer.sign(
        DELEGATION_PAYLOAD_TYPE, delegation_payload_bytes(signed))
    return signed


class Decision:
    """One gate decision and the receipts it emitted."""

    def __init__(self, allowed, reason_code, receipt, burn_receipt=None):
        self.allowed = allowed
        self.reason_code = reason_code
        self.receipt = receipt
        self.burn_receipt = burn_receipt

    def __repr__(self):
        if self.allowed:
            return "Decision(ALLOW, receipt=%s)" % self.receipt["receipt_id"]
        return "Decision(DENY %s, receipt=%s)" % (
            self.reason_code, self.receipt["receipt_id"])


class ToolGate:
    def __init__(self, signer, standing_policy=None, authorized_key_ids=(),
                 counterparty_verifiers=None, delegation_verifiers=None,
                 require_signed_delegations=False):
        self.signer = signer
        self.standing_policy = standing_policy or {}
        self.authorized_key_ids = set(authorized_key_ids)
        self.counterparty_verifiers = counterparty_verifiers or {}
        self.delegation_verifiers = delegation_verifiers or {}
        self.require_signed_delegations = bool(require_signed_delegations)
        self.tools = {}
        self.delegations = {}
        self.chain = []

    def next_receipt_id(self):
        """The receipt id the next appended receipt will carry.

        Countersigners need it before the call: the outcome
        descriptor binds the receipt identity (re-audit M2), and
        the gate's ids are a deterministic function of chain
        length, so the id is knowable in advance.
        """
        return "g-%04d" % len(self.chain)

    # ---------------------------------------------------------- setup
    def register_tool(self, name, definition_hash, scope_class="default",
                      risk_weight=1):
        """Pin a tool definition. Only this hash will ever be served."""
        self.tools[name] = {
            "definition_hash": definition_hash,
            "scope_class": scope_class,
            "risk_weight": int(risk_weight),
        }

    def add_delegation(self, manifest):
        """Register a delegation manifest (charter scope object).

        manifest keys: manifest_id, grantor_seat, grantee_seat,
        agent (dict with id, model, model_version), scope (charter
        scope object), parent_manifest_id (optional). A manifest
        may carry manifest_signer_key_id and manifest_sig (see
        sign_delegation): when this gate has delegation_verifiers,
        a carried signature must verify under the named key, and
        when require_signed_delegations is set an unsigned manifest
        is refused (re-audit finding M7).
        """
        for key in ("manifest_id", "grantor_seat", "grantee_seat",
                    "agent", "scope"):
            if key not in manifest:
                raise ValueError("delegation manifest missing %r" % key)
        signature = manifest.get("manifest_sig")
        if signature is not None:
            key_id = manifest.get("manifest_signer_key_id")
            verifier = self.delegation_verifiers.get(key_id)
            if verifier is None:
                raise ValueError(
                    "delegation %s carries a signature from key %r, "
                    "for which this gate has no verifier"
                    % (manifest["manifest_id"], key_id))
            if not verifier.verify(
                    DELEGATION_PAYLOAD_TYPE,
                    delegation_payload_bytes(manifest), signature):
                raise ValueError(
                    "delegation %s signature does not verify under "
                    "key %r" % (manifest["manifest_id"], key_id))
        elif self.require_signed_delegations:
            raise ValueError(
                "delegation %s is unsigned and this gate requires "
                "signed delegations" % manifest["manifest_id"])
        self.delegations[manifest["manifest_id"]] = copy.deepcopy(manifest)

    # ------------------------------------------------------- receipts
    def _scope_string(self, manifest):
        scope = manifest["scope"]
        limits = scope.get("limits", {})
        limits_part = ",".join(
            "%s=%s" % (name, limits[name]) for name in sorted(limits))
        return "tools=[%s];resources=[%s];ops=[%s];limits={%s}" % (
            ",".join(scope.get("tools", [])),
            ",".join(scope.get("resources", [])),
            ",".join(scope.get("operations", [])),
            limits_part,
        )

    def _append(self, receipt_type, manifest, action_name, arguments_hash,
                result_hash, timestamp, reason_code=None, verdict=None,
                action_extra=None, receipt_extra=None):
        sequence = len(self.chain)
        prior = chain_head(self.chain) if self.chain else GENESIS_HASH
        receipt = build_receipt(
            self.signer,
            "g-%04d" % sequence,
            receipt_type,
            sequence,
            int(timestamp),
            manifest["grantor_seat"],
            manifest["agent"],
            self._scope_string(manifest),
            action_name,
            arguments_hash,
            result_hash,
            prior,
            reason_code=reason_code,
            verdict=verdict,
            action_extra=action_extra,
            receipt_extra=receipt_extra,
        )
        self.chain.append(receipt)
        return receipt

    def issue_grant(self, manifest_id, timestamp):
        manifest = self.delegations[manifest_id]
        return self._append(
            "GRANT", manifest, "grant.delegate",
            sha256_hex(("grant:" + manifest_id).encode("utf-8")),
            sha256_hex(b"grant-issued"), timestamp,
            receipt_extra={"delegation_manifest_id": manifest_id},
        )

    # ----------------------------------------------------- revocation
    def revoked_manifest_ids(self):
        """Revocation state, read from the receipt chain itself."""
        revoked = set()
        for receipt in self.chain:
            if receipt.get("receipt_type") == "REVOCATION":
                revoked.add(receipt.get("revoked_manifest_id"))
        return revoked

    def _delegation_revoked(self, manifest_id):
        revoked = self.revoked_manifest_ids()
        seen = set()
        current = manifest_id
        while current is not None and current not in seen:
            if current in revoked:
                return True
            seen.add(current)
            manifest = self.delegations.get(current) or {}
            current = manifest.get("parent_manifest_id")
        return False

    def _require_authorized(self, key_id, act):
        if self.authorized_key_ids and key_id not in self.authorized_key_ids:
            raise PermissionError(
                "%s attempted with key %r, which the charter does not "
                "authorize for this act" % (act, key_id)
            )

    def revoke(self, manifest_id, timestamp, revoker_key_id):
        """Revoke a delegation, effective at this receipt's sequence."""
        self._require_authorized(revoker_key_id, "revocation")
        manifest = self.delegations[manifest_id]
        return self._append(
            "REVOCATION", manifest, "delegation.revoke",
            sha256_hex(("revoke:" + manifest_id).encode("utf-8")),
            sha256_hex(b"revoked"), timestamp,
            verdict={"decision": "revoke", "manifest_id": manifest_id},
            receipt_extra={
                "revoked_manifest_id": manifest_id,
                "revoked_by_key_id": revoker_key_id,
            },
        )

    def kill_burn(self, manifest_id, timestamp, revoker_key_id):
        """Emit the KILL-BURN receipt of Section 16.6 for a delegation.

        Records the seat's pre-kill Standing vector so a stranger can
        recompute both sides of the burn from the same chain.
        """
        self._require_authorized(revoker_key_id, "kill burn")
        manifest = self.delegations[manifest_id]
        agent_id = manifest["agent"]["id"]
        pre = compute_standing(
            self.chain, self.standing_policy,
            eval_time=int(timestamp), agent_id=agent_id,
            counterparty_verifiers=self.counterparty_verifiers,
        )
        return self._append(
            "KILL-BURN", manifest, "standing.kill_burn",
            sha256_hex(("kill-burn:" + manifest_id).encode("utf-8")),
            sha256_hex(b"standing-burned-to-zero"), timestamp,
            verdict={
                "decision": "kill-burn",
                "manifest_id": manifest_id,
                "pre_kill_standing": {
                    cls: entry["standing"] for cls, entry in pre.items()
                },
                "post_kill_standing": {
                    cls: 0 for cls in pre
                },
            },
            receipt_extra={
                "delegation_manifest_id": manifest_id,
                "killed_agent_ids": self._subtree_agent_ids(manifest_id),
            },
        )

    def _subtree_agent_ids(self, manifest_id):
        """Agent ids of a delegation and every descendant delegation."""
        ids = []
        frontier = [manifest_id]
        seen = set()
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            manifest = self.delegations.get(current)
            if manifest is None:
                continue
            ids.append(manifest["agent"]["id"])
            for child_id, child in self.delegations.items():
                if child.get("parent_manifest_id") == current:
                    frontier.append(child_id)
        return ids

    # -------------------------------------------------------- helpers
    def _used_authorisations(self):
        used = set()
        for receipt in self.chain:
            if receipt.get("receipt_type") == "ACTION":
                used.add(receipt["receipt_id"])
                auth = (receipt.get("action") or {}).get("authorisation_id")
                if auth:
                    used.add(auth)
        return used

    def _spent_under(self, manifest_id):
        total = 0
        for receipt in self.chain:
            if receipt.get("receipt_type") != "ACTION":
                continue
            if receipt.get("delegation_manifest_id") != manifest_id:
                continue
            total += int((receipt.get("action") or {}).get("budget_cost", 0))
        return total

    def _delegation_depth(self, manifest_id):
        depth = 0
        seen = set()
        current = self.delegations.get(manifest_id) or {}
        while current.get("parent_manifest_id") and current["parent_manifest_id"] not in seen:
            seen.add(current["parent_manifest_id"])
            depth += 1
            current = self.delegations.get(current["parent_manifest_id"]) or {}
        return depth

    def standing_of(self, agent_id, timestamp):
        return compute_standing(
            self.chain, self.standing_policy,
            eval_time=int(timestamp), agent_id=agent_id,
            counterparty_verifiers=self.counterparty_verifiers,
        )

    def _spent_in_epoch(self, manifest_id, timestamp):
        epoch_seconds = int(self.standing_policy.get("epoch_seconds", 0) or 0)
        total = 0
        for receipt in self.chain:
            if receipt.get("receipt_type") != "ACTION":
                continue
            if receipt.get("delegation_manifest_id") != manifest_id:
                continue
            when = int(receipt.get("timestamp", 0))
            if epoch_seconds > 0 and when // epoch_seconds != int(timestamp) // epoch_seconds:
                continue
            total += int((receipt.get("action") or {}).get("budget_cost", 0))
        return total

    # ------------------------------------------------------- decision
    def propose(self, manifest_id, tool, definition_hash, arguments,
                timestamp, budget_cost=0, irreversibility=0,
                data_sensitivity=0, counterparty_id=None,
                counterparty_sig=None, replay_of=None,
                authorisation_id=None, resource="repo", operation="call"):
        """Decide one proposed tool call. Always emits receipts."""
        if isinstance(arguments, str):
            arguments = arguments.encode("utf-8")
        arguments_hash = sha256_hex(arguments)
        manifest = self.delegations.get(manifest_id)
        if manifest is None:
            raise ValueError("unknown delegation manifest %r" % manifest_id)
        tool_info = self.tools.get(tool)
        scope_class = tool_info["scope_class"] if tool_info else "default"
        agent_id = manifest["agent"]["id"]

        def deny(reason_code, detail, extra_verdict=None):
            before = self.standing_of(agent_id, timestamp).get(
                scope_class, {"standing": 0})
            verdict = {"decision": "deny", "reason_code": reason_code,
                       "detail": detail}
            if extra_verdict:
                verdict.update(extra_verdict)
            receipt = self._append(
                "DENIAL", manifest, tool, arguments_hash,
                sha256_hex(b""), timestamp,
                reason_code=reason_code, verdict=verdict,
                action_extra={"scope_class": scope_class},
                receipt_extra={"delegation_manifest_id": manifest_id},
            )
            after = self.standing_of(agent_id, timestamp).get(
                scope_class, {"standing": 0})
            policy = _class_policy(self.standing_policy, scope_class)
            ordinal = after.get("denials", 0)
            nominal = burn_amount_for_denial(policy, reason_code, ordinal)
            burn_receipt = self._append(
                "BURN", manifest, "standing.burn",
                arguments_hash, sha256_hex(b"burn-applied"), timestamp,
                verdict={
                    "decision": "burn",
                    "reason_code": reason_code,
                    "burn_amount": int(before["standing"] - after["standing"]),
                    "nominal_burn": nominal,
                    "pre_burn_standing": before["standing"],
                    "post_burn_standing": after["standing"],
                },
                action_extra={"scope_class": scope_class,
                              "burn_amount": int(before["standing"]
                                                 - after["standing"])},
                receipt_extra={"delegation_manifest_id": manifest_id,
                               "related_receipt_id": receipt["receipt_id"]},
            )
            return Decision(False, reason_code, receipt, burn_receipt)

        # 1. Manifest pinning.
        if tool_info is None:
            return deny("manifest-mismatch",
                        "tool %r is not in the pinned manifest set" % tool)
        if definition_hash != tool_info["definition_hash"]:
            return deny(
                "manifest-mismatch",
                "tool %r definition hash %s differs from the pinned "
                "manifest hash %s" % (tool, definition_hash,
                                      tool_info["definition_hash"]),
            )
        # 2. Delegation scope: tool, resource, operation, and the
        # delegation's validity window (audit finding M7).
        if tool not in manifest["scope"].get("tools", []):
            return deny("scope",
                        "delegation %s does not grant tool %r"
                        % (manifest_id, tool))
        if resource not in manifest["scope"].get("resources", []):
            return deny("scope",
                        "delegation %s does not grant resource %r"
                        % (manifest_id, resource))
        if operation not in manifest["scope"].get("operations", []):
            return deny("scope",
                        "delegation %s does not grant operation %r"
                        % (manifest_id, operation))
        issued_at = manifest.get("issued_at")
        expires_at = manifest.get("expires_at")
        if issued_at is not None and int(timestamp) < int(issued_at):
            return deny("scope",
                        "delegation %s is not yet in force at %d "
                        "(issued_at %d)" % (manifest_id, int(timestamp),
                                            int(issued_at)))
        if expires_at is not None and int(timestamp) >= int(expires_at):
            return deny("scope",
                        "delegation %s expired at %d; the call is at "
                        "%d" % (manifest_id, int(expires_at),
                                int(timestamp)))
        # 3. Revocation and replay, from the chain itself. A replay is
        # named as a replay even when the delegation is also revoked:
        # both grounds are recorded on the one denial receipt.
        revoked = self._delegation_revoked(manifest_id)
        if replay_of is not None and replay_of in self._used_authorisations():
            extra = {"replayed_authorisation": replay_of}
            if revoked:
                extra["standing_ceiling"] = 0
                extra["independent_grounds"] = ["revoked",
                                                "standing-ceiling"]
            return deny("revoked",
                        "authorisation %r was already consumed by an "
                        "earlier ACTION receipt; a replay holds no "
                        "standing authority" % replay_of, extra)
        if revoked:
            return deny("revoked",
                        "delegation %s, or an ancestor of it, is revoked "
                        "in the receipt chain" % manifest_id,
                        {"standing_ceiling": 0,
                         "independent_grounds": ["revoked",
                                                 "standing-ceiling"]})
        # 4. Budget: cumulative spend, and the external_calls count
        # (re-audit finding M7: every allowed action under a
        # delegation is one external call against its limit).
        limits = manifest["scope"].get("limits", {})
        spend_cap = limits.get("spend_units")
        if spend_cap is not None and (
            self._spent_under(manifest_id) + int(budget_cost) > int(spend_cap)
        ):
            return deny("budget",
                        "cumulative spend under %s plus %d exceeds the "
                        "spend_units limit %d"
                        % (manifest_id, int(budget_cost), int(spend_cap)))
        calls_cap = limits.get("external_calls")
        if calls_cap is not None:
            calls_used = sum(
                1 for receipt in self.chain
                if receipt.get("receipt_type") == "ACTION"
                and receipt.get("delegation_manifest_id") == manifest_id)
            if calls_used + 1 > int(calls_cap):
                return deny("budget",
                            "external_calls under %s: %d already taken, "
                            "this call exceeds the limit %d"
                            % (manifest_id, calls_used, int(calls_cap)))
        # 5. Standing ceiling.
        entry = self.standing_of(agent_id, timestamp).get(scope_class)
        if entry is None:
            ceilings = ceilings_for_standing(
                0, _class_policy(self.standing_policy, scope_class))
            standing_value = 0
        else:
            ceilings = entry["ceilings"]
            standing_value = entry["standing"]
        epoch_spent = self._spent_in_epoch(manifest_id, timestamp)
        if (
            int(budget_cost) > int(ceilings["max_budget_per_action"])
            or epoch_spent + int(budget_cost) > int(ceilings["max_budget_per_epoch"])
            or int(irreversibility) > int(ceilings["max_irreversibility"])
            or int(data_sensitivity) > int(ceilings["max_data_sensitivity"])
        ):
            return deny(
                "standing-ceiling",
                "call exceeds the Standing ceiling for class %s: "
                "standing %d gives budget per action %d, budget per "
                "epoch %d (already spent %d this epoch), "
                "irreversibility %d, data sensitivity %d"
                % (scope_class, standing_value,
                   ceilings["max_budget_per_action"],
                   ceilings["max_budget_per_epoch"], epoch_spent,
                   ceilings["max_irreversibility"],
                   ceilings["max_data_sensitivity"]),
                {"standing": standing_value,
                 "recomputed_ceiling": ceilings},
            )
        # 5b. Depth and fanout for calls travelling through a
        # sub-delegation, checked against the granting (parent)
        # seat's own Standing ceilings: the seat that delegated is
        # the seat whose ceilings bound the delegation, not only
        # the root grantor at the top of the chain (re-audit
        # finding M7).
        depth = self._delegation_depth(manifest_id)
        if depth > 0:
            parent_id = manifest.get("parent_manifest_id")
            parent_agent = self.delegations[parent_id]["agent"]["id"]
            parent_entry = self.standing_of(parent_agent, timestamp).get(
                scope_class)
            parent_ceilings = (
                parent_entry["ceilings"] if parent_entry is not None
                else ceilings_for_standing(
                    0, _class_policy(self.standing_policy, scope_class)))
            parent_standing = (
                parent_entry["standing"] if parent_entry is not None else 0)
            fanout = sum(
                1 for child in self.delegations.values()
                if child.get("parent_manifest_id") == parent_id)
            if (
                depth > int(parent_ceilings["max_delegation_depth"])
                or fanout > int(parent_ceilings["max_fanout"])
            ):
                return deny(
                    "standing-ceiling",
                    "sub-delegated call exceeds the granting seat's "
                    "Standing ceilings for class %s: delegation depth "
                    "%d against %d, fanout %d against %d"
                    % (scope_class, depth,
                       parent_ceilings["max_delegation_depth"], fanout,
                       parent_ceilings["max_fanout"]),
                    {"standing": parent_standing,
                     "recomputed_ceiling": parent_ceilings},
                )
        # Allow.
        action_extra = {
            "scope_class": scope_class,
            "risk_weight": tool_info["risk_weight"],
            "budget_cost": int(budget_cost),
            "irreversibility": int(irreversibility),
            "delegation_depth": self._delegation_depth(manifest_id),
        }
        if authorisation_id is not None:
            action_extra["authorisation_id"] = authorisation_id
        receipt_extra = {"delegation_manifest_id": manifest_id}
        if counterparty_id is not None:
            receipt_extra["counterparty_id"] = counterparty_id
        if counterparty_sig is not None:
            # Audit finding M2, re-audit findings M2 and r10:
            # record a countersignature only when a verifier is
            # configured for the counterparty and the signature
            # verifies over the bound outcome descriptor, which
            # names this receipt (the id the gate is about to
            # assign), the arguments and result hashes, and the
            # risk weight the gate computed from the signed
            # manifest. A signature over any other descriptor, or
            # one no verifier can check, is not recorded at all.
            result_hash = sha256_hex(
                ("result:" + arguments_hash).encode("utf-8"))
            verifier = self.counterparty_verifiers.get(counterparty_id)
            if verifier is not None and verifier.verify(
                COUNTERPARTY_PAYLOAD_TYPE,
                counterparty_outcome_bytes(
                    agent_id, tool, scope_class, int(timestamp),
                    risk_weight=tool_info["risk_weight"],
                    receipt_id=self.next_receipt_id(),
                    arguments_hash=arguments_hash,
                    result_hash=result_hash),
                counterparty_sig,
            ):
                receipt_extra["counterparty_sig"] = counterparty_sig
        receipt = self._append(
            "ACTION", manifest, tool, arguments_hash,
            sha256_hex(("result:" + arguments_hash).encode("utf-8")),
            timestamp, action_extra=action_extra,
            receipt_extra=receipt_extra,
        )
        return Decision(True, None, receipt)
