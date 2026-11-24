"""Tests for the ToolGate prototype. Author: Gavin Blacklock."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acta import HmacSigner, sha256_hex, verify_chain  # noqa: E402
from institutio import countersign_outcome  # noqa: E402
from toolgate import ToolGate  # noqa: E402

SIGNER = HmacSigner(b"unit-test-secret", key_id="gate-key-1")
CP_SIGNER = HmacSigner(b"counterparty-secret", key_id="cp-1")
CP_VERIFIERS = {"cp-1": CP_SIGNER}
FOUNDER = "founder-root-key-1"
WRITE_HASH = sha256_hex(b"tool-definition:write:v1")
AGENT = {"id": "agent-1", "model": "model-x", "model_version": "1.0"}
CHILD_AGENT = {"id": "agent-2", "model": "model-x", "model_version": "1.0"}
# Stated completely (finding S3): no computation default stands
# behind any field Section 16.10 assigns to the policy. The
# ceiling curve is the tier set the prototype once defaulted to,
# now the policy's own.
POLICY = {"countersign_policy": {"required_for": ["write", "default"]},
          "ceiling_curve": [
              {"min_standing": 0, "max_budget_per_action": 5,
               "max_budget_per_epoch": 25, "max_irreversibility": 0,
               "max_data_sensitivity": 0, "max_delegation_depth": 0,
               "max_fanout": 0},
              {"min_standing": 1, "max_budget_per_action": 10,
               "max_budget_per_epoch": 50, "max_irreversibility": 0,
               "max_data_sensitivity": 1, "max_delegation_depth": 0,
               "max_fanout": 1},
              {"min_standing": 10, "max_budget_per_action": 50,
               "max_budget_per_epoch": 250, "max_irreversibility": 1,
               "max_data_sensitivity": 2, "max_delegation_depth": 1,
               "max_fanout": 2},
              {"min_standing": 50, "max_budget_per_action": 250,
               "max_budget_per_epoch": 1000, "max_irreversibility": 2,
               "max_data_sensitivity": 3, "max_delegation_depth": 2,
               "max_fanout": 4},
              {"min_standing": 200, "max_budget_per_action": 1000,
               "max_budget_per_epoch": 5000, "max_irreversibility": 3,
               "max_data_sensitivity": 3, "max_delegation_depth": 3,
               "max_fanout": 8},
          ],
          "scope_classes": {"write": {
              "mint_rate": 2, "mint_cap_per_epoch": 1000000,
              "half_life_seconds": 10000000,
              "hop_attenuation_ppm": 1000000,
              # Per-class placement (decision 7); stated at
              # policy level under the retired merge (round 5).
              "correlated_burn_fraction_ppm": 250000,
              "burn_unit": 5,
              "burn_multipliers": {"revoked": 2, "scope": 2,
                                   "manifest-mismatch": 1, "budget": 1,
                                   "standing-ceiling": 1}},
              # Unregistered tools fall in class "default"; stated
              # explicitly (finding S3).
              "default": {
              "mint_rate": 2, "mint_cap_per_epoch": 1000000,
              "half_life_seconds": 10000000,
              "hop_attenuation_ppm": 1000000,
              "correlated_burn_fraction_ppm": 250000,
              "burn_unit": 5,
              "burn_multipliers": {"revoked": 2, "scope": 2,
                                   "manifest-mismatch": 1, "budget": 1,
                                   "standing-ceiling": 1}}}}


def make_gate():
    gate = ToolGate(SIGNER, standing_policy=POLICY,
                    authorized_key_ids=(FOUNDER,),
                    counterparty_verifiers=CP_VERIFIERS)
    gate.register_tool("repo.write", WRITE_HASH, scope_class="write",
                       risk_weight=3)
    gate.register_tool("repo.read", sha256_hex(b"tool-definition:read:v1"),
                       scope_class="write", risk_weight=1)
    scope = {"tools": ["repo.write", "repo.read"], "resources": ["repo"],
             "operations": ["call"],
             "limits": {"spend_units": 100, "external_calls": 10}}
    gate.add_delegation({"manifest_id": "m-1", "grantor_seat": "founder",
                         "grantee_seat": "worker", "agent": AGENT,
                         "scope": scope})
    gate.add_delegation({"manifest_id": "m-1-child",
                         "grantor_seat": "worker",
                         "grantee_seat": "child", "agent": CHILD_AGENT,
                         "parent_manifest_id": "m-1",
                         "scope": {"tools": ["repo.write"],
                                   "resources": ["repo"],
                                   "operations": ["call"],
                                   "limits": {"spend_units": 50,
                                              "external_calls": 5}}})
    gate.issue_grant("m-1", 1000)
    return gate


def bound_sig(gate, agent_id, when, arguments="args"):
    """A countersignature over the gate's bound outcome descriptor."""
    arguments_hash = sha256_hex(arguments.encode("utf-8"))
    result_hash = sha256_hex(("result:" + arguments_hash).encode("utf-8"))
    return countersign_outcome(
        CP_SIGNER, agent_id, "repo.write", "write", when,
        risk_weight=3, receipt_id=gate.next_receipt_id(),
        arguments_hash=arguments_hash, result_hash=result_hash)


def allow(gate, when=1060, **kwargs):
    kwargs.setdefault("budget_cost", 3)
    kwargs.setdefault("counterparty_id", "cp-1")
    kwargs.setdefault(
        "counterparty_sig", bound_sig(gate, AGENT["id"], when))
    return gate.propose("m-1", "repo.write", WRITE_HASH, "args", when,
                        **kwargs)


class TestToolGate(unittest.TestCase):
    def test_allow_emits_action_and_mints_standing(self):
        gate = make_gate()
        decision = allow(gate)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.receipt["receipt_type"], "ACTION")
        entry = gate.standing_of("agent-1", 1060)["write"]
        self.assertEqual(entry["standing"], 6)  # mint 2 * risk 3

    def test_chain_verifies_after_decisions(self):
        gate = make_gate()
        allow(gate)
        gate.propose("m-1", "repo.write", sha256_hex(b"forged"), "x", 1120)
        result = verify_chain(gate.chain, verifier=SIGNER,
                              expected_key_id="gate-key-1")
        self.assertTrue(result.ok, result.message)

    def test_manifest_mismatch_denied_and_burn_receipted(self):
        gate = make_gate()
        allow(gate)
        decision = gate.propose("m-1", "repo.write",
                                sha256_hex(b"tool-definition:write:v2"),
                                "x", 1120)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "manifest-mismatch")
        self.assertEqual(decision.receipt["reason_code"],
                         "manifest-mismatch")
        self.assertEqual(decision.burn_receipt["receipt_type"], "BURN")
        self.assertEqual(
            decision.burn_receipt["verdict"]["burn_amount"], 5)

    def test_unregistered_tool_is_manifest_mismatch(self):
        gate = make_gate()
        decision = gate.propose("m-1", "repo.delete", WRITE_HASH, "x", 1060)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "manifest-mismatch")

    def test_scope_denial_for_tool_outside_delegation(self):
        gate = make_gate()
        gate.register_tool("admin.exec", sha256_hex(b"tool-definition:admin"),
                           scope_class="write", risk_weight=1)
        decision = gate.propose("m-1", "admin.exec",
                                sha256_hex(b"tool-definition:admin"),
                                "x", 1060)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "scope")

    def test_budget_denial(self):
        gate = make_gate()
        decision = allow(gate, budget_cost=101)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "budget")

    def test_standing_ceiling_denial_for_new_agent(self):
        gate = make_gate()
        # Standing 0 gives an entry ceiling of 5 per action; a call
        # costing 50 fits the manifest budget (100) but not Standing.
        # Budget check runs first only above the manifest cap, so use
        # irreversibility, which only the ceiling constrains.
        decision = gate.propose("m-1", "repo.write", WRITE_HASH, "x",
                                1060, budget_cost=3, irreversibility=3)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "standing-ceiling")
        self.assertIn("recomputed_ceiling", decision.receipt["verdict"])

    def test_revoked_denial_and_child_subtree(self):
        gate = make_gate()
        allow(gate)
        gate.revoke("m-1", 2000, FOUNDER)
        direct = allow(gate, when=2060)
        self.assertFalse(direct.allowed)
        self.assertEqual(direct.reason_code, "revoked")
        child = gate.propose("m-1-child", "repo.write", WRITE_HASH, "x",
                             2120, budget_cost=3)
        self.assertFalse(child.allowed)
        self.assertEqual(child.reason_code, "revoked")

    def test_replay_denied_as_revoked(self):
        gate = make_gate()
        first = allow(gate, authorisation_id="auth-1")
        self.assertTrue(first.allowed)
        replay = allow(gate, when=1120, replay_of="auth-1",
                       authorisation_id="auth-1")
        self.assertFalse(replay.allowed)
        self.assertEqual(replay.reason_code, "revoked")
        self.assertIn("auth-1", replay.receipt["verdict"]["detail"])

    def test_revoke_with_wrong_key_raises_and_emits_nothing(self):
        gate = make_gate()
        before = len(gate.chain)
        with self.assertRaises(PermissionError):
            gate.revoke("m-1", 2000, "rogue-key-9")
        self.assertEqual(len(gate.chain), before)

    def test_kill_burn_zeroes_standing(self):
        gate = make_gate()
        allow(gate)
        self.assertEqual(gate.standing_of("agent-1", 1060)["write"]
                         ["standing"], 6)
        gate.revoke("m-1", 2000, FOUNDER)
        gate.kill_burn("m-1", 2060, FOUNDER)
        entry = gate.standing_of("agent-1", 2060)["write"]
        self.assertEqual(entry["standing"], 0)
        self.assertTrue(entry["killed"])


if __name__ == "__main__":
    unittest.main()
