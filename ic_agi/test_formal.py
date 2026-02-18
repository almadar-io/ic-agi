"""
IC-AGI — Phase 8 Tests: Formal Verification
=============================================

Test suite that runs:
  1. Exhaustive model checker (14 safety properties × all reachable states)
  2. Algebraic Shamir SSS proofs (8 properties × randomized trials)

Total checks:  ≈ 50+  (22 test cases covering 14+8 formal properties)

Run:  python -m pytest ic_agi/test_formal.py -v
"""

import itertools
import pytest

from ic_agi.formal.model_checker import (
    CheckResult,
    DistributedModel,
    DistributedState,
    ThresholdModel,
    ThresholdState,
    TokenModel,
    TokenState,
    check_model,
    run_all_models,
)
from ic_agi.formal.shamir_proofs import (
    proof_a1_reconstruction,
    proof_a2_threshold_necessity,
    proof_a3_information_theoretic,
    proof_a4_rotation_preserves,
    proof_a5_rotation_invalidates,
    proof_a6_share_uniformity,
    proof_a7_lagrange_basis,
    proof_a8_degree_bound,
    run_all_proofs,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION A — Model Checker: Threshold Authorization
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestThresholdModel:
    """Model 1 — P1 through P4."""

    @pytest.fixture(scope="class")
    def result(self) -> CheckResult:
        m = ThresholdModel(approvers=("A", "B", "C"), k=2)
        return check_model(
            "ThresholdAuthorization",
            m.initial_states(), m.successors, m.invariants(),
        )

    def test_states_explored(self, result: CheckResult):
        """Model has non-trivial state space."""
        assert result.states_explored > 10

    def test_all_invariants_hold(self, result: CheckResult):
        """All 4 invariants pass across every state."""
        assert result.all_passed, f"Violations: {result.violations}"

    def test_no_violations(self, result: CheckResult):
        assert result.violations == []

    def test_property_checks_positive(self, result: CheckResult):
        """At least (states × 4) checks were performed."""
        assert result.properties_checked >= result.states_explored * 4

    # ── Direct property checks on hand-crafted states ──

    def test_p1_threshold_safety_manual(self):
        """P1: cannot execute without K approvals."""
        m = ThresholdModel(approvers=("A", "B", "C"), k=2)
        inv = dict(m.invariants())
        # 1 approval, executed → violation
        bad = ThresholdState(votes=(("A", True),), resolved=True,
                             resolution="approved", executed=True)
        assert not inv["P1_ThresholdSafety"](bad)

    def test_p2_no_unilateral_manual(self):
        """P2: single vote cannot approve."""
        m = ThresholdModel(approvers=("A", "B", "C"), k=2)
        inv = dict(m.invariants())
        bad = ThresholdState(votes=(("A", True),), resolved=True,
                             resolution="approved", executed=False)
        assert not inv["P2_NoUnilateralAuthority"](bad)

    def test_p3_denial_finality_manual(self):
        """P3: denied → never executed."""
        m = ThresholdModel(approvers=("A", "B", "C"), k=2)
        inv = dict(m.invariants())
        bad = ThresholdState(votes=(("A", False), ("B", False)),
                             resolved=True, resolution="denied", executed=True)
        assert not inv["P3_DenialFinality"](bad)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION B — Model Checker: Capability Tokens
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTokenModel:
    """Model 2 — P5 through P9."""

    @pytest.fixture(scope="class")
    def result(self) -> CheckResult:
        m = TokenModel(budget=2, ttl=3, max_clock=5)
        return check_model(
            "CapabilityTokens",
            m.initial_states(), m.successors, m.invariants(),
        )

    def test_states_explored(self, result: CheckResult):
        assert result.states_explored > 5

    def test_all_invariants_hold(self, result: CheckResult):
        assert result.all_passed, f"Violations: {result.violations}"

    def test_no_violations(self, result: CheckResult):
        assert result.violations == []

    def test_property_checks_positive(self, result: CheckResult):
        assert result.properties_checked >= result.states_explored * 5

    def test_p5_anti_replay_manual(self):
        """P5: uses cannot exceed budget."""
        m = TokenModel(budget=2, ttl=3, max_clock=5)
        inv = dict(m.invariants())
        bad = TokenState(uses=3, clock=1, revoked=False,
                         signature_valid=True, execution_log=(0, 1, 2))
        assert not inv["P5_AntiReplay"](bad)

    def test_p6_ttl_enforcement_manual(self):
        """P6: no execution at or after TTL."""
        m = TokenModel(budget=2, ttl=3, max_clock=5)
        inv = dict(m.invariants())
        bad = TokenState(uses=1, clock=4, revoked=False,
                         signature_valid=True, execution_log=(3,))
        assert not inv["P6_TTLEnforcement"](bad)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION C — Model Checker: Distributed Execution
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestDistributedModel:
    """Model 3 — P10 through P14."""

    @pytest.fixture(scope="class")
    def result(self) -> CheckResult:
        m = DistributedModel(
            segments=("s1", "s2", "s3"),
            workers=("w1", "w2"),
            k_shares=2,
        )
        return check_model(
            "DistributedExecution",
            m.initial_states(), m.successors, m.invariants(),
        )

    def test_states_explored(self, result: CheckResult):
        assert result.states_explored > 50

    def test_all_invariants_hold(self, result: CheckResult):
        assert result.all_passed, f"Violations: {result.violations}"

    def test_no_violations(self, result: CheckResult):
        assert result.violations == []

    def test_property_checks_positive(self, result: CheckResult):
        assert result.properties_checked >= result.states_explored * 5

    def test_p10_segment_isolation_holds(self):
        """P10: no single worker sees all segments (by construction of 3 segs on 2 workers)."""
        m = DistributedModel(segments=("s1", "s2", "s3"), workers=("w1", "w2"), k_shares=2)
        inv = dict(m.invariants())
        # Worker w1 has all 3 → violation
        wv = m._from_dict({"w1": frozenset(["s1", "s2", "s3"]), "w2": frozenset()})
        bad = DistributedState(
            assignment=m._from_dict({"s1": "w1", "s2": "w1", "s3": "w1"}),
            token_issued=m._from_dict({"s1": True, "s2": True, "s3": True}),
            executed=m._from_dict({"s1": True, "s2": True, "s3": True}),
            circuit_open=m._from_dict({"w1": False, "w2": False}),
            state_integrity=m._from_dict({"s1": "intact", "s2": "intact", "s3": "intact"}),
            worker_view=wv,
            exec_circuit_snapshot=m._from_dict({"s1": False, "s2": False, "s3": False}),
            exec_integrity_snapshot=m._from_dict({"s1": "intact", "s2": "intact", "s3": "intact"}),
        )
        assert not inv["P10_SegmentIsolation"](bad)

    def test_p13_hmac_integrity_manual(self):
        """P13: tampered segment cannot be executed."""
        m = DistributedModel(segments=("s1", "s2", "s3"), workers=("w1", "w2"), k_shares=2)
        inv = dict(m.invariants())
        bad = DistributedState(
            assignment=m._from_dict({"s1": "w1", "s2": None, "s3": None}),
            token_issued=m._from_dict({"s1": True, "s2": False, "s3": False}),
            executed=m._from_dict({"s1": True, "s2": False, "s3": False}),
            circuit_open=m._from_dict({"w1": False, "w2": False}),
            state_integrity=m._from_dict({"s1": "tampered", "s2": "unchecked", "s3": "unchecked"}),
            worker_view=m._from_dict({"w1": frozenset(["s1"]), "w2": frozenset()}),
            exec_circuit_snapshot=m._from_dict({"s1": False, "s2": False, "s3": False}),
            exec_integrity_snapshot=m._from_dict({"s1": "tampered", "s2": "none", "s3": "none"}),
        )
        assert not inv["P13_HMACIntegrity"](bad)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION D — Aggregate Model Check
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestAllModels:
    """Run all three models together."""

    def test_run_all_no_violations(self):
        results = run_all_models(verbose=False)
        for r in results:
            assert r.all_passed, f"{r.model_name}: {r.violations}"

    def test_total_states_reasonable(self):
        results = run_all_models(verbose=False)
        total = sum(r.states_explored for r in results)
        assert total > 100, f"Only {total} states — too few"

    def test_total_checks_large(self):
        results = run_all_models(verbose=False)
        total = sum(r.properties_checked for r in results)
        assert total > 500, f"Only {total} checks — expected many more"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION E — Algebraic Proofs: Shamir SSS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestShamirProofs:
    """A1 through A8 — algebraic property verification."""

    def test_a1_reconstruction(self):
        r = proof_a1_reconstruction(trials=50)
        assert r.passed, r.detail

    def test_a2_threshold_necessity(self):
        r = proof_a2_threshold_necessity(trials=50)
        assert r.passed, r.detail

    def test_a3_information_theoretic(self):
        r = proof_a3_information_theoretic(trials=20)
        assert r.passed, r.detail

    def test_a4_rotation_preserves(self):
        r = proof_a4_rotation_preserves(trials=50)
        assert r.passed, r.detail

    def test_a5_rotation_invalidates(self):
        r = proof_a5_rotation_invalidates(trials=50)
        assert r.passed, r.detail

    def test_a6_share_uniformity(self):
        r = proof_a6_share_uniformity(trials=200)
        assert r.passed, r.detail

    def test_a7_lagrange_basis(self):
        r = proof_a7_lagrange_basis(trials=30)
        assert r.passed, r.detail

    def test_a8_degree_bound(self):
        r = proof_a8_degree_bound(trials=30)
        assert r.passed, r.detail

    def test_all_proofs_pass(self):
        results = run_all_proofs(verbose=False)
        for r in results:
            assert r.passed, f"{r.name}: {r.detail}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECTION F — Cross-cutting: model + algebra
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestFormalVerificationSummary:
    """End-to-end: all 14 model properties + 8 algebraic proofs."""

    def test_complete_formal_verification(self):
        """
        MASTER CHECK — 22 formal properties in total.
        This is the single most important test in the verification suite.
        """
        # Model checker
        model_results = run_all_models(verbose=False)
        for r in model_results:
            assert r.all_passed, f"Model {r.model_name}: {r.violations}"

        # Algebraic proofs
        proof_results = run_all_proofs(verbose=False)
        for p in proof_results:
            assert p.passed, f"Proof {p.name}: {p.detail}"

        # Counts
        total_model_states = sum(r.states_explored for r in model_results)
        total_model_checks = sum(r.properties_checked for r in model_results)
        total_proof_trials = sum(p.trials for p in proof_results)

        assert total_model_states > 100
        assert total_model_checks > 500
        assert total_proof_trials > 200
