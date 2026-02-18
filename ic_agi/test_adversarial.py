"""
IC-AGI — Adversarial Crypto Tests
====================================

These tests simulate ATTACKS against the IC-AGI cryptographic primitives
and verify that the defenses hold.

Scenarios:
  1. Forged HMAC token → rejected by worker
  2. Tampered token fields → signature verification fails
  3. Expired token → rejected
  4. Revoked token → rejected
  5. < K shares → reconstruction impossible
  6. Mixed-generation shares → wrong secret
  7. Brute-force single share → reveals nothing
  8. Replay attack (re-use consumed token) → rejected
"""

import sys
import os
import time
import copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ic_agi.audit_log import AuditLog
from ic_agi.threshold_auth import ThresholdAuthorizer
from ic_agi.control_plane import ControlPlane, CapabilityToken
from ic_agi.worker import Worker
from ic_agi.share_manager import ShareManager, Share, PRIME
from ic_agi.ir_definition import build_add_function

PASS = 0
FAIL = 0


def check(label: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {label}")
    else:
        FAIL += 1
        print(f"  ❌ {label}  — {detail}")


def _make_system():
    """Create a full IC-AGI system for testing."""
    audit = AuditLog()
    auth = ThresholdAuthorizer(["a-0", "a-1", "a-2"], threshold=2, audit_log=audit)
    cp = ControlPlane(auth, audit, default_ttl=120, default_budget=5)
    return audit, auth, cp


# ══════════════════════════════════════════════
#  ATTACK 1: Forged HMAC Token
# ══════════════════════════════════════════════
def test_forged_hmac_token():
    """A token with a forged signature is rejected by the worker."""
    print("\n═══ ATTACK 1: Forged HMAC Token ═══")
    audit, auth, cp = _make_system()

    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=60, budget=1)
    token_dict = token.to_dict()

    # Forge the signature
    token_dict["signature"] = "0" * 64  # Fake hex signature
    
    worker = Worker("test-worker", audit, signing_key=cp.signing_key)
    func = build_add_function(1, 1)
    segments = func.segment(1)

    result = worker.execute_segment(segments[0], capability_token=token_dict)
    check("Forged HMAC → execution rejected", not result.success)
    check("Error mentions capability", "capability" in (result.error or "").lower() or "rejected" in (result.error or "").lower())


# ══════════════════════════════════════════════
#  ATTACK 2: Tampered Token Fields
# ══════════════════════════════════════════════
def test_tampered_token_fields():
    """Modifying any signed field invalidates the HMAC."""
    print("\n═══ ATTACK 2: Tampered Token Fields ═══")
    audit, auth, cp = _make_system()

    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=60, budget=1)

    # Tamper with scope (privilege escalation attempt)
    tampered = copy.deepcopy(token)
    tampered.scope = ["compute.basic", "admin.root"]
    check("Tampered scope → sig invalid", not tampered.verify(cp.signing_key))

    # Tamper with budget (unlimited use attempt)
    tampered2 = copy.deepcopy(token)
    tampered2.budget = 999999
    check("Tampered budget → sig invalid", not tampered2.verify(cp.signing_key))

    # Tamper with expires_at (extend life attempt)
    tampered3 = copy.deepcopy(token)
    tampered3.expires_at = time.time() + 999999
    check("Tampered expires_at → sig invalid", not tampered3.verify(cp.signing_key))

    # Tamper with issued_to (impersonation attempt)
    tampered4 = copy.deepcopy(token)
    tampered4.issued_to = "admin-root"
    check("Tampered issued_to → sig invalid", not tampered4.verify(cp.signing_key))

    # Original is still valid
    check("Original token → sig valid", token.verify(cp.signing_key))


# ══════════════════════════════════════════════
#  ATTACK 3: Expired Token
# ══════════════════════════════════════════════
def test_expired_token():
    """An expired token is rejected even with valid signature."""
    print("\n═══ ATTACK 3: Expired Token ═══")
    audit, auth, cp = _make_system()

    # Issue a token that expires immediately
    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=0.001, budget=1)
    time.sleep(0.01)  # Wait for expiry

    check("Token expired", not token.is_valid())
    check("Signature still valid (but token expired)", token.verify(cp.signing_key))

    # Worker should reject
    worker = Worker("test-worker", audit, signing_key=cp.signing_key)
    func = build_add_function(1, 1)
    segments = func.segment(1)
    result = worker.execute_segment(segments[0], capability_token=token.to_dict())
    check("Expired token → execution rejected", not result.success)


# ══════════════════════════════════════════════
#  ATTACK 4: Revoked Token
# ══════════════════════════════════════════════
def test_revoked_token():
    """A revoked token is rejected."""
    print("\n═══ ATTACK 4: Revoked Token ═══")
    audit, auth, cp = _make_system()

    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=60, budget=1)
    check("Token valid before revoke", token.is_valid())

    cp.revoke_token(token.token_id, "Suspected compromise")
    check("Token invalid after revoke", not token.is_valid())

    # Worker should reject
    worker = Worker("test-worker", audit, signing_key=cp.signing_key)
    func = build_add_function(1, 1)
    segments = func.segment(1)
    result = worker.execute_segment(segments[0], capability_token=token.to_dict())
    check("Revoked token → execution rejected", not result.success)


# ══════════════════════════════════════════════
#  ATTACK 5: Insufficient Shares (< K)
# ══════════════════════════════════════════════
def test_insufficient_shares():
    """Attempting reconstruction with < K shares raises PermissionError."""
    print("\n═══ ATTACK 5: Insufficient Shares ═══")
    sm = ShareManager(num_nodes=5, threshold=3)
    sm.split("secret", 42.0)

    # 0 shares — nonexistent key
    try:
        sm.reconstruct("nonexistent_key")
        check("No shares (unknown key) rejected", False, "Should have raised")
    except KeyError:
        check("No shares (unknown key) → KeyError", True)

    # 1 share
    try:
        sm.reconstruct("secret", provided_shares=sm._shares["secret"][:1])
        check("1 share rejected", False, "Should have raised")
    except PermissionError:
        check("1 share → PermissionError", True)

    # 2 shares (K=3)
    try:
        sm.reconstruct("secret", provided_shares=sm._shares["secret"][:2])
        check("2 shares rejected (K=3)", False, "Should have raised")
    except PermissionError:
        check("2 shares → PermissionError (K=3)", True)

    # 3 shares → should work
    result = sm.reconstruct("secret", provided_shares=sm._shares["secret"][:3])
    check("3 shares → correct", abs(result - 42.0) < 1e-9)


# ══════════════════════════════════════════════
#  ATTACK 6: Mixed-Generation Shares
# ══════════════════════════════════════════════
def test_mixed_generation_shares():
    """Combining old + new shares → wrong secret."""
    print("\n═══ ATTACK 6: Mixed-Generation Shares ═══")
    sm = ShareManager(num_nodes=5, threshold=3)
    secret = 500.0
    old_shares = sm.split("gen", secret)
    old_copies = [Share(
        share_id=s.share_id, owner_node=s.owner_node, key=s.key,
        value=s.value, share_index=s.share_index,
        total_shares=s.total_shares, threshold=s.threshold,
        generation=s.generation,
    ) for s in old_shares]

    new_shares = sm.rotate("gen")

    # Mix: 1 old + 2 new
    mixed = [old_copies[0], new_shares[1], new_shares[2]]
    wrong = sm.reconstruct("gen", provided_shares=mixed)
    check("1 old + 2 new → wrong secret",
          abs(wrong - secret) > 1e-3,
          f"DANGER: got {wrong} ≈ {secret}")

    # Mix: 2 old + 1 new
    mixed2 = [old_copies[0], old_copies[1], new_shares[2]]
    wrong2 = sm.reconstruct("gen", provided_shares=mixed2)
    check("2 old + 1 new → wrong secret",
          abs(wrong2 - secret) > 1e-3,
          f"DANGER: got {wrong2} ≈ {secret}")


# ══════════════════════════════════════════════
#  ATTACK 7: Single Share Reveals Nothing
# ══════════════════════════════════════════════
def test_single_share_reveals_nothing():
    """A single share is uniformly random in GF(p) — reveals nothing."""
    print("\n═══ ATTACK 7: Single Share Reveals Nothing ═══")
    sm = ShareManager(num_nodes=5, threshold=3)

    # Split the same secret 100 times, collect share[0]
    secret = 42.0
    first_shares = []
    for _ in range(100):
        shares = sm.split("info", secret)
        first_shares.append(shares[0].value)

    # All first shares should be DIFFERENT (random polynomial coefficients)
    unique = len(set(first_shares))
    check(f"100 splits → {unique} unique first shares (should be 100)", unique == 100)

    # The average should NOT converge to any encoding of 42
    # (if info leaked, the average would be predictable)
    avg = sum(first_shares) / len(first_shares)
    check("Average of shares is NOT the encoded secret",
          abs(avg - (42 * 10**18)) > 10**15,
          f"avg={avg}")


# ══════════════════════════════════════════════
#  ATTACK 8: Replay Attack (Re-use Consumed Token)
# ══════════════════════════════════════════════
def test_replay_consumed_token():
    """A consumed token cannot be re-used."""
    print("\n═══ ATTACK 8: Replay Attack ═══")
    audit, auth, cp = _make_system()

    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=60, budget=1)
    check("Token valid before use", token.is_valid())

    # Consume it
    consumed = token.consume()
    check("First consume succeeds", consumed)
    check("Token invalid after consume (budget=1)", not token.is_valid())

    # Attempt replay
    consumed2 = token.consume()
    check("Second consume fails (replay blocked)", not consumed2)


# ══════════════════════════════════════════════
#  ATTACK 9: Wrong Signing Key
# ══════════════════════════════════════════════
def test_wrong_signing_key():
    """Token signed with key A fails verification with key B."""
    print("\n═══ ATTACK 9: Wrong Signing Key ═══")
    import secrets as sec

    audit, auth, cp = _make_system()
    token = cp.issue_capability("worker-0", ["compute.basic"], ttl_seconds=60, budget=1)

    # Verify with correct key
    check("Correct key → valid", token.verify(cp.signing_key))

    # Verify with wrong key
    wrong_key = sec.token_bytes(32)
    check("Wrong key → invalid", not token.verify(wrong_key))

    # Worker with wrong key rejects
    worker = Worker("rogue-worker", audit, signing_key=wrong_key)
    func = build_add_function(1, 1)
    segments = func.segment(1)
    result = worker.execute_segment(segments[0], capability_token=token.to_dict())
    check("Worker with wrong key → rejects token", not result.success)


# ══════════════════════════════════════════════
#  ATTACK 10: Critical Action Without Approval
# ══════════════════════════════════════════════
def test_critical_without_approval():
    """Critical capabilities require K-of-N threshold approval."""
    print("\n═══ ATTACK 10: Critical Action Without Approval ═══")
    audit, auth, cp = _make_system()

    # No approval → PermissionError
    try:
        cp.issue_capability("worker-0", ["admin.root"], criticality="critical")
        check("Critical without approval rejected", False, "Should have raised")
    except PermissionError:
        check("Critical without approval → PermissionError", True)

    # With unapproved request → PermissionError
    req = auth.create_request("Dangerous action", "attacker", criticality="critical")
    try:
        cp.issue_capability("worker-0", ["admin.root"], criticality="critical",
                           approval_request_id=req.request_id)
        check("Unapproved request rejected", False, "Should have raised")
    except PermissionError:
        check("Unapproved request → PermissionError", True)

    # Approve with K votes → succeeds
    auth.submit_vote(req.request_id, "a-0", vote=True)
    auth.submit_vote(req.request_id, "a-1", vote=True)
    token = cp.issue_capability("worker-0", ["admin.root"], criticality="critical",
                               approval_request_id=req.request_id)
    check("Approved request → token issued", token is not None)
    check("Token has valid signature", token.verify(cp.signing_key))


# ════════════════════════════════════════════════
#  Run all attack tests
# ════════════════════════════════════════════════
if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  IC-AGI — Adversarial Cryptographic Test Suite          ║")
    print("║  Simulating attacks against the security primitives     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    test_forged_hmac_token()
    test_tampered_token_fields()
    test_expired_token()
    test_revoked_token()
    test_insufficient_shares()
    test_mixed_generation_shares()
    test_single_share_reveals_nothing()
    test_replay_consumed_token()
    test_wrong_signing_key()
    test_critical_without_approval()

    print("\n════════════════════════════════════════════════════════════")
    if FAIL == 0:
        print(f"  🛡️  ALL {PASS} ADVERSARIAL CHECKS PASSED")
        print(f"     IC-AGI defenses hold against all simulated attacks")
    else:
        print(f"  ❌  {FAIL} DEFENSE FAILURES out of {PASS + FAIL} checks")
    print("════════════════════════════════════════════════════════════")
    sys.exit(1 if FAIL else 0)
