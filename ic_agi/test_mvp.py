#!/usr/bin/env python3
"""
IC-AGI — MVP Test Script
==========================

Demonstrates the full IC-AGI distributed execution pipeline:

  1. Build a trivial IR function (add two numbers).
  2. Split state into distributed shares.
  3. Issue capability tokens (TTL, scope, budget).
  4. Require K-of-N threshold approval for critical actions.
  5. Execute the function through distributed workers.
  6. Log all actions in an append-only audit trail.
  7. Verify audit trail integrity.

This script is the canonical end-to-end test for the IC-AGI MVP.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ic_agi.ir_definition import IRFunction, IRInstruction, IROpCode, build_add_function
from ic_agi.share_manager import ShareManager
from ic_agi.audit_log import AuditLog
from ic_agi.threshold_auth import ThresholdAuthorizer
from ic_agi.control_plane import ControlPlane
from ic_agi.worker import Worker
from ic_agi.scheduler import Scheduler


def separator(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def test_ir_definition():
    """Test 1: Build and inspect an IR function."""
    separator("TEST 1: IR Definition — Build 'add(3, 7)'")
    
    fn = build_add_function(3, 7)
    print(f"Function ID:    {fn.function_id}")
    print(f"Function Name:  {fn.name}")
    print(f"Capabilities:   {fn.required_capabilities}")
    print(f"Criticality:    {fn.criticality}")
    print(f"Instructions:   {len(fn.instructions)}")
    for i, instr in enumerate(fn.instructions):
        print(f"  [{i}] {instr}")
    
    # Test segmentation
    segments = fn.segment(2)
    print(f"\nSegmented into {len(segments)} segments:")
    for seg in segments:
        print(f"  Segment {seg.segment_index}: {len(seg.instructions)} instructions")
        for instr in seg.instructions:
            print(f"    {instr}")
    
    print("\n✅ IR Definition test PASSED")
    return fn


def test_share_manager():
    """Test 2: Distribute state into shares and reconstruct."""
    separator("TEST 2: Share Manager — Split & Reconstruct")
    
    sm = ShareManager(num_nodes=3, threshold=2)
    
    # Split a value
    value = 42.0
    print(f"Original value: {value}")
    shares = sm.split("secret_value", value)
    
    print(f"\nDistributed into {len(shares)} shares:")
    for s in shares:
        print(f"  Node {s.owner_node}: share_value = {s.value:.6f}")
    
    # Reconstruct
    reconstructed = sm.reconstruct("secret_value")
    print(f"\nReconstructed value: {reconstructed:.6f}")
    assert abs(reconstructed - value) < 1e-9, "Reconstruction failed!"
    print("✅ Reconstruction matches original")
    
    # Test insufficient shares
    print("\nTesting insufficient shares (1 of 3, threshold=2)...")
    try:
        sm.reconstruct("secret_value", provided_shares=[shares[0]])
        print("❌ Should have raised PermissionError!")
    except PermissionError as e:
        print(f"✅ Correctly rejected: {e}")
    
    # Test share rotation
    print("\nRotating shares...")
    new_shares = sm.rotate("secret_value")
    reconstructed_after_rotation = sm.reconstruct("secret_value")
    print(f"Reconstructed after rotation: {reconstructed_after_rotation:.6f}")
    assert abs(reconstructed_after_rotation - value) < 1e-9
    print("✅ Rotation preserves secret value")
    
    print("\n✅ Share Manager test PASSED")


def test_audit_log():
    """Test 3: Append-only audit log with integrity verification."""
    separator("TEST 3: Audit Log — Append & Verify")
    
    log = AuditLog()
    
    # Append entries
    log.append_entry({"source": "test", "event": "START", "detail": "Test begins"})
    log.append_entry({"source": "test", "event": "ACTION", "detail": "Something happened"})
    log.append_entry({"source": "test", "event": "END", "detail": "Test ends"})
    
    print(f"Entries in log: {len(log)}")
    for entry in log.dump():
        print(f"  [{entry['index']}] {entry['data']['event']}: {entry['data']['detail']}")
        print(f"       hash: {entry['entry_hash']}  prev: {entry['prev_hash']}")
    
    # Verify integrity
    integrity = log.verify_integrity()
    print(f"\nChain integrity: {'✅ VALID' if integrity else '❌ BROKEN'}")
    assert integrity, "Audit log integrity check failed!"
    
    print("\n✅ Audit Log test PASSED")
    return log


def test_threshold_authorization(audit_log: AuditLog):
    """Test 4: K-of-N threshold approval simulation."""
    separator("TEST 4: Threshold Authorization (2-of-3)")
    
    approvers = ["approver-alice", "approver-bob", "approver-carol"]
    auth = ThresholdAuthorizer(approver_ids=approvers, threshold=2, audit_log=audit_log)
    
    # Create approval request
    req = auth.create_request(
        action_description="Execute critical infrastructure update",
        requester="scheduler",
        criticality="critical"
    )
    print(f"Approval Request: {req.request_id}")
    print(f"Action: {req.action_description}")
    print(f"Threshold: 2-of-3")
    
    # Alice approves
    print("\nAlice votes: APPROVE")
    result = auth.submit_vote(req.request_id, "approver-alice", True)
    print(f"  Status: {result['status']}, Approvals: {result['approvals']}/{auth.threshold}")
    assert result["status"] == "pending"
    
    # Bob approves → threshold reached
    print("\nBob votes: APPROVE")
    result = auth.submit_vote(req.request_id, "approver-bob", True)
    print(f"  Status: {result['status']}, Approvals: {result['approvals']}/{auth.threshold}")
    assert result["status"] == "approved"
    
    print(f"\nIs approved? {auth.is_approved(req.request_id)}")
    assert auth.is_approved(req.request_id)
    
    # Test denial scenario
    print("\n--- Denial Scenario (new request) ---")
    req2 = auth.create_request(
        action_description="Delete all backups",
        requester="rogue-agent",
        criticality="critical"
    )
    
    auth.submit_vote(req2.request_id, "approver-alice", False)
    result = auth.submit_vote(req2.request_id, "approver-bob", False)
    print(f"  2 denials → Status: {result['status']}")
    assert result["status"] == "denied"
    
    # Test invalid approver
    print("\n--- Invalid Approver Test ---")
    req3 = auth.create_request(
        action_description="Test action",
        requester="test",
        criticality="critical"
    )
    try:
        auth.submit_vote(req3.request_id, "unknown-approver", True)
        print("❌ Should have raised PermissionError!")
    except PermissionError as e:
        print(f"✅ Correctly rejected unknown approver: {e}")
    
    print("\n✅ Threshold Authorization test PASSED")
    return auth, req.request_id


def test_capability_validation(audit_log: AuditLog, auth: ThresholdAuthorizer, approval_id: str):
    """Test 5: Capability token issuance and validation."""
    separator("TEST 5: Capability Token Issuance & Validation")
    
    cp = ControlPlane(
        threshold_authorizer=auth,
        audit_log=audit_log,
        default_ttl=60.0,
        default_budget=1
    )
    
    # Issue a low-criticality token (no approval needed)
    print("Issuing LOW criticality token...")
    token = cp.issue_capability(
        issued_to="worker-001",
        scope=["compute.basic"],
        ttl_seconds=30.0,
        budget=1,
        criticality="low"
    )
    print(f"  Token ID: {token.token_id}")
    print(f"  Scope:    {token.scope}")
    print(f"  TTL:      {token.ttl_seconds}s")
    print(f"  Valid:    {token.is_valid()}")
    assert token.is_valid()
    
    # Consume the token
    print("\nConsuming token...")
    consumed = token.consume()
    print(f"  Consumed: {consumed}")
    print(f"  Valid after use: {token.is_valid()}")
    assert not token.is_valid(), "Token should be exhausted after single use"
    print("✅ Token correctly exhausted after budget consumed")
    
    # Try to issue critical token WITHOUT approval
    print("\nAttempting critical token WITHOUT approval...")
    try:
        cp.issue_capability(
            issued_to="worker-001",
            scope=["infra.critical"],
            criticality="critical"
        )
        print("❌ Should have raised PermissionError!")
    except PermissionError as e:
        print(f"✅ Correctly rejected: {e}")
    
    # Issue critical token WITH approval
    print("\nIssuing critical token WITH approval...")
    critical_token = cp.issue_capability(
        issued_to="worker-001",
        scope=["infra.critical"],
        criticality="critical",
        approval_request_id=approval_id
    )
    print(f"  Token ID: {critical_token.token_id}")
    print(f"  Valid: {critical_token.is_valid()}")
    assert critical_token.is_valid()
    
    # Test revocation
    print("\nRevoking token...")
    cp.revoke_token(critical_token.token_id, reason="Testing revocation")
    print(f"  Valid after revoke: {critical_token.is_valid()}")
    assert not critical_token.is_valid()
    print("✅ Token correctly invalidated after revocation")
    
    print("\n✅ Capability Validation test PASSED")
    return cp


def test_distributed_execution(audit_log: AuditLog, auth: ThresholdAuthorizer, approval_id: str):
    """Test 6: Full distributed execution pipeline."""
    separator("TEST 6: Distributed Execution Pipeline")
    
    # Setup
    cp = ControlPlane(
        threshold_authorizer=auth,
        audit_log=audit_log,
        default_ttl=60.0,
        default_budget=1
    )
    
    workers = [
        Worker(worker_id="worker-alpha", audit_log=audit_log),
        Worker(worker_id="worker-beta", audit_log=audit_log),
        Worker(worker_id="worker-gamma", audit_log=audit_log)
    ]
    
    scheduler = Scheduler(
        control_plane=cp,
        workers=workers,
        audit_log=audit_log,
        num_segments=2
    )
    
    # Build the function: add(3, 7)
    fn = build_add_function(3, 7)
    print(f"Executing: {fn.name}(3, 7)")
    print(f"Segments: {scheduler.num_segments}")
    print(f"Workers:  {[w.worker_id for w in workers]}")
    
    # Execute through the pipeline
    result = scheduler.execute_function(fn)
    
    print(f"\nResult:")
    print(f"  Success:           {result['success']}")
    print(f"  Return Value:      {result['return_value']}")
    print(f"  Segments Executed: {result['segments_executed']}")
    print(f"  Worker Details:")
    for wr in result["worker_results"]:
        print(f"    {wr['worker_id']}: {'✅' if wr['success'] else '❌'} ({wr['execution_time_ms']:.2f}ms)")
    
    assert result["success"], "Execution should succeed"
    assert result["return_value"] == 10, f"Expected 10, got {result['return_value']}"
    print(f"\n✅ add(3, 7) = {result['return_value']} — CORRECT")
    
    # ── Test without capability (should fail) ──
    print("\n--- Testing execution WITHOUT capability token ---")
    worker = Worker(worker_id="rogue-worker", audit_log=audit_log)
    from ic_agi.ir_definition import IRSegment
    segment = IRSegment(
        parent_function_id="test",
        instructions=fn.instructions,
        required_capabilities=["compute.basic"]
    )
    rogue_result = worker.execute_segment(segment, capability_token=None)
    print(f"  Rogue execution success: {rogue_result.success}")
    print(f"  Error: {rogue_result.error}")
    assert not rogue_result.success
    print("✅ Execution correctly blocked without capability")
    
    print("\n✅ Distributed Execution test PASSED")


def test_audit_trail_final(audit_log: AuditLog):
    """Test 7: Final audit trail integrity check."""
    separator("TEST 7: Final Audit Trail Integrity")
    
    print(f"Total audit entries: {len(audit_log)}")
    
    # Show last 10 entries
    recent = audit_log.get_entries(limit=10)
    print(f"\nLast {len(recent)} entries:")
    for entry in recent:
        src = entry.data.get("source", "?")
        evt = entry.data.get("event", "?")
        print(f"  [{entry.index:3d}] [{src:20s}] {evt}")
    
    # Verify full chain integrity
    integrity = audit_log.verify_integrity()
    print(f"\n🔐 Full chain integrity: {'✅ VERIFIED' if integrity else '❌ BROKEN'}")
    assert integrity, "Audit log integrity compromised!"
    
    print("\n✅ Audit Trail Integrity test PASSED")


def main():
    """Run all IC-AGI MVP tests."""
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          IC-AGI MVP — Distributed Execution Test        ║")
    print("║       Infrastructure Critical Anti-AGI Framework        ║")
    print("║                                                         ║")
    print("║  'Separating intelligence from authority.'              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    
    # Shared audit log — all components log to the same append-only trail
    audit_log = AuditLog()
    
    # Test 1: IR Definition
    fn = test_ir_definition()
    
    # Test 2: Share Manager
    test_share_manager()
    
    # Test 3: Audit Log
    test_audit_log()
    
    # Test 4: Threshold Authorization
    auth, approval_id = test_threshold_authorization(audit_log)
    
    # Test 5: Capability Validation
    cp = test_capability_validation(audit_log, auth, approval_id)
    
    # Test 6: Distributed Execution
    test_distributed_execution(audit_log, auth, approval_id)
    
    # Test 7: Final Audit Trail
    test_audit_trail_final(audit_log)
    
    # ── Final Summary ──
    print("\n" + "═" * 60)
    print("  🎉  ALL IC-AGI MVP TESTS PASSED")
    print("═" * 60)
    print(f"\n  Modules tested:")
    print(f"    ✅ IR Definition (Intermediate Representation)")
    print(f"    ✅ Share Manager (Distributed State — Mock)")
    print(f"    ✅ Audit Log (Append-Only, Hash-Chained)")
    print(f"    ✅ Threshold Authorization (K-of-N Approval)")
    print(f"    ✅ Control Plane (Capability Issuance)")
    print(f"    ✅ Worker (Distributed Execution Stub)")
    print(f"    ✅ Scheduler (IR Segment Routing)")
    print(f"\n  Total audit entries: {len(audit_log)}")
    print(f"  Audit chain integrity: {'✅ VERIFIED' if audit_log.verify_integrity() else '❌ BROKEN'}")
    print()


if __name__ == "__main__":
    main()
