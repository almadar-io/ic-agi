"""
IC-AGI — Integration Test Suite (Live Cluster)
================================================

End-to-end tests against the deployed IC-AGI system on GKE.
Tests every critical path:

  ✅ Health & Status
  ✅ Basic distributed execution
  ✅ Threshold approval flow (approve + deny)
  ✅ Critical execution WITH approval (must succeed)
  ✅ Critical execution WITHOUT approval (must fail)
  ✅ Share distribution & reconstruction
  ✅ Audit trail integrity
  ✅ Edge cases & security boundaries
"""

import requests
import sys
import time
import json

BASE_URL = "http://34.69.69.238"
PASSED = 0
FAILED = 0
TOTAL = 0


def test(name: str):
    """Decorator-style test runner."""
    global TOTAL
    TOTAL += 1
    print(f"\n{'─'*60}")
    print(f"  TEST {TOTAL}: {name}")
    print(f"{'─'*60}")


def ok(msg: str = ""):
    global PASSED
    PASSED += 1
    print(f"  ✅ PASS {msg}")


def fail(msg: str = ""):
    global FAILED
    FAILED += 1
    print(f"  ❌ FAIL {msg}")


def assert_eq(actual, expected, label=""):
    if actual == expected:
        ok(f"{label}: {actual}")
    else:
        fail(f"{label}: expected {expected}, got {actual}")


def assert_true(condition, label=""):
    if condition:
        ok(label)
    else:
        fail(label)


# ════════════════════════════════════════════════════════════
#  1. HEALTH CHECK
# ════════════════════════════════════════════════════════════
test("Health Check — Liveness Probe")
r = requests.get(f"{BASE_URL}/health")
assert_eq(r.status_code, 200, "HTTP status")
data = r.json()
assert_eq(data["status"], "healthy", "Status field")
assert_true("node_id" in data, "Has node_id")
assert_true("uptime_seconds" in data, "Has uptime")
print(f"  → Node: {data['node_id']}, Uptime: {data['uptime_seconds']:.0f}s")


# ════════════════════════════════════════════════════════════
#  2. SYSTEM STATUS
# ════════════════════════════════════════════════════════════
test("System Status — Configuration Verification")
r = requests.get(f"{BASE_URL}/status")
assert_eq(r.status_code, 200, "HTTP status")
data = r.json()
assert_eq(data["threshold"], "2-of-3", "Threshold config")
assert_eq(data["workers"], 3, "Worker count")
assert_true(data["audit_integrity"], "Audit integrity")
print(f"  → Audit entries so far: {data['audit_entries']}")


# ════════════════════════════════════════════════════════════
#  3. BASIC EXECUTION — add(3, 7) = 10
# ════════════════════════════════════════════════════════════
test("Basic Execution — add(3, 7) = 10")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 3,
    "operand_b": 7,
    "criticality": "low",
    "caller_id": "integration-test"
})
assert_eq(r.status_code, 200, "HTTP status")
data = r.json()
assert_true(data["success"], "Execution success")
assert_eq(data["return_value"], 10.0, "Return value")
assert_true(data["segments_executed"] >= 2, f"Segments: {data['segments_executed']}")
print(f"  → Workers used: {[w['worker_id'] for w in data['worker_results']]}")


# ════════════════════════════════════════════════════════════
#  4. EXECUTION WITH DIFFERENT OPERANDS — add(-5, 15.5) = 10.5
# ════════════════════════════════════════════════════════════
test("Execution — add(-5, 15.5) = 10.5 (negative + float)")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": -5,
    "operand_b": 15.5,
    "criticality": "low",
    "caller_id": "integration-test"
})
data = r.json()
assert_true(data["success"], "Execution success")
assert_eq(data["return_value"], 10.5, "Return value")


# ════════════════════════════════════════════════════════════
#  5. EXECUTION WITH ZEROS — add(0, 0) = 0
# ════════════════════════════════════════════════════════════
test("Edge Case — add(0, 0) = 0")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 0,
    "operand_b": 0,
    "criticality": "low",
    "caller_id": "integration-test"
})
data = r.json()
assert_true(data["success"], "Execution success")
assert_eq(data["return_value"], 0.0, "Return value")


# ════════════════════════════════════════════════════════════
#  6. LARGE NUMBERS — add(999999, 1) = 1000000
# ════════════════════════════════════════════════════════════
test("Edge Case — add(999999, 1) = 1000000")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 999999,
    "operand_b": 1,
    "criticality": "low",
    "caller_id": "integration-test"
})
data = r.json()
assert_true(data["success"], "Execution success")
assert_eq(data["return_value"], 1000000.0, "Return value")


# ════════════════════════════════════════════════════════════
#  7. UNKNOWN FUNCTION — must fail 400
# ════════════════════════════════════════════════════════════
test("Security — Reject Unknown Function")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "rm_rf_slash",
    "operand_a": 0,
    "operand_b": 0,
    "criticality": "low",
    "caller_id": "integration-test"
})
assert_eq(r.status_code, 400, "HTTP 400 rejected")
assert_true("Unknown function" in r.json()["detail"], "Error mentions unknown function")


# ════════════════════════════════════════════════════════════
#  8. CRITICAL EXECUTION WITHOUT APPROVAL — must fail 403
# ════════════════════════════════════════════════════════════
test("Security — Critical Execution WITHOUT Approval (must fail)")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 1,
    "operand_b": 1,
    "criticality": "critical",
    "caller_id": "integration-test"
    # No approval_request_id!
})
assert_eq(r.status_code, 403, "HTTP 403 rejected")
print(f"  → Error: {r.json()['detail'][:80]}")


# ════════════════════════════════════════════════════════════
#  9. THRESHOLD APPROVAL — FULL FLOW (2-of-3 APPROVE)
# ════════════════════════════════════════════════════════════
test("Threshold Approval — Create Request + 2-of-3 Approve")

# Create request
r = requests.post(f"{BASE_URL}/approval/create", json={
    "action_description": "Integration test critical action",
    "requester": "test-suite",
    "criticality": "critical"
})
assert_eq(r.status_code, 200, "Create request")
approval = r.json()
req_id = approval["request_id"]
print(f"  → Request ID: {req_id}")
assert_eq(approval["threshold"], "2-of-3", "Threshold")

# Vote 1 (approver-0 approves) → pending
r = requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": req_id,
    "approver_id": "approver-0",
    "vote": True
})
v1 = r.json()
assert_eq(v1["status"], "pending", "After vote 1: pending")
assert_eq(v1["approvals"], 1, "1 approval")
assert_eq(v1["remaining"], 1, "1 remaining")

# Vote 2 (approver-2 approves) → approved!
r = requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": req_id,
    "approver_id": "approver-2",
    "vote": True
})
v2 = r.json()
assert_eq(v2["status"], "approved", "After vote 2: approved")
assert_eq(v2["approvals"], 2, "2 approvals")


# ════════════════════════════════════════════════════════════
# 10. CRITICAL EXECUTION WITH APPROVAL — must succeed
# ════════════════════════════════════════════════════════════
test("Critical Execution WITH Approval — add(42, 58) = 100")
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 42,
    "operand_b": 58,
    "criticality": "critical",
    "approval_request_id": req_id,
    "caller_id": "integration-test"
})
assert_eq(r.status_code, 200, "HTTP 200")
data = r.json()
assert_true(data["success"], "Execution success")
assert_eq(data["return_value"], 100.0, "Return value = 100")
print(f"  → Critical action executed with threshold approval ✅")


# ════════════════════════════════════════════════════════════
# 11. THRESHOLD DENIAL — 2-of-3 DENY
# ════════════════════════════════════════════════════════════
test("Threshold Denial — 2-of-3 Deny Blocks Action")

r = requests.post(f"{BASE_URL}/approval/create", json={
    "action_description": "Dangerous action that should be denied",
    "requester": "rogue-agent",
    "criticality": "critical"
})
deny_req_id = r.json()["request_id"]

# 2 denials → denied
requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": deny_req_id, "approver_id": "approver-0", "vote": False
})
r = requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": deny_req_id, "approver_id": "approver-1", "vote": False
})
assert_eq(r.json()["status"], "denied", "Request denied")

# Try to use denied approval for execution → must fail
r = requests.post(f"{BASE_URL}/execute", json={
    "function_name": "add",
    "operand_a": 1,
    "operand_b": 1,
    "criticality": "critical",
    "approval_request_id": deny_req_id,
    "caller_id": "integration-test"
})
assert_eq(r.status_code, 403, "Denied approval → 403")
print(f"  → Denied approval correctly blocks critical execution")


# ════════════════════════════════════════════════════════════
# 12. INVALID APPROVER — must fail 403
# ════════════════════════════════════════════════════════════
test("Security — Invalid Approver Rejected")
r = requests.post(f"{BASE_URL}/approval/create", json={
    "action_description": "Test invalid approver",
    "requester": "test",
    "criticality": "critical"
})
test_req_id = r.json()["request_id"]

r = requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": test_req_id,
    "approver_id": "hacker-9000",
    "vote": True
})
assert_eq(r.status_code, 403, "Unknown approver → 403")


# ════════════════════════════════════════════════════════════
# 13. DOUBLE VOTING — must be idempotent
# ════════════════════════════════════════════════════════════
test("Security — Double Voting is Idempotent")
r = requests.post(f"{BASE_URL}/approval/create", json={
    "action_description": "Test double vote",
    "requester": "test",
    "criticality": "critical"
})
dv_req_id = r.json()["request_id"]

requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": dv_req_id, "approver_id": "approver-0", "vote": True
})
r = requests.post(f"{BASE_URL}/approval/vote", json={
    "request_id": dv_req_id, "approver_id": "approver-0", "vote": True
})
assert_eq(r.json()["status"], "already_voted", "Double vote detected")


# ════════════════════════════════════════════════════════════
# 14. SHARE DISTRIBUTION & RECONSTRUCTION
# ════════════════════════════════════════════════════════════
test("Share Manager — Split & Reconstruct Secret")
r = requests.post(f"{BASE_URL}/shares/split", json={
    "key": "test_secret",
    "value": 42.0
})
assert_eq(r.status_code, 200, "Split OK")
shares = r.json()
assert_eq(shares["num_shares"], 3, "3 shares created")
assert_eq(shares["threshold"], 2, "Threshold = 2")
print(f"  → Shares distributed to: {[s['owner_node'] for s in shares['shares']]}")

# Reconstruct
r = requests.post(f"{BASE_URL}/shares/reconstruct/test_secret")
assert_eq(r.status_code, 200, "Reconstruct OK")
reconstructed = r.json()["reconstructed_value"]
assert_true(abs(reconstructed - 42.0) < 1e-9, f"Reconstructed: {reconstructed} ≈ 42.0")


# ════════════════════════════════════════════════════════════
# 15. RECONSTRUCT UNKNOWN KEY — must fail
# ════════════════════════════════════════════════════════════
test("Security — Reconstruct Unknown Key Fails")
r = requests.post(f"{BASE_URL}/shares/reconstruct/nonexistent_key")
assert_eq(r.status_code, 403, "Unknown key → 403")


# ════════════════════════════════════════════════════════════
# 16. AUDIT TRAIL — INTEGRITY & CONTENT
# ════════════════════════════════════════════════════════════
test("Audit Trail — Integrity Verification")
r = requests.get(f"{BASE_URL}/audit?limit=5")
assert_eq(r.status_code, 200, "Audit query OK")
audit = r.json()
assert_true(audit["integrity"], "Hash-chain integrity VERIFIED")
assert_true(audit["total_entries"] > 20, f"Total entries: {audit['total_entries']}")
print(f"  → {audit['total_entries']} entries, chain integrity: ✅")

# Check that we can filter by source
r = requests.get(f"{BASE_URL}/audit?source=ControlPlane&limit=3")
cp_entries = r.json()["entries"]
assert_true(
    all(e["data"]["source"] == "ControlPlane" for e in cp_entries),
    "Filter by source works"
)

r = requests.get(f"{BASE_URL}/audit?event=CAPABILITY_ISSUED&limit=3")
cap_entries = r.json()["entries"]
assert_true(
    all(e["data"]["event"] == "CAPABILITY_ISSUED" for e in cap_entries),
    "Filter by event works"
)


# ════════════════════════════════════════════════════════════
# 17. CONCURRENT REQUESTS — Rapid-fire execution
# ════════════════════════════════════════════════════════════
test("Stress — 10 Rapid-Fire Executions")
results = []
for i in range(10):
    r = requests.post(f"{BASE_URL}/execute", json={
        "function_name": "add",
        "operand_a": i,
        "operand_b": i * 10,
        "criticality": "low",
        "caller_id": f"stress-integ-{i}"
    })
    results.append(r.json())

all_ok = all(r["success"] for r in results)
all_correct = all(
    r["return_value"] == i + i * 10
    for i, r in enumerate(results)
)
assert_true(all_ok, "All 10 executions succeeded")
assert_true(all_correct, "All 10 results mathematically correct")
print(f"  → Results: {[r['return_value'] for r in results]}")


# ════════════════════════════════════════════════════════════
# 18. FINAL AUDIT INTEGRITY CHECK
# ════════════════════════════════════════════════════════════
test("Final — Audit Integrity After All Tests")
r = requests.get(f"{BASE_URL}/audit?limit=1")
audit = r.json()
assert_true(audit["integrity"], "FINAL chain integrity VERIFIED")
print(f"  → Total audit entries after all tests: {audit['total_entries']}")
print(f"  → Hash chain: INTACT ✅")


# ════════════════════════════════════════════════════════════
#  SUMMARY
# ════════════════════════════════════════════════════════════
print(f"\n{'═'*60}")
print(f"  IC-AGI INTEGRATION TEST RESULTS")
print(f"{'═'*60}")
print(f"  Total Tests:  {TOTAL}")
print(f"  Passed:       {PASSED} ✅")
print(f"  Failed:       {FAILED} ❌")
print(f"  Endpoint:     {BASE_URL}")
print(f"{'═'*60}")

if FAILED > 0:
    print(f"\n  ⚠️  {FAILED} test(s) FAILED — review output above")
    sys.exit(1)
else:
    print(f"\n  🎉  ALL TESTS PASSED — IC-AGI is fully operational")
    sys.exit(0)
