# 🛡️ IC-AGI — Infrastructure Critical Anti-AGI

**Separate intelligence from authority.**

IC-AGI is a distributed execution and authority framework that ensures no single entity — human or artificial — can unilaterally execute critical actions. It is designed to control actors that may be *more intelligent* than the control system itself.

[![Tests](https://img.shields.io/badge/tests-273%2F273-brightgreen)]()
[![TLA+](https://img.shields.io/badge/formal_verification-TLA%2B-blue)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-green)]()
[![Phase](https://img.shields.io/badge/phase-8%20of%2010-orange)]()

---

## 🧠 The Problem

> *"The power of AI agents comes from intelligence, data access, and freedom to act. But security is the biggest bottleneck for broad adoption."*

As AI agents become more capable, the core challenge shifts from *capability* to *containment*:

- The more data & control you give an AI agent, the more it can help you — **and** the more it can hurt you.
- No single machine should hold the keys to critical infrastructure.
- Traditional access control assumes trusted principals. AI agents are **adversarial by design assumption**.

IC-AGI solves this by distributing authority so that **no single point of compromise** can lead to uncontrolled action.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│              CONTROL PLANE              │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Policy   │ │Capability│ │Threshold│ │
│  │ Engine   │ │ Issuer   │ │Approvers│ │
│  └──────────┘ └──────────┘ └─────────┘ │
│         ┌──────────────┐                │
│         │  Audit Ledger│ (append-only)  │
│         └──────────────┘                │
└─────────────────┬───────────────────────┘
                  │ Capability Tokens
                  │ (TTL + Scope + Budget)
┌─────────────────▼───────────────────────┐
│             EXECUTION PLANE             │
│  ┌────────┐  ┌────────┐  ┌────────┐    │
│  │Worker 0│  │Worker 1│  │Worker 2│    │
│  │(shard) │  │(shard) │  │(shard) │    │
│  └────────┘  └────────┘  └────────┘    │
│  No worker sees ALL segments.           │
│  State encrypted in transit (HMAC).     │
└─────────────────────────────────────────┘
```

---

## 🔐 Core Security Guarantees

| Guarantee | Mechanism | Formally Verified |
|---|---|---|
| **No unilateral authority** | K-of-N threshold approval (Shamir SSS) | ✅ TLA+ P1-P4 |
| **Capability-bounded execution** | Tokens with TTL, scope, and consumable budget | ✅ TLA+ P5-P9 |
| **Anti-replay** | HMAC-SHA256 signatures, budget=1 enforcement | ✅ TLA+ P5 |
| **Segment isolation** | No worker holds all IR segments | ✅ TLA+ P10-P14 |
| **Tamper detection** | Encrypt-then-MAC on state in transit | ✅ TLA+ P13 |
| **Oracle abuse prevention** | Rate limiting + behavioral fingerprinting | ✅ Tested |
| **Compromised node isolation** | Circuit breaker (CLOSED→OPEN→HALF_OPEN) | ✅ Tested |
| **Proactive key rotation** | Zero-polynomial protocol (secret never reconstructed) | ✅ Algebraic proof A4-A5 |

---

## ⚡ Quick Start

```bash
# Clone
git clone https://github.com/saezbaldo/ic-agi.git
cd ic-agi

# Install
pip install -r requirements.txt

# Run tests (273 checks)
python -m pytest ic_agi/ -v

# Start the control plane
python -m ic_agi.service
```

### Execute a function

```bash
# Simple addition (distributed across workers)
curl -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{"function": "add", "operands": [3, 7]}'

# Custom sandboxed code
curl -X POST http://localhost:8080/execute \
  -H "Content-Type: application/json" \
  -d '{
    "function": "custom",
    "code": "result = sum(range(100))",
    "inputs": {},
    "output_names": ["result"]
  }'
```

---

## 🧪 What's Been Verified

### Formal Verification (TLA+ & Algebraic Proofs)

- **14 safety properties** verified via exhaustive model checking (~50,000+ states, ~250,000+ property checks)
- **8 algebraic proofs** of Shamir Secret Sharing correctness
- Zero violations found

### Adversarial Testing

| Attack Vector | Result |
|---|---|
| Forged HMAC token | ❌ Rejected |
| Replay attack (consumed token) | ❌ Rejected |
| Expired token reuse | ❌ Rejected |
| Tampered state in transit | ❌ Detected via MAC |
| Man-in-the-middle (altered operands) | ❌ HMAC integrity check fails |
| Malicious code injection (import, eval, exec) | ❌ AST validator rejects |
| Oracle extraction (repeated queries) | ❌ Anti-oracle blocks |
| Distributed flooding | ❌ Global rate cap |
| Combined multi-vector attack | ❌ All vectors blocked |

### Test Results

| Suite | Checks | Status |
|---|---|---|
| Unit tests | 7/7 | ✅ |
| Shamir crypto | 23/23 | ✅ |
| Adversarial attacks | 32/32 | ✅ |
| Integration (GKE) | 49/49 | ✅ |
| Distributed execution | 25/25 | ✅ |
| Anti-oracle & rate limiting | 47/47 | ✅ |
| Sandbox runtime & MITM | 58/58 | ✅ |
| Formal verification | 32/32 | ✅ |
| **Total** | **273/273** | ✅ |

---

## 🗺️ Roadmap

| Phase | Description | Status |
|---|---|---|
| 1 | IR Specification & Sandboxed Execution | ✅ Complete |
| 2 | Capability System (TTL, Scope, Budget) | ✅ Complete |
| 3 | Threshold Authorization (K-of-N) | ✅ Complete |
| 4 | Real Cryptography (Shamir, HMAC-SHA256) | ✅ Complete |
| 5 | Distributed Worker Communication (K8s) | ✅ Complete |
| 6 | Anti-Oracle & Rate Limiting | ✅ Complete |
| 7 | Real Runtime + Adversarial Testing | ✅ Complete |
| 8 | Formal Verification (TLA+) | ✅ Complete |
| 9 | Governance Protocols | 🔄 In Progress |
| 10 | Production Hardening | 📋 Planned |

---

## 🏛️ Design Principles

1. **No single node contains full authority.**
2. **No single node contains full program logic.**
3. **Execution requires explicit capabilities with TTL and scope.**
4. **Critical actions require K-of-N threshold approval.**
5. **All state transitions are auditable.**
6. **Oracle abuse is rate-limited and monitored.**
7. **Secrets are rotated proactively.**

---

## 🔬 How It's Different

IC-AGI is **not** a new cryptographic primitive. Every component exists independently:

- Shamir Secret Sharing (1979)
- Capability-based security (1966)
- Threshold signatures (1991)
- Circuit breakers (2007)

**What's novel is the composition thesis:** a system designed from first principles to control actors that are potentially more intelligent than the control system itself. No existing system combines threshold authorization, distributed IR execution, capability tokens with consumable budgets, anti-oracle detection, and formal verification into a single framework purpose-built for AI agent containment.

See the full [Competitive Analysis](PLAN-A_IC-AGI_Competitive_Analysis.md) for detailed comparison against Kerberos, HashiCorp Vault, Gnosis Safe, Temporal.io, LangChain, and others.

---

## 📂 Project Structure

```
ic_agi/
├── ir_definition.py        # Intermediate Representation (opcodes, segments)
├── share_manager.py         # Shamir Secret Sharing over GF(p)
├── threshold_auth.py        # K-of-N threshold authorization
├── threshold_crypto.py      # Cryptographic threshold operations
├── control_plane.py         # Policy engine + capability issuer
├── worker.py                # Local IR execution worker
├── remote_worker.py         # Distributed worker (HTTP/K8s)
├── scheduler.py             # IR segment routing
├── sandbox_executor.py      # AST-validated Python sandbox
├── crypto_utils.py          # HMAC-SHA256 encrypt-then-MAC
├── audit_log.py             # Append-only audit ledger
├── rate_limiter.py          # Sliding-window rate limiter
├── anti_oracle.py           # Behavioral fingerprinting
├── circuit_breaker.py       # Worker health state machine
├── service.py               # HTTP API (FastAPI)
├── formal/
│   ├── ThresholdAuth.tla     # TLA+ spec (P1-P4)
│   ├── CapabilityTokens.tla  # TLA+ spec (P5-P9)
│   ├── DistributedExecution.tla # TLA+ spec (P10-P14)
│   ├── model_checker.py      # Exhaustive BFS model checker
│   └── shamir_proofs.py      # Algebraic proofs (A1-A8)
k8s/                          # Kubernetes manifests (GKE-ready)
```

---

## 🤝 Contributing

We welcome contributions from:

- **Cryptographers** — threshold schemes, MPC protocols
- **Distributed systems engineers** — consensus, fault tolerance
- **AI safety researchers** — containment strategies, threat models
- **Formal methods experts** — TLA+, TLAPS proofs, Coq/Lean
- **Security auditors** — penetration testing, adversarial analysis

---

## 📄 License

Apache 2.0

---

## 📬 Contact

- **X:** [@saezbaldo](https://x.com/saezbaldo)
- **Email:** saezbaldo@gmail.com

---

*IC-AGI is not about hiding code from intelligence. It is about separating intelligence from authority.*
