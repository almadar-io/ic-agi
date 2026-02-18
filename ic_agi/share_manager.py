"""
IC-AGI — Shamir's Secret Sharing over GF(p)
=============================================

Production-grade implementation of Shamir's Secret Sharing Scheme
over a prime finite field GF(p).

CRYPTOGRAPHIC PROPERTIES:
- Information-theoretic security: any (K-1) shares reveal ZERO
  information about the secret (not even computational).
- Threshold reconstruction: exactly K shares are needed.
- Shares are elements of GF(p) — a 256-bit prime field.

ALGORITHM:
  Split(secret, K, N):
    1. Choose a random polynomial f(x) of degree K-1 where f(0) = secret
    2. Evaluate f(i) for i = 1..N → these are the shares
    3. Distribute share_i to node_i

  Reconstruct(shares, K):
    1. Collect at least K shares (x_i, y_i)
    2. Use Lagrange interpolation to compute f(0)
    3. f(0) = secret

PROACTIVE ROTATION:
  Re-share without reconstructing:
    1. Generate a random zero-polynomial g(x) with g(0)=0, degree K-1
    2. Evaluate g(i) for each node i
    3. New share_i = old_share_i + g(i)  (mod p)
    4. New shares are valid for the same secret, old shares are invalid

SECURITY RATIONALE:
- The prime p is 256 bits — same security level as secp256k1 / Ed25519.
- Random coefficients use Python's ``secrets`` module (CSPRNG).
- No floating point — all arithmetic is exact in the finite field.
"""

import secrets
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import uuid


# ── Finite Field Prime ──
# A 256-bit prime: the order of the secp256k1 curve — well-studied and safe.
PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _mod_inverse(a: int, p: int = PRIME) -> int:
    """Modular multiplicative inverse via Fermat's little theorem: a^(p-2) mod p."""
    if a % p == 0:
        raise ZeroDivisionError("Cannot invert zero in the field")
    return pow(a, p - 2, p)


def _lagrange_interpolate(points: List[Tuple[int, int]], p: int = PRIME) -> int:
    """
    Lagrange interpolation at x=0 over GF(p).

    Given K points (x_i, y_i), computes f(0) where f is the unique
    polynomial of degree < K passing through all points.

    f(0) = Σ y_i · Π_{j≠i} (0 − x_j) / (x_i − x_j)   (mod p)
    """
    k = len(points)
    if k == 0:
        raise ValueError("Need at least one point for interpolation")

    secret = 0
    for i in range(k):
        xi, yi = points[i]
        numerator = 1
        denominator = 1
        for j in range(k):
            if i == j:
                continue
            xj = points[j][0]
            numerator = (numerator * (0 - xj)) % p
            denominator = (denominator * (xi - xj)) % p
        lagrange_coeff = (numerator * _mod_inverse(denominator, p)) % p
        secret = (secret + yi * lagrange_coeff) % p
    return secret


# ── Encoding helpers ──
# Multiply by 10^18 so 18 decimal digits of precision survive the round-trip.
_PRECISION = 10**18


def _encode_secret(value: float) -> int:
    """Encode a float as a field element (deterministic, reversible)."""
    scaled = int(round(value * _PRECISION))
    return scaled % PRIME


def _decode_secret(field_element: int) -> float:
    """Decode a field element back to a float (handles negatives via p/2 rule)."""
    if field_element > PRIME // 2:
        scaled = field_element - PRIME
    else:
        scaled = field_element
    return scaled / _PRECISION


@dataclass
class Share:
    """
    A single Shamir share — a point (x, y) on the secret polynomial.

    - share_index = x  (1-indexed, since f(0) = secret)
    - value       = y  (field element in GF(p) — THE SECRET SHARE)
    """
    share_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    owner_node: str = ""
    key: str = ""
    value: int = 0                 # y-coordinate in GF(p)
    share_index: int = 0           # x-coordinate (1..N)
    total_shares: int = 0          # N
    threshold: int = 0             # K
    generation: int = 0            # Rotation generation counter


class ShareManager:
    """
    Shamir's Secret Sharing over GF(p) with proactive rotation.

    GUARANTEES:
    1. Any (K-1) or fewer shares reveal ZERO information about the secret.
    2. Any K or more shares reconstruct the secret exactly.
    3. Proactive rotation invalidates old shares without revealing the secret.
    """

    def __init__(self, num_nodes: int = 3, threshold: int = 2):
        if threshold < 2:
            raise ValueError("Threshold must be >= 2 (no single-node authority)")
        if threshold > num_nodes:
            raise ValueError("Threshold cannot exceed number of nodes")

        self.num_nodes = num_nodes
        self.threshold = threshold
        self.node_ids = [f"node-{i}" for i in range(num_nodes)]
        self._shares: Dict[str, List[Share]] = {}
        self._generation: Dict[str, int] = {}

    # ──────────────── Split ────────────────

    def split(self, key: str, value: float) -> List[Share]:
        """
        Split *value* into N Shamir shares.

        1. Encode secret → s ∈ GF(p)
        2. Random polynomial f(x) = s + a₁x + … + a_{K−1}x^{K−1}
        3. Shares = { (i, f(i)) for i = 1..N }
        """
        secret = _encode_secret(value)
        generation = self._generation.get(key, 0)

        # Random polynomial with f(0) = secret
        coefficients = [secret] + [secrets.randbelow(PRIME) for _ in range(self.threshold - 1)]

        shares = []
        for i in range(1, self.num_nodes + 1):
            y = self._evaluate_polynomial(coefficients, i)
            shares.append(Share(
                owner_node=self.node_ids[i - 1],
                key=key,
                value=y,
                share_index=i,
                total_shares=self.num_nodes,
                threshold=self.threshold,
                generation=generation,
            ))

        self._shares[key] = shares
        return shares

    # ──────────────── Reconstruct ────────────────

    def reconstruct(self, key: str, provided_shares: Optional[List[Share]] = None) -> float:
        """
        Reconstruct the secret from ≥ K shares via Lagrange interpolation.

        Raises PermissionError when fewer than K shares are provided.
        """
        shares = provided_shares or self._shares.get(key, [])

        if not shares:
            raise KeyError(f"No shares found for key: {key}")

        if len(shares) < self.threshold:
            raise PermissionError(
                f"Insufficient shares: {len(shares)} provided, "
                f"{self.threshold} required. "
                "SECURITY: Cannot reconstruct without threshold."
            )

        # Any K shares yield the same result
        selected = shares[:self.threshold]
        points = [(s.share_index, s.value) for s in selected]
        return _decode_secret(_lagrange_interpolate(points))

    # ──────────────── Rotate (zero-polynomial protocol) ────────────────

    def rotate(self, key: str) -> List[Share]:
        """
        Proactive rotation WITHOUT reconstructing the secret.

        Generate a zero-polynomial g(x) with g(0)=0, degree K-1.
        New share_i = old_share_i + g(i)  (mod p).

        The secret is unchanged; ALL old shares are invalidated.
        """
        if key not in self._shares:
            raise KeyError(f"No shares found for key: {key}")

        old_shares = self._shares[key]
        self._generation[key] = self._generation.get(key, 0) + 1
        new_generation = self._generation[key]

        # Zero-polynomial: g(0) = 0
        zero_coefficients = [0] + [secrets.randbelow(PRIME) for _ in range(self.threshold - 1)]

        new_shares = []
        for old in old_shares:
            delta = self._evaluate_polynomial(zero_coefficients, old.share_index)
            new_shares.append(Share(
                owner_node=old.owner_node,
                key=key,
                value=(old.value + delta) % PRIME,
                share_index=old.share_index,
                total_shares=old.total_shares,
                threshold=old.threshold,
                generation=new_generation,
            ))

        self._shares[key] = new_shares
        return new_shares

    # ──────────────── Queries ────────────────

    def get_node_shares(self, node_id: str) -> List[Share]:
        """Get all shares held by a specific node."""
        result = []
        for shares in self._shares.values():
            for share in shares:
                if share.owner_node == node_id:
                    result.append(share)
        return result

    # ──────────────── Internal ────────────────

    @staticmethod
    def _evaluate_polynomial(coefficients: List[int], x: int) -> int:
        """Horner's method in GF(p): f(x) = c₀ + x(c₁ + x(c₂ + …))."""
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % PRIME
        return result
