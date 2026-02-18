"""
IC-AGI — Append-Only Audit Log
================================

Every action in IC-AGI is logged in an append-only ledger.
Entries cannot be modified or deleted once written.

SECURITY RATIONALE:
- Immutability prevents post-hoc tampering of execution history.
- Every entry is chained (hash-linked) to its predecessor,
  creating a verifiable sequence.
- In production, this log would be replicated across multiple
  independent custodians and could use a Merkle tree for
  efficient verification.

MOCK NOTICE:
This implementation uses a simple in-memory list with SHA-256 chaining.
Production systems would use:
  - Distributed append-only stores (e.g., Trillian, immudb)
  - Hardware-backed tamper-evident logging
  - Cryptographic timestamping authorities
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditEntry:
    """
    A single entry in the audit log.
    
    Each entry contains:
    - A sequential index
    - A timestamp
    - The event data (who, what, when, where)
    - A hash of the previous entry (chain integrity)
    - A hash of this entry (for verification)
    """
    index: int
    timestamp: float
    data: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """
        Compute the SHA-256 hash of this entry.
        
        SECURITY RATIONALE:
        - Hash includes index, timestamp, data, and prev_hash.
        - Any modification to any field changes the hash.
        - Chain breaks are detectable by verifying hash linkage.
        """
        content = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "prev_hash": self.prev_hash
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


class AuditLog:
    """
    Append-only audit log with hash-chain integrity.
    
    SECURITY RATIONALE:
    - Entries can only be appended, never modified or deleted.
    - Each entry's hash depends on all previous entries.
    - Verification can detect any tampering.
    - The log can be replicated for redundancy.
    """

    def __init__(self):
        self._entries: List[AuditEntry] = []
        self._genesis_hash = hashlib.sha256(b"IC-AGI-GENESIS").hexdigest()

    def append_entry(self, data: Dict[str, Any]) -> AuditEntry:
        """
        Append a new entry to the audit log.
        
        SECURITY RATIONALE:
        - Timestamp is recorded at write time (not caller-supplied).
        - Entry is hash-chained to the previous entry.
        - Once appended, the entry is immutable.
        """
        prev_hash = self._entries[-1].entry_hash if self._entries else self._genesis_hash
        
        entry = AuditEntry(
            index=len(self._entries),
            timestamp=time.time(),
            data=data,
            prev_hash=prev_hash
        )
        entry.entry_hash = entry.compute_hash()
        
        self._entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        """
        Verify the entire chain's integrity.
        
        SECURITY RATIONALE:
        - Recomputes every hash and checks linkage.
        - If ANY entry was modified, the chain breaks.
        - Returns False if tampering is detected.
        """
        for i, entry in enumerate(self._entries):
            # Verify hash correctness
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                return False

            # Verify chain linkage
            if i == 0:
                if entry.prev_hash != self._genesis_hash:
                    return False
            else:
                if entry.prev_hash != self._entries[i - 1].entry_hash:
                    return False

        return True

    def get_entries(
        self,
        source: Optional[str] = None,
        event: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[AuditEntry]:
        """
        Query audit entries with optional filters.
        
        SECURITY RATIONALE:
        - Read-only access to the log.
        - Filters are applied in-memory (no mutation risk).
        """
        results = self._entries

        if source:
            results = [e for e in results if e.data.get("source") == source]
        if event:
            results = [e for e in results if e.data.get("event") == event]
        if limit:
            results = results[-limit:]

        return results

    def __len__(self):
        return len(self._entries)

    def dump(self) -> List[Dict[str, Any]]:
        """Export the full log as a list of dictionaries (for inspection)."""
        return [
            {
                "index": e.index,
                "timestamp": e.timestamp,
                "data": e.data,
                "prev_hash": e.prev_hash[:16] + "...",
                "entry_hash": e.entry_hash[:16] + "..."
            }
            for e in self._entries
        ]
