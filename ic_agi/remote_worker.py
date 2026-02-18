"""
IC-AGI — Remote Worker Client
================================

A ``RemoteWorker`` behaves like a local ``Worker`` but delegates execution
to a remote worker pod over HTTP.  The control-plane scheduler uses
``RemoteWorker`` instances so that each IR segment is executed on a
*physically separate* Kubernetes pod.

STATE-IN-TRANSIT SECURITY:
  - The ``initial_state`` dict is encrypted with the shared signing key
    before being sent over the network.
  - The worker pod decrypts, executes, and re-encrypts the result state.
  - An HMAC tag guarantees integrity (tampering → immediate rejection).

NETWORK TOPOLOGY (inside the K8s cluster):
  Control Plane → HTTP POST →
    ic-agi-worker-{i}.ic-agi-worker-headless.ic-agi.svc.cluster.local:8080/worker/execute
"""

import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .worker import WorkerResult
from .ir_definition import IRSegment
from .crypto_utils import encrypt_state, decrypt_state
from .audit_log import AuditLog


class RemoteWorker:
    """
    HTTP client that sends IR segments to a remote worker pod for execution.

    Implements the same interface used by the ``Scheduler``:
      - ``worker_id``  (str)
      - ``execute_segment(segment, capability_token, initial_state)``
    """

    def __init__(
        self,
        worker_id: str,
        base_url: str,
        signing_key: bytes,
        audit_log: Optional[AuditLog] = None,
        timeout_seconds: float = 30.0,
    ):
        self.worker_id = worker_id
        self.base_url = base_url.rstrip("/")
        self._signing_key = signing_key
        self.audit_log = audit_log
        self.timeout = timeout_seconds

    def execute_segment(
        self,
        segment: IRSegment,
        capability_token: Optional[Dict] = None,
        initial_state: Optional[Dict[str, Any]] = None,
    ) -> WorkerResult:
        """
        Send a segment to the remote worker pod and return the result.

        SECURITY:
          - State is encrypted before leaving the control plane.
          - Token is passed as-is (already HMAC-signed).
          - Response state is verified + decrypted on arrival.
        """
        start = time.time()

        # ── Encrypt outbound state ──
        state_to_send = initial_state or {}
        encrypted_out = encrypt_state(state_to_send, self._signing_key)

        # ── Build request payload ──
        payload = {
            "segment": segment.to_dict(),
            "capability_token": capability_token,
            "encrypted_state": encrypted_out,
        }

        self._log("REMOTE_SEND", segment.segment_id,
                  f"Sending segment {segment.segment_index} to {self.base_url}")

        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/worker/execute",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            self._log("REMOTE_ERROR", segment.segment_id,
                      f"HTTP {e.code}: {error_body}")
            return WorkerResult(
                worker_id=self.worker_id,
                segment_id=segment.segment_id,
                success=False,
                error=f"Remote worker HTTP {e.code}: {error_body}",
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            self._log("REMOTE_ERROR", segment.segment_id, str(e))
            return WorkerResult(
                worker_id=self.worker_id,
                segment_id=segment.segment_id,
                success=False,
                error=f"Remote worker unreachable: {e}",
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Decrypt inbound state ──
        if resp_data.get("success") and "encrypted_state" in resp_data:
            try:
                decrypted = decrypt_state(resp_data["encrypted_state"], self._signing_key)
            except ValueError as ve:
                self._log("REMOTE_TAMPER", segment.segment_id, str(ve))
                return WorkerResult(
                    worker_id=self.worker_id,
                    segment_id=segment.segment_id,
                    success=False,
                    error=str(ve),
                    execution_time_ms=(time.time() - start) * 1000,
                )
        else:
            decrypted = resp_data.get("state", {})

        elapsed = (time.time() - start) * 1000
        self._log("REMOTE_RECV", segment.segment_id,
                  f"Received result from {resp_data.get('worker_id', '?')} "
                  f"in {elapsed:.1f}ms")

        return WorkerResult(
            worker_id=resp_data.get("worker_id", self.worker_id),
            segment_id=segment.segment_id,
            success=resp_data.get("success", False),
            state=decrypted,
            error=resp_data.get("error"),
            execution_time_ms=elapsed,
        )

    def _log(self, event: str, segment_id: str, detail: str):
        if self.audit_log:
            self.audit_log.append_entry({
                "source": "RemoteWorker",
                "worker_id": self.worker_id,
                "event": event,
                "segment_id": segment_id,
                "detail": detail,
            })
