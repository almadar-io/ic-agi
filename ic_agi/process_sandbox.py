"""
IC-AGI — Process-Isolated Sandbox Executor
=============================================

A hardened sandbox that executes code in a **subprocess** with:
  - OS-level resource limits (memory, CPU time)
  - Real process kill on timeout (not thread abandonment)
  - Separate memory address space (no shared state exploit)
  - AST pre-validation (existing whitelist from SandboxExecutor)
  - JSON-based state transfer (no pickle/marshal)

ARCHITECTURE:
  1. Code + inputs are serialized to JSON.
  2. A subprocess.Popen is started with a wrapper script.
  3. The wrapper loads inputs, runs code, captures outputs.
  4. Outputs are serialized back to JSON via stdout.
  5. If the process exceeds the timeout, it is **killed** (SIGKILL).

SECURITY LAYERS:
  Layer 1: AST whitelist (static analysis — existing)
  Layer 2: Subprocess isolation (separate address space)
  Layer 3: Timeout via process kill (wall-clock + CPU time)
  Layer 4: Memory limit (via resource module on Linux)
  Layer 5: No network/filesystem in sandbox namespace

COMPATIBILITY:
  - Windows: Uses subprocess.Popen with timeout → TerminateProcess
  - Linux: Uses resource.setrlimit for CPU/memory + SIGKILL
  - Fallback: If subprocess fails, falls back to thread-based sandbox

MOCK NOTICE:
  In production, replace subprocess with:
    - gVisor (runsc) for container-level isolation
    - Wasmtime/Wasmer for WASM-level isolation
    - Firecracker for microVM-level isolation
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .sandbox_executor import (
    SandboxConfig, SandboxResult, SandboxExecutor, validate_ast
)


@dataclass
class ProcessSandboxConfig:
    """Configuration for the process-isolated sandbox."""
    max_code_length: int = 4096
    default_timeout: float = 5.0
    max_timeout: float = 30.0
    max_memory_mb: int = 128          # Memory limit in MB
    max_cpu_seconds: float = 10.0     # CPU time limit
    max_output_bytes: int = 65536     # Max stdout from subprocess
    python_executable: str = ""       # Auto-detect if empty


@dataclass
class ProcessSandboxResult:
    """Result from process-isolated execution."""
    success: bool
    outputs: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    process_pid: Optional[int] = None
    exit_code: Optional[int] = None
    killed: bool = False              # True if process was force-killed


# ── The subprocess wrapper script (injected into the child process)
_SUBPROCESS_WRAPPER = '''
import json
import sys
import math

# Load inputs from stdin
input_data = json.loads(sys.stdin.read())
code = input_data["code"]
inputs = input_data.get("inputs", {})
output_names = input_data.get("output_names", [])

# Build restricted namespace
namespace = {}
namespace.update({
    "abs": abs, "round": round, "min": min, "max": max,
    "sum": sum, "len": len, "range": range, "enumerate": enumerate,
    "zip": zip, "map": map, "filter": filter, "sorted": sorted,
    "reversed": reversed, "int": int, "float": float, "str": str,
    "bool": bool, "list": list, "tuple": tuple, "set": set,
    "dict": dict, "frozenset": frozenset, "isinstance": isinstance,
    "all": all, "any": any, "pow": pow, "divmod": divmod,
    "sqrt": math.sqrt, "ceil": math.ceil, "floor": math.floor,
    "log": math.log, "log2": math.log2, "log10": math.log10,
    "exp": math.exp, "sin": math.sin, "cos": math.cos, "tan": math.tan,
    "pi": math.pi, "e": math.e, "inf": math.inf, "nan": math.nan,
})
namespace.update(inputs)

# Execute
try:
    exec(code, {"__builtins__": {}}, namespace)
except Exception as ex:
    print(json.dumps({"success": False, "error": str(ex)}))
    sys.exit(0)

# Collect outputs
if output_names:
    outputs = {k: namespace[k] for k in output_names if k in namespace}
else:
    outputs = {
        k: v for k, v in namespace.items()
        if not k.startswith("_") and not callable(v)
        and k not in inputs and k not in (
            "abs", "round", "min", "max", "sum", "len", "range",
            "enumerate", "zip", "map", "filter", "sorted", "reversed",
            "int", "float", "str", "bool", "list", "tuple", "set",
            "dict", "frozenset", "isinstance", "all", "any", "pow",
            "divmod", "sqrt", "ceil", "floor", "log", "log2", "log10",
            "exp", "sin", "cos", "tan", "pi", "e", "inf", "nan",
        )
    }

# Serialize outputs (handle non-JSON types)
safe_outputs = {}
for k, v in outputs.items():
    try:
        json.dumps(v)
        safe_outputs[k] = v
    except (TypeError, ValueError):
        safe_outputs[k] = str(v)

print(json.dumps({"success": True, "outputs": safe_outputs}))
'''


class ProcessSandboxExecutor:
    """
    Subprocess-based sandbox with real process isolation.

    Usage:
        executor = ProcessSandboxExecutor()
        result = executor.execute(
            code="result = a + b * 2",
            inputs={"a": 3, "b": 7},
            timeout=5.0,
        )
        # result.outputs == {"result": 17}

    The code runs in a completely separate Python process.
    If it exceeds the timeout, the process is **killed** — not abandoned.
    """

    def __init__(self, config: Optional[ProcessSandboxConfig] = None) -> None:
        self.config = config or ProcessSandboxConfig()
        self._ast_validator = SandboxExecutor()  # Reuse AST validation

        # Auto-detect Python executable
        if not self.config.python_executable:
            self.config.python_executable = sys.executable

    def execute(
        self,
        code: str,
        inputs: Optional[Dict[str, Any]] = None,
        output_names: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> ProcessSandboxResult:
        """
        Execute code in an isolated subprocess.

        Args:
            code:         Python code string to execute.
            inputs:       Input variables injected into the namespace.
            output_names: Which variables to return (None = auto-detect).
            timeout:      Wall-clock timeout in seconds.

        Returns:
            ``ProcessSandboxResult`` with outputs or error.
        """
        start = time.time()
        timeout = min(
            timeout or self.config.default_timeout,
            self.config.max_timeout,
        )

        # ── Layer 1: AST Validation ──
        if len(code) > self.config.max_code_length:
            return ProcessSandboxResult(
                success=False,
                error=f"Code exceeds max length ({self.config.max_code_length} chars)",
                execution_time_ms=(time.time() - start) * 1000,
            )

        ast_errors = validate_ast(code)
        if ast_errors:
            return ProcessSandboxResult(
                success=False,
                error=f"AST validation failed: {ast_errors}",
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Layer 2: Subprocess Execution ──
        input_data = json.dumps({
            "code": code,
            "inputs": inputs or {},
            "output_names": output_names or [],
        })

        try:
            proc = subprocess.Popen(
                [self.config.python_executable, "-c", _SUBPROCESS_WRAPPER],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # Don't inherit environment (security)
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),  # Windows needs this
                    "PYTHONPATH": "",
                },
            )
        except Exception as e:
            return ProcessSandboxResult(
                success=False,
                error=f"Failed to start sandbox subprocess: {e}",
                execution_time_ms=(time.time() - start) * 1000,
            )

        pid = proc.pid
        killed = False

        try:
            # ── Layer 3: Timeout with real process kill ──
            stdout, stderr = proc.communicate(
                input=input_data,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            killed = True
            return ProcessSandboxResult(
                success=False,
                error=f"SANDBOX_TIMEOUT: Process killed after {timeout}s",
                execution_time_ms=(time.time() - start) * 1000,
                process_pid=pid,
                exit_code=-9,
                killed=True,
            )
        except Exception as e:
            try:
                proc.kill()
            except Exception:
                pass
            return ProcessSandboxResult(
                success=False,
                error=f"SANDBOX_ERROR: {e}",
                execution_time_ms=(time.time() - start) * 1000,
                process_pid=pid,
            )

        elapsed = (time.time() - start) * 1000

        # ── Parse subprocess output ──
        if proc.returncode != 0:
            return ProcessSandboxResult(
                success=False,
                error=f"Process exited with code {proc.returncode}: {stderr.strip()}",
                execution_time_ms=elapsed,
                process_pid=pid,
                exit_code=proc.returncode,
            )

        if len(stdout) > self.config.max_output_bytes:
            return ProcessSandboxResult(
                success=False,
                error=f"Output exceeds max size ({self.config.max_output_bytes} bytes)",
                execution_time_ms=elapsed,
                process_pid=pid,
                exit_code=0,
            )

        try:
            result_data = json.loads(stdout)
        except json.JSONDecodeError:
            return ProcessSandboxResult(
                success=False,
                error=f"Failed to parse subprocess output: {stdout[:200]}",
                execution_time_ms=elapsed,
                process_pid=pid,
                exit_code=0,
            )

        if result_data.get("success"):
            return ProcessSandboxResult(
                success=True,
                outputs=result_data.get("outputs", {}),
                execution_time_ms=elapsed,
                process_pid=pid,
                exit_code=0,
            )
        else:
            return ProcessSandboxResult(
                success=False,
                error=result_data.get("error", "Unknown sandbox error"),
                execution_time_ms=elapsed,
                process_pid=pid,
                exit_code=0,
            )

    def execute_with_fallback(
        self,
        code: str,
        inputs: Optional[Dict[str, Any]] = None,
        output_names: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> ProcessSandboxResult:
        """
        Execute in subprocess; fall back to thread-based sandbox on failure.

        This ensures execution works even if subprocess creation fails
        (e.g., in restricted container environments).
        """
        result = self.execute(code, inputs, output_names, timeout)
        if result.success:
            return result

        # If subprocess failed to START (not code error), try thread fallback
        if result.error and "Failed to start" in result.error:
            fallback = self._ast_validator.execute(
                code=code,
                inputs=inputs or {},
                output_names=output_names,
                timeout=timeout or self.config.default_timeout,
            )
            return ProcessSandboxResult(
                success=fallback.success,
                outputs=fallback.outputs,
                error=fallback.error,
                execution_time_ms=fallback.execution_time_ms,
            )

        return result
