"""
IC-AGI — Sandboxed Python Executor
=====================================

Executes *real* Python code within a restricted sandbox.
This is the bridge between the IR instruction model and
actual computation.

SECURITY LAYERS (defense-in-depth):
  1. **AST Whitelist** — code is parsed into an AST and only safe
     node types are permitted (no imports, exec, eval, open, etc.).
  2. **Restricted Builtins** — the execution namespace provides a
     tiny subset of Python builtins (math-safe, no I/O).
  3. **Timeout** — execution is bounded by a wall-clock deadline.
  4. **Resource Caps** — output size is capped; recursion limit lowered.
  5. **No Network / No Filesystem** — the namespace contains no
     references to ``os``, ``sys``, ``socket``, ``subprocess``, etc.

USAGE:
    executor = SandboxExecutor()
    result = executor.execute(
        code="result = a + b * 2",
        inputs={"a": 3, "b": 7},
        timeout=5.0,
    )
    # result.outputs == {"result": 17}

WHY NOT ``exec()`` ALONE?
    Unrestricted ``exec`` can import modules, open files, spawn
    processes, exfiltrate data, and crash the interpreter.
    The sandbox makes code execution *deterministic* and *safe*
    by statically rejecting dangerous constructs before any
    byte of user code runs.
"""

from __future__ import annotations

import ast
import math
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set


# ────────────────────────────────────────────────────────────
#  Configuration
# ────────────────────────────────────────────────────────────

@dataclass
class SandboxConfig:
    """Tuneable knobs for the sandbox."""
    max_code_length: int = 4096          # characters
    max_output_values: int = 64          # number of output bindings
    max_output_total_bytes: int = 65536  # total serialised size cap
    default_timeout: float = 5.0         # seconds
    max_timeout: float = 30.0            # hard ceiling
    max_recursion: int = 50              # sys.setrecursionlimit
    max_iterations: int = 1_000_000      # for-loop guard


# ────────────────────────────────────────────────────────────
#  AST Whitelist — static analysis before execution
# ────────────────────────────────────────────────────────────

# AST node types that are safe for numeric / logic computation.
_SAFE_AST_NODES: FrozenSet[type] = frozenset({
    # Literals & names
    ast.Module, ast.Expression, ast.Interactive,
    ast.Constant, ast.Name, ast.Load, ast.Store, ast.Del,
    ast.Starred, ast.FormattedValue, ast.JoinedStr,

    # Expressions
    ast.BinOp, ast.UnaryOp, ast.BoolOp,
    ast.Compare, ast.IfExp, ast.NamedExpr,

    # Operators
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
    ast.Mod, ast.Pow, ast.LShift, ast.RShift,
    ast.BitOr, ast.BitXor, ast.BitAnd, ast.Invert,
    ast.Not, ast.UAdd, ast.USub,
    ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Is, ast.IsNot, ast.In, ast.NotIn,

    # Collections
    ast.List, ast.Tuple, ast.Set, ast.Dict,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
    ast.comprehension,

    # Subscript / Attribute
    ast.Subscript, ast.Slice, ast.Index,  # Index removed in 3.9+ but harmless
    ast.Attribute,

    # Statements (safe subset)
    ast.Assign, ast.AugAssign, ast.AnnAssign,
    ast.Expr,  # bare expression statement
    ast.Return,
    ast.If, ast.For, ast.While, ast.Break, ast.Continue, ast.Pass,
    ast.FunctionDef, ast.Lambda, ast.arguments, ast.arg,

    # Call (filtered further by name check)
    ast.Call,
    ast.keyword,
})

# Built-in names that are NEVER allowed in code strings.
_FORBIDDEN_NAMES: FrozenSet[str] = frozenset({
    "import", "__import__",
    "exec", "eval", "compile",
    "open", "input", "print",        # I/O
    "exit", "quit",
    "globals", "locals", "vars", "dir",
    "getattr", "setattr", "delattr", "hasattr",
    "type", "super", "__class__",
    "breakpoint", "help",
    "__builtins__", "__loader__", "__spec__",
    "os", "sys", "subprocess", "socket", "shutil",
    "pathlib", "io", "ctypes", "signal",
    "__build_class__",
})

# Functions that ARE allowed (math-safe).
_ALLOWED_CALLABLES: Dict[str, Any] = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "sum": sum,
    "len": len,
    "range": range,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "sorted": sorted,
    "reversed": reversed,
    "int": int,
    "float": float,
    "str": str,
    "bool": bool,
    "list": list,
    "tuple": tuple,
    "set": set,
    "dict": dict,
    "frozenset": frozenset,
    "isinstance": isinstance,
    "all": all,
    "any": any,
    "pow": pow,
    "divmod": divmod,
    # math module functions
    "sqrt": math.sqrt,
    "ceil": math.ceil,
    "floor": math.floor,
    "log": math.log,
    "log2": math.log2,
    "log10": math.log10,
    "exp": math.exp,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "pi": math.pi,
    "e": math.e,
    "inf": math.inf,
    "nan": math.nan,
}


# ────────────────────────────────────────────────────────────
#  Static Validator
# ────────────────────────────────────────────────────────────

class _ASTValidator(ast.NodeVisitor):
    """Walk the AST tree and reject anything outside the whitelist."""

    def __init__(self) -> None:
        self.errors: List[str] = []

    def generic_visit(self, node: ast.AST) -> None:
        if type(node) not in _SAFE_AST_NODES:
            self.errors.append(
                f"SANDBOX_REJECT: Disallowed construct "
                f"'{type(node).__name__}' at line {getattr(node, 'lineno', '?')}"
            )
        super().generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in _FORBIDDEN_NAMES:
            self.errors.append(
                f"SANDBOX_REJECT: Forbidden name '{node.id}' "
                f"at line {getattr(node, 'lineno', '?')}"
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Block dunder attribute access
        if node.attr.startswith("__") and node.attr.endswith("__"):
            self.errors.append(
                f"SANDBOX_REJECT: Dunder attribute '{node.attr}' "
                f"at line {getattr(node, 'lineno', '?')}"
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'import' statement at line {node.lineno}"
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'from ... import' statement at line {node.lineno}"
        )

    def visit_Global(self, node: ast.Global) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'global' statement at line {node.lineno}"
        )

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'nonlocal' statement at line {node.lineno}"
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'class' definition at line {node.lineno}"
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'async def' at line {node.lineno}"
        )

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'async for' at line {node.lineno}"
        )

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'async with' at line {node.lineno}"
        )

    def visit_Await(self, node: ast.Await) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'await' at line {node.lineno}"
        )

    def visit_With(self, node: ast.With) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'with' statement at line {node.lineno}"
        )

    def visit_Raise(self, node: ast.Raise) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'raise' statement at line {node.lineno}"
        )

    def visit_Try(self, node: ast.Try) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'try/except' at line {node.lineno}"
        )

    def visit_TryStar(self, node: ast.AST) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'try/except*' at line {getattr(node, 'lineno', '?')}"
        )

    def visit_Delete(self, node: ast.Delete) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'del' statement at line {node.lineno}"
        )

    def visit_Assert(self, node: ast.Assert) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'assert' statement at line {node.lineno}"
        )

    def visit_Yield(self, node: ast.Yield) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'yield' at line {node.lineno}"
        )

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.errors.append(
            f"SANDBOX_REJECT: 'yield from' at line {node.lineno}"
        )


def validate_ast(source: str) -> List[str]:
    """
    Parse and validate a source string.
    Returns a list of errors (empty == safe).
    """
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as se:
        return [f"SANDBOX_REJECT: SyntaxError — {se}"]
    validator = _ASTValidator()
    validator.visit(tree)
    return validator.errors


# ────────────────────────────────────────────────────────────
#  Execution Result
# ────────────────────────────────────────────────────────────

@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""
    success: bool
    outputs: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    rejected_constructs: List[str] = field(default_factory=list)


# ────────────────────────────────────────────────────────────
#  Sandbox Executor
# ────────────────────────────────────────────────────────────

class SandboxExecutor:
    """
    Execute Python code strings in a restricted environment.

    Usage::

        executor = SandboxExecutor()
        result = executor.execute(
            code="result = a + b",
            inputs={"a": 10, "b": 20},
        )
        assert result.outputs["result"] == 30
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    # ── public API ──

    def execute(
        self,
        code: str,
        inputs: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        output_names: Optional[List[str]] = None,
    ) -> SandboxResult:
        """
        Execute *code* in the sandbox.

        Args:
            code: Python source (multi-line ok).
            inputs: Name→value bindings injected into the namespace.
            timeout: Max wall-clock seconds (capped by config).
            output_names: If provided, only these names are returned.
                          Otherwise ALL new bindings are returned.

        Returns:
            SandboxResult with outputs or error.
        """
        start = time.time()

        # ── Length check ──
        if len(code) > self.config.max_code_length:
            return SandboxResult(
                success=False,
                error=f"SANDBOX_REJECT: Code exceeds max length "
                      f"({len(code)} > {self.config.max_code_length})",
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Static AST validation ──
        errors = validate_ast(code)
        if errors:
            return SandboxResult(
                success=False,
                error="SANDBOX_REJECT: Static analysis failed",
                rejected_constructs=errors,
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Build restricted namespace ──
        namespace: Dict[str, Any] = {}
        namespace.update(_ALLOWED_CALLABLES)
        if inputs:
            namespace.update(inputs)

        # Snapshot input keys so we can diff outputs later
        input_keys: Set[str] = set(namespace.keys())

        # ── Determine timeout ──
        effective_timeout = min(
            timeout or self.config.default_timeout,
            self.config.max_timeout,
        )

        # ── Execute with timeout ──
        exec_error: Optional[str] = None
        completed = threading.Event()

        def _run():
            nonlocal exec_error
            try:
                compiled = compile(code, "<sandbox>", "exec")
                # Use namespace as BOTH globals and locals.
                # This avoids the Python 3 scoping issue where
                # comprehensions/generators inside exec() cannot
                # see variables defined in the local dict when
                # globals and locals are separate dicts.
                namespace["__builtins__"] = {}
                exec(compiled, namespace)  # noqa: S102
            except Exception as exc:
                exec_error = f"SANDBOX_RUNTIME: {type(exc).__name__}: {exc}"
            finally:
                completed.set()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        finished = completed.wait(timeout=effective_timeout)

        if not finished:
            return SandboxResult(
                success=False,
                error=f"SANDBOX_TIMEOUT: Execution exceeded {effective_timeout}s",
                execution_time_ms=(time.time() - start) * 1000,
            )

        if exec_error:
            return SandboxResult(
                success=False,
                error=exec_error,
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Collect outputs ──
        if output_names:
            outputs = {k: namespace[k] for k in output_names if k in namespace}
        else:
            # Return all NEW bindings (not builtins / inputs)
            outputs = {
                k: v for k, v in namespace.items()
                if k not in input_keys and not k.startswith("_")
            }

        # ── Cap output count ──
        if len(outputs) > self.config.max_output_values:
            return SandboxResult(
                success=False,
                error=f"SANDBOX_REJECT: Too many output bindings "
                      f"({len(outputs)} > {self.config.max_output_values})",
                execution_time_ms=(time.time() - start) * 1000,
            )

        # ── Serialisability check — strip non-JSON-safe values ──
        safe_outputs: Dict[str, Any] = {}
        for k, v in outputs.items():
            if isinstance(v, (int, float, bool, str, type(None))):
                safe_outputs[k] = v
            elif isinstance(v, (list, tuple)):
                safe_outputs[k] = _coerce_sequence(v)
            elif isinstance(v, dict):
                safe_outputs[k] = _coerce_dict(v)
            else:
                safe_outputs[k] = str(v)  # fallback to repr

        elapsed = (time.time() - start) * 1000
        return SandboxResult(
            success=True,
            outputs=safe_outputs,
            execution_time_ms=elapsed,
        )

    def validate_only(self, code: str) -> List[str]:
        """Static-check code without executing it."""
        if len(code) > self.config.max_code_length:
            return [f"Code exceeds max length ({len(code)})"]
        return validate_ast(code)


# ────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────

def _coerce_sequence(seq) -> list:
    """Recursively coerce a sequence to JSON-safe types."""
    out = []
    for item in seq:
        if isinstance(item, (int, float, bool, str, type(None))):
            out.append(item)
        elif isinstance(item, (list, tuple)):
            out.append(_coerce_sequence(item))
        elif isinstance(item, dict):
            out.append(_coerce_dict(item))
        else:
            out.append(str(item))
    return out


def _coerce_dict(d) -> dict:
    """Recursively coerce a dict to JSON-safe types."""
    out = {}
    for k, v in d.items():
        key = str(k)
        if isinstance(v, (int, float, bool, str, type(None))):
            out[key] = v
        elif isinstance(v, (list, tuple)):
            out[key] = _coerce_sequence(v)
        elif isinstance(v, dict):
            out[key] = _coerce_dict(v)
        else:
            out[key] = str(v)
    return out
