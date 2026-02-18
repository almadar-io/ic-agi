"""
IC-AGI — Intermediate Representation (IR) Definition
=====================================================

The IR is the fundamental unit of computation in IC-AGI.
Instead of executing raw code, the system operates on a structured
Intermediate Representation that can be:

  1. Inspected before execution (auditability)
  2. Split across distributed workers (no single node sees the full logic)
  3. Governed by capabilities and threshold approvals

SECURITY RATIONALE:
- Raw code execution is dangerous because it cannot be easily inspected.
- An IR allows deterministic policy checks before any execution occurs.
- Each IR node declares its required capabilities explicitly.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import uuid


class IROpCode(Enum):
    """
    Supported operation codes in the IR.
    Each opcode maps to a deterministic, sandboxed operation.
    
    SECURITY RATIONALE:
    - Whitelisted opcodes prevent arbitrary code execution.
    - New opcodes require explicit governance approval.
    """
    CONST = "CONST"           # Load a constant value
    ADD = "ADD"               # Arithmetic addition
    SUB = "SUB"               # Arithmetic subtraction
    MUL = "MUL"               # Arithmetic multiplication
    DIV = "DIV"               # Arithmetic division (checked)
    CALL = "CALL"             # Call a sub-function (requires capability)
    RETURN = "RETURN"         # Return a value from execution
    LOAD = "LOAD"             # Load a variable from state
    STORE = "STORE"           # Store a variable into state
    COMPARE = "COMPARE"       # Compare two values
    BRANCH = "BRANCH"         # Conditional branch
    EXEC_CODE = "EXEC_CODE"   # Execute sandboxed Python code (Phase 7)


@dataclass
class IRInstruction:
    """
    A single instruction in the Intermediate Representation.
    
    Each instruction has:
    - An opcode from the whitelisted set
    - Operands (inputs to the operation)
    - An optional output register name
    - Required capability scope (what permissions are needed)
    """
    opcode: IROpCode
    operands: List[Any] = field(default_factory=list)
    output: Optional[str] = None
    required_scope: Optional[str] = None  # Capability scope needed

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-safe dict for network transport."""
        return {
            "opcode": self.opcode.value,
            "operands": self.operands,
            "output": self.output,
            "required_scope": self.required_scope,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IRInstruction":
        """Deserialize from a dict received over the network."""
        return cls(
            opcode=IROpCode(d["opcode"]),
            operands=d.get("operands", []),
            output=d.get("output"),
            required_scope=d.get("required_scope"),
        )

    def __repr__(self):
        return f"IR({self.opcode.value} {self.operands} -> {self.output})"


@dataclass
class IRFunction:
    """
    A complete IR function — a sequence of IR instructions that together
    represent a computation.
    
    SECURITY RATIONALE:
    - Each function is assigned a unique ID for tracking.
    - The function declares its required capabilities upfront.
    - The criticality level determines what approval threshold is needed.
    - Functions can be split into segments for distributed execution.
    """
    function_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    instructions: List[IRInstruction] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    criticality: str = "low"  # "low", "medium", "high", "critical"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_instruction(self, instruction: IRInstruction):
        """Add an instruction to the function."""
        self.instructions.append(instruction)
        return self

    def segment(self, num_segments: int) -> List['IRSegment']:
        """
        Split this function into segments for distributed execution.
        
        SECURITY RATIONALE:
        - No single worker sees the entire function logic.
        - Each segment can be executed independently on separate nodes.
        - Recombination requires coordination through the ControlPlane.
        """
        if num_segments <= 0:
            raise ValueError("Number of segments must be positive")
        
        segments = []
        chunk_size = max(1, len(self.instructions) // num_segments)
        
        for i in range(0, len(self.instructions), chunk_size):
            chunk = self.instructions[i:i + chunk_size]
            seg = IRSegment(
                segment_id=str(uuid.uuid4()),
                parent_function_id=self.function_id,
                segment_index=len(segments),
                instructions=chunk,
                required_capabilities=self.required_capabilities.copy(),
                criticality=self.criticality
            )
            segments.append(seg)
        
        return segments


@dataclass
class IRSegment:
    """
    A segment of an IR function, assigned to a specific worker.
    
    SECURITY RATIONALE:
    - Segments are the unit of distributed execution.
    - Each segment carries its own capability requirements.
    - Workers must present valid capability tokens to execute a segment.
    """
    segment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_function_id: str = ""
    segment_index: int = 0
    instructions: List[IRInstruction] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    criticality: str = "low"
    assigned_worker: Optional[str] = None
    state_in: Dict[str, Any] = field(default_factory=dict)
    state_out: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for network transport to a remote worker."""
        return {
            "segment_id": self.segment_id,
            "parent_function_id": self.parent_function_id,
            "segment_index": self.segment_index,
            "instructions": [i.to_dict() for i in self.instructions],
            "required_capabilities": self.required_capabilities,
            "criticality": self.criticality,
            "assigned_worker": self.assigned_worker,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IRSegment":
        """Deserialize from a dict received over the network."""
        return cls(
            segment_id=d["segment_id"],
            parent_function_id=d.get("parent_function_id", ""),
            segment_index=d.get("segment_index", 0),
            instructions=[IRInstruction.from_dict(i) for i in d.get("instructions", [])],
            required_capabilities=d.get("required_capabilities", []),
            criticality=d.get("criticality", "low"),
            assigned_worker=d.get("assigned_worker"),
        )


# ── Helper: Build a trivial "add two numbers" IR function ──

def build_add_function(a_value: float, b_value: float) -> IRFunction:
    """
    Build a simple IR function that adds two numbers.
    Used as the canonical test case for the MVP.
    """
    fn = IRFunction(name="add_two_numbers", required_capabilities=["compute.basic"])
    fn.add_instruction(IRInstruction(IROpCode.CONST, [a_value], output="a"))
    fn.add_instruction(IRInstruction(IROpCode.CONST, [b_value], output="b"))
    fn.add_instruction(IRInstruction(IROpCode.ADD, ["a", "b"], output="result"))
    fn.add_instruction(IRInstruction(IROpCode.RETURN, ["result"]))
    return fn


def build_code_function(
    code: str,
    inputs: Dict[str, Any],
    output_names: List[str],
    *,
    name: str = "code_exec",
    capabilities: Optional[List[str]] = None,
    criticality: str = "low",
) -> IRFunction:
    """
    Build an IR function that executes real Python code.

    The EXEC_CODE instruction carries *everything* it needs:
      operands[0] = code string
      operands[1] = list of output variable names
      operands[2] = dict of input bindings

    This means the instruction is self-contained and works
    correctly regardless of which segment it lands in.

    Args:
        code: Python source code to execute in the sandbox.
        inputs: Name→value dict injected before execution.
        output_names: Variables to extract after execution.
        name: Human-readable function name.
        capabilities: Required capability scopes.
        criticality: Execution criticality level.
    """
    caps = capabilities or ["compute.sandbox"]
    fn = IRFunction(
        name=name,
        required_capabilities=caps,
        criticality=criticality,
    )

    # ── Single self-contained EXEC_CODE instruction ──
    # All inputs are embedded in operands[2] so the instruction
    # doesn’t depend on prior CONST instructions being in the
    # same segment.
    fn.add_instruction(IRInstruction(
        IROpCode.EXEC_CODE,
        [code, output_names, inputs],
        output="__sandbox__",
        required_scope="compute.sandbox",
    ))

    # ── Capture requested outputs ──
    for oname in output_names:
        fn.add_instruction(IRInstruction(IROpCode.RETURN, [oname]))

    return fn


# ── Prebuilt function catalog (common operations) ──

FUNCTION_CATALOG: Dict[str, dict] = {
    "add": {
        "description": "Add two numbers",
        "builder": "build_add_function",
        "params": ["operand_a", "operand_b"],
        "capabilities": ["compute.basic"],
    },
    "multiply": {
        "description": "Multiply two numbers",
        "code": "result = a * b",
        "inputs": ["a", "b"],
        "outputs": ["result"],
        "capabilities": ["compute.basic"],
    },
    "power": {
        "description": "Raise a to the power of b",
        "code": "result = a ** b",
        "inputs": ["a", "b"],
        "outputs": ["result"],
        "capabilities": ["compute.basic"],
    },
    "stats": {
        "description": "Compute mean and variance of a list of numbers",
        "code": (
            "n = len(numbers)\n"
            "mean = sum(numbers) / n\n"
            "diffs = [x - mean for x in numbers]\n"
            "variance = sum(d * d for d in diffs) / n"
        ),
        "inputs": ["numbers"],
        "outputs": ["mean", "variance", "n"],
        "capabilities": ["compute.sandbox"],
    },
    "fibonacci": {
        "description": "Compute the n-th Fibonacci number",
        "code": (
            "a_val, b_val = 0, 1\n"
            "for _ in range(n):\n"
            "    a_val, b_val = b_val, a_val + b_val\n"
            "result = a_val"
        ),
        "inputs": ["n"],
        "outputs": ["result"],
        "capabilities": ["compute.sandbox"],
    },
    "sort": {
        "description": "Sort a list of numbers",
        "code": "result = sorted(data)",
        "inputs": ["data"],
        "outputs": ["result"],
        "capabilities": ["compute.sandbox"],
    },
    "custom": {
        "description": "Execute arbitrary sandboxed Python code",
        "code": None,  # provided at call time
        "inputs": [],
        "outputs": [],
        "capabilities": ["compute.sandbox"],
    },
}
