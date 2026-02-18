"""
IC-AGI — CRM Business Rules Segmentation Example
===================================================

This module demonstrates how real CRM business rules are expressed as
segmented IR functions.  The key security property:

    **No single worker sees the full business rule.**

Each rule is decomposed into opaque segments.  A worker executing
Segment-0 does not know what Segment-1 does, nor what the overall
business outcome is.  This prevents an autonomous AI agent from
*reasoning* about the full rule and finding exploitable combinations.

EXAMPLE — Commission Calculation:

    Full rule (ONLY visible to the Scheduler):
      IF deal_amount > 100_000
         AND client_tier == "enterprise"
         AND discount_pct < 15
         AND seller_seniority_years > 2
      THEN commission_rate = 12%
      ELSE commission_rate = 5%

    After segmentation (each worker sees ONE of these):
      Segment 0: "Is X > 100_000?"          →  flag_a (bool)
      Segment 1: "Is Y == 'enterprise'?"     →  flag_b (bool)
      Segment 2: "Is Z < 15 AND W > 2?"      →  flag_c (bool)
      Segment 3: "If all flags true → 0.12, else 0.05"  →  rate (float)

    Worker A knows it compared a number to 100 000.
    It does NOT know that the number was a deal amount, nor that the
    result feeds into a commission formula.

NAMING CONVENTION — Obfuscated Variables:
    The segments use opaque names (v_in_0, v_out_0) intentionally.
    If a worker saw `deal_amount > 100000` it could infer context.
    With `v_in_0 > 100000` it cannot.

INTEGRATION:
    These builders return standard ``IRFunction`` objects.  They plug
    directly into the existing ``Scheduler.execute_function()`` pipeline
    — the same pipeline that already handles capability tokens, threshold
    approval, audit logging, and circuit breakers.
"""

from typing import Any, Dict, List, Optional

from .ir_definition import (
    IRFunction,
    IRInstruction,
    IROpCode,
    build_code_function,
)


# ────────────────────────────────────────────────────────────
#  1. CRM Commission Calculation — Segmented
# ────────────────────────────────────────────────────────────

def build_commission_rule_segmented(
    deal_amount: float,
    client_tier: str,
    discount_pct: float,
    seller_seniority_years: int,
    *,
    num_segments: int = 4,
) -> List[IRFunction]:
    """
    Build the commission calculation as N independent IR functions,
    each destined for a DIFFERENT worker.

    SECURITY RATIONALE:
      - Segment 0 sees `deal_amount` but not `client_tier` or `discount`.
      - Segment 1 sees `client_tier` but not `deal_amount` or `discount`.
      - Segment 2 sees `discount` and `seniority` but not `deal_amount`.
      - Segment 3 sees boolean flags but NOT the original data.
      - No single worker can reconstruct the full rule or the full input.

    Args:
        deal_amount:   The monetary value of the deal.
        client_tier:   "enterprise", "mid-market", or "smb".
        discount_pct:  The discount percentage applied (0-100).
        seller_seniority_years: Years of experience of the seller.
        num_segments:  Number of segments (minimum 4 for this rule).

    Returns:
        List of IRFunction, one per segment.  The Scheduler will assign
        each to a different worker.
    """

    # ── Segment 0: Deal size check ──
    # Worker sees: "is v_in_0 > 100000?"
    # Worker does NOT know v_in_0 is a deal amount.
    seg0 = build_code_function(
        code="v_out_0 = v_in_0 > 100000",
        inputs={"v_in_0": deal_amount},
        output_names=["v_out_0"],
        name="seg0_numeric_threshold",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    # ── Segment 1: Client tier check ──
    # Worker sees: "is v_in_1 == 'enterprise'?"
    # Worker does NOT know this is a client classification.
    seg1 = build_code_function(
        code="v_out_1 = v_in_1 == 'enterprise'",
        inputs={"v_in_1": client_tier},
        output_names=["v_out_1"],
        name="seg1_string_match",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    # ── Segment 2: Discount + seniority check ──
    # Worker sees two comparisons.  It doesn't know one is a discount
    # and the other is seniority, nor that they relate to commissions.
    seg2 = build_code_function(
        code="v_out_2 = (v_in_2 < 15) and (v_in_3 > 2)",
        inputs={"v_in_2": discount_pct, "v_in_3": seller_seniority_years},
        output_names=["v_out_2"],
        name="seg2_dual_compare",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    # ── Segment 3: Final decision ──
    # Worker sees three booleans and returns a number.
    # It does NOT know what the booleans represent, nor that the
    # output is a commission rate.  The variable names are opaque.
    seg3 = build_code_function(
        code="v_out_3 = 0.12 if (v_in_4 and v_in_5 and v_in_6) else 0.05",
        inputs={
            # These will be filled by the orchestrator after seg0-2 execute.
            # For now they are placeholders — the Scheduler fills them.
            "v_in_4": None,  # ← flag from seg0
            "v_in_5": None,  # ← flag from seg1
            "v_in_6": None,  # ← flag from seg2
        },
        output_names=["v_out_3"],
        name="seg3_conditional_select",
        capabilities=["compute.sandbox"],
        criticality="low",  # Combiner sees only flags, not financial data
    )

    return [seg0, seg1, seg2, seg3]


# ────────────────────────────────────────────────────────────
#  2. CRM Discount Approval — Segmented
# ────────────────────────────────────────────────────────────

def build_discount_approval_segmented(
    requested_discount: float,
    deal_amount: float,
    client_ltv: float,
    margin_pct: float,
) -> List[IRFunction]:
    """
    Determine whether a discount request should be auto-approved,
    require manager approval, or be denied.

    Full rule (ONLY visible to orchestrator):
      IF requested_discount <= 10:            → auto-approve
      ELIF requested_discount <= 25
           AND deal_amount > 50_000
           AND client_ltv > 100_000:          → manager approval (1-of-2)
      ELIF requested_discount <= 40
           AND margin_pct > 30:               → director approval (2-of-3)
      ELSE:                                   → denied

    After segmentation each worker only sees one check:

    Segment 0: "Is v_in_0 <= 10?"                     → quick_approve
    Segment 1: "Is v_in_1 <= 25 AND v_in_2 > 50000
                AND v_in_3 > 100000?"                  → manager_gate
    Segment 2: "Is v_in_4 <= 40 AND v_in_5 > 30?"     → director_gate
    Segment 3: Combine flags → decision string
    """

    seg0 = build_code_function(
        code="v_out_0 = v_in_0 <= 10",
        inputs={"v_in_0": requested_discount},
        output_names=["v_out_0"],
        name="seg0_quick_check",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    seg1 = build_code_function(
        code="v_out_1 = (v_in_1 <= 25) and (v_in_2 > 50000) and (v_in_3 > 100000)",
        inputs={
            "v_in_1": requested_discount,
            "v_in_2": deal_amount,
            "v_in_3": client_ltv,
        },
        output_names=["v_out_1"],
        name="seg1_mid_check",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    seg2 = build_code_function(
        code="v_out_2 = (v_in_4 <= 40) and (v_in_5 > 30)",
        inputs={"v_in_4": requested_discount, "v_in_5": margin_pct},
        output_names=["v_out_2"],
        name="seg2_high_check",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    # Decision combiner — sees only boolean flags, not business data.
    seg3 = build_code_function(
        code=(
            "if v_in_6:\n"
            "    v_out_3 = 'auto_approve'\n"
            "elif v_in_7:\n"
            "    v_out_3 = 'require_manager_1of2'\n"
            "elif v_in_8:\n"
            "    v_out_3 = 'require_director_2of3'\n"
            "else:\n"
            "    v_out_3 = 'denied'"
        ),
        inputs={"v_in_6": None, "v_in_7": None, "v_in_8": None},
        output_names=["v_out_3"],
        name="seg3_decision",
        capabilities=["compute.sandbox"],
        criticality="low",  # Combiner sees only flags, not business data
    )

    return [seg0, seg1, seg2, seg3]


# ────────────────────────────────────────────────────────────
#  3. CRM Lead Scoring — Segmented
# ────────────────────────────────────────────────────────────

def build_lead_scoring_segmented(
    email_opens: int,
    website_visits: int,
    days_since_last_contact: int,
    company_size: int,
    industry_match: bool,
) -> List[IRFunction]:
    """
    Score a lead from 0-100 based on engagement and fit signals.

    Full rule (ONLY visible to orchestrator):
      engagement_score = min(email_opens * 3 + website_visits * 2, 50)
      recency_penalty  = max(0, days_since_last_contact - 7) * 2
      fit_bonus        = (10 if company_size > 100 else 0)
                       + (15 if industry_match else 0)
      final_score      = max(0, min(100, engagement_score - recency_penalty + fit_bonus))

    After segmentation:
      Seg 0: Engagement score (sees opens + visits, doesn't know it's about leads)
      Seg 1: Recency penalty  (sees days, doesn't know it's CRM-related)
      Seg 2: Fit bonus        (sees size + bool, doesn't know what they mean)
      Seg 3: Combine scores   (sees 3 numbers, doesn't know what they represent)
    """

    seg0 = build_code_function(
        code="v_out_0 = min(v_in_0 * 3 + v_in_1 * 2, 50)",
        inputs={"v_in_0": email_opens, "v_in_1": website_visits},
        output_names=["v_out_0"],
        name="seg0_weighted_sum",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    seg1 = build_code_function(
        code="v_out_1 = max(0, v_in_2 - 7) * 2",
        inputs={"v_in_2": days_since_last_contact},
        output_names=["v_out_1"],
        name="seg1_decay_calc",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    seg2 = build_code_function(
        code="v_out_2 = (10 if v_in_3 > 100 else 0) + (15 if v_in_4 else 0)",
        inputs={"v_in_3": company_size, "v_in_4": industry_match},
        output_names=["v_out_2"],
        name="seg2_bonus_calc",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    seg3 = build_code_function(
        code="v_out_3 = max(0, min(100, v_in_5 - v_in_6 + v_in_7))",
        inputs={"v_in_5": None, "v_in_6": None, "v_in_7": None},
        output_names=["v_out_3"],
        name="seg3_clamp",
        capabilities=["compute.sandbox"],
        criticality="low",
    )

    return [seg0, seg1, seg2, seg3]


# ────────────────────────────────────────────────────────────
#  4. Segmented Orchestrator
# ────────────────────────────────────────────────────────────

class SegmentedRuleOrchestrator:
    """
    Orchestrates the execution of segmented business rules.

    This class implements the DATA-FLOW GRAPH that connects outputs
    of earlier segments to inputs of later segments.  The graph
    itself is opaque to any individual worker.

    SECURITY RATIONALE:
      - The orchestrator knows the *wiring* (seg0.out → seg3.in_4)
        but does NOT execute the logic — workers do.
      - Workers execute the *logic* but do NOT know the wiring.
      - Neither party has the full picture.

    WORKFLOW:
      1. Execute independent segments (seg0, seg1, seg2) in parallel.
      2. Collect their outputs.
      3. Wire outputs into the final segment's inputs.
      4. Execute the final segment.
      5. Return the result.
    """

    def __init__(self, scheduler):
        """
        Args:
            scheduler: An IC-AGI Scheduler instance with workers,
                       control plane, and audit log already configured.
        """
        self.scheduler = scheduler

    def execute_segmented_rule(
        self,
        segments: List[IRFunction],
        wiring: Dict[str, str],
        approval_request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a segmented rule through the IC-AGI pipeline.

        Args:
            segments: List of IRFunction, one per segment.
            wiring:   Maps "seg{N}.output_name" → "seg{M}.input_name".
                      Example: {"seg0.v_out_0": "seg3.v_in_4"}
            approval_request_id: For critical segments that need threshold auth.

        Returns:
            Dict with the final result and execution trace.

        Example wiring for commission rule:
            {
                "seg0.v_out_0": "seg3.v_in_4",  # deal flag → combiner
                "seg1.v_out_1": "seg3.v_in_5",  # tier flag → combiner
                "seg2.v_out_2": "seg3.v_in_6",  # discount flag → combiner
            }
        """
        results = {}
        outputs = {}

        # ── Phase 1: Execute independent segments ──
        # (those whose inputs are NOT wired from other segments)
        dependent_indices = set()
        for target in wiring.values():
            seg_idx = int(target.split(".")[0].replace("seg", ""))
            dependent_indices.add(seg_idx)

        independent = [
            (i, seg) for i, seg in enumerate(segments)
            if i not in dependent_indices
        ]

        for idx, seg_fn in independent:
            result = self.scheduler.execute_function(
                seg_fn,
                approval_request_id=approval_request_id,
            )
            results[f"seg{idx}"] = result

            # Extract outputs
            if result.get("success"):
                state = result.get("state", {})
                for key, val in state.items():
                    if key.startswith("v_out") or key == "__return__":
                        outputs[f"seg{idx}.{key}"] = val

        # ── Phase 2: Wire outputs → dependent segment inputs ──
        for source_key, target_key in wiring.items():
            if source_key in outputs:
                target_seg_idx = int(target_key.split(".")[0].replace("seg", ""))
                target_input = target_key.split(".")[1]

                # Patch the dependent segment's input
                target_fn = segments[target_seg_idx]
                for instr in target_fn.instructions:
                    if instr.opcode == IROpCode.EXEC_CODE and len(instr.operands) >= 3:
                        instr.operands[2][target_input] = outputs[source_key]

        # ── Phase 3: Execute dependent segments ──
        for idx in sorted(dependent_indices):
            seg_fn = segments[idx]
            result = self.scheduler.execute_function(
                seg_fn,
                approval_request_id=approval_request_id,
            )
            results[f"seg{idx}"] = result

            if result.get("success"):
                state = result.get("state", {})
                for key, val in state.items():
                    if key.startswith("v_out") or key == "__return__":
                        outputs[f"seg{idx}.{key}"] = val

        # ── Assemble final result ──
        # The last segment's output is the rule's output
        last_idx = len(segments) - 1
        last_result = results.get(f"seg{last_idx}", {})

        return {
            "success": all(r.get("success", False) for r in results.values()),
            "final_output": outputs.get(
                f"seg{last_idx}.v_out_{last_idx}",
                last_result.get("return_value"),
            ),
            "segment_results": results,
            "all_outputs": outputs,
        }


# ────────────────────────────────────────────────────────────
#  5. Convenience: Build Rule + Wiring Together
# ────────────────────────────────────────────────────────────

def commission_rule_with_wiring(
    deal_amount: float,
    client_tier: str,
    discount_pct: float,
    seller_seniority_years: int,
) -> tuple:
    """
    Returns (segments, wiring) ready for SegmentedRuleOrchestrator.

    Usage:
        segments, wiring = commission_rule_with_wiring(
            deal_amount=150_000,
            client_tier="enterprise",
            discount_pct=10.0,
            seller_seniority_years=5,
        )
        result = orchestrator.execute_segmented_rule(segments, wiring)
        commission_rate = result["final_output"]  # 0.12
    """
    segments = build_commission_rule_segmented(
        deal_amount, client_tier, discount_pct, seller_seniority_years,
    )
    wiring = {
        "seg0.v_out_0": "seg3.v_in_4",
        "seg1.v_out_1": "seg3.v_in_5",
        "seg2.v_out_2": "seg3.v_in_6",
    }
    return segments, wiring


def discount_rule_with_wiring(
    requested_discount: float,
    deal_amount: float,
    client_ltv: float,
    margin_pct: float,
) -> tuple:
    """Returns (segments, wiring) for the discount approval rule."""
    segments = build_discount_approval_segmented(
        requested_discount, deal_amount, client_ltv, margin_pct,
    )
    wiring = {
        "seg0.v_out_0": "seg3.v_in_6",
        "seg1.v_out_1": "seg3.v_in_7",
        "seg2.v_out_2": "seg3.v_in_8",
    }
    return segments, wiring


def lead_scoring_with_wiring(
    email_opens: int,
    website_visits: int,
    days_since_last_contact: int,
    company_size: int,
    industry_match: bool,
) -> tuple:
    """Returns (segments, wiring) for the lead scoring rule."""
    segments = build_lead_scoring_segmented(
        email_opens, website_visits, days_since_last_contact,
        company_size, industry_match,
    )
    wiring = {
        "seg0.v_out_0": "seg3.v_in_5",
        "seg1.v_out_1": "seg3.v_in_6",
        "seg2.v_out_2": "seg3.v_in_7",
    }
    return segments, wiring
