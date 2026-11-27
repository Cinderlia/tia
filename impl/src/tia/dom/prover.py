"""FlowProver: prove that one flow's read side is reachable, then hand a plan on.

The prover is the old trigger agent under a narrower contract:

* input: a flow (target read site + candidate write sites + sink class);
* allowed: direct database writes to *discover* the conditions a branch needs;
* output: a :class:`FlowProbe` with the payload plan, the constraint plan, the
  final trigger request and the evidence refs;
* never: legitimate replay (the injection agent does that) or a final report.

Direct writes are always undone before the prover returns, so the handoff
carries evidence+plan, never a dirty database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tia.dom.trigger import StageRecord, TriggerResult, normalize_slice, run_trigger
from tia.orch.kernel import ToolClient


@dataclass
class FlowProbe:
    flow_id: str
    sink_class: str
    verdict: str = ""
    case_id: str = ""
    residue: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    constraints: list[dict[str, Any]] = field(default_factory=list)
    final_trigger: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    stages: list[StageRecord] = field(default_factory=list)
    trace: list[Any] = field(default_factory=list)
    report: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "sink_class": self.sink_class,
            "verdict": self.verdict,
            "case_id": self.case_id,
            "residue": self.residue,
            "payload": self.payload,
            "constraints": self.constraints,
            "final_trigger": self.final_trigger,
            "evidence_refs": self.evidence_refs,
            "notes": self.notes,
            "stages": [{"stage": s.stage, "ok": s.ok, "note": s.note} for s in self.stages],
        }


def _plan(notes: dict[str, Any]) -> dict[str, Any]:
    plan = notes.get("constraint_plan")
    return plan if isinstance(plan, dict) else {}


async def run_flow_prover(
    flow: dict[str, Any],
    target_raw: dict[str, Any],
    base_url: str,
    *,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
) -> tuple[FlowProbe, TriggerResult]:
    """Run the prover and return both the flow probe and the raw trigger result."""

    trigger = await run_trigger(
        normalize_slice(target_raw),
        base_url=base_url,
        payload_base=payload_base,
        budget=budget,
        client=client,
        slice_id=slice_id or str(flow.get("target_slice_id") or ""),
        flow=flow,
    )
    notes = trigger.notes or {}
    plan = _plan(notes)
    raw_payload = plan.get("payload")
    payload: dict[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}
    raw_constraints = plan.get("constraints")
    constraints: list[Any] = raw_constraints if isinstance(raw_constraints, list) else []
    evidence_refs = [step.evidence_ref for step in trigger.trace if step.evidence_ref]
    raw_final = plan.get("final_trigger")
    probe = FlowProbe(
        flow_id=str(flow.get("flow_id") or ""),
        sink_class=str(flow.get("sink_class") or "xss"),
        verdict=trigger.verdict,
        case_id=trigger.case_id,
        residue=trigger.residue,
        payload=payload,
        constraints=[dict(item) for item in constraints if isinstance(item, dict)],
        final_trigger=raw_final if isinstance(raw_final, dict) else {},
        evidence_refs=[str(ref) for ref in evidence_refs],
        notes=notes,
        stages=trigger.stages,
        trace=trigger.trace,
        report=trigger.report,
    )
    return probe, trigger
