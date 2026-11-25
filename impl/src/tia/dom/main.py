"""Main agent: slice queue → trigger → inject → archive (deterministic version of M0–M6).

First get the "scheduling + archiving" main path working: queue ordering, budget, consecutive failure circuit breaker, DONE determination.
LLM planner (reasoning for slice selection) can be added later, simply replacing :func:`pick`; tool semantics remain unchanged.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from tia.dom.inject import run_inject
from tia.dom.trigger import normalize_slice, run_trigger
from tia.orch.kernel import ToolClient
from tia.schemas.objects import CaseOutcome


@dataclass
class MainResult:
    outcomes: list[CaseOutcome] = field(default_factory=list)
    stop_reason: str = "DONE"
    report: str = ""


def slice_id(raw: dict[str, Any], index: int) -> str:
    explicit = raw.get("slice_id")
    if explicit:
        return str(explicit)
    sink = raw.get("sink") or raw.get("sinkFile") or f"slice-{index}"
    text = str(sink)
    return f"slice-{index:03d}-{abs(hash(text)) % 10000:04d}"


def pick(slices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Candidate ranking: untried first, then cluster by sink kind and file path, finally stable lexicographic order."""

    def key(item: tuple[int, dict[str, Any]]) -> tuple[int, str, str]:
        index, raw = item
        return (int(raw.get("attempts") or 0), str(raw.get("kind") or ""), str(raw.get("sinkFile") or raw.get("sink") or index))

    return [raw for _, raw in sorted(enumerate(slices), key=key)]


async def run_main(
    raw_slices: list[dict[str, Any]],
    base_url: str,
    limit: int = 1,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    trigger_client: ToolClient | None = None,
    inject_client: ToolClient | None = None,
    max_consecutive_failures: int = 3,
) -> MainResult:
    result = MainResult()
    failures = 0
    for order, raw in enumerate(pick(raw_slices)[: max(limit, 0)]):
        started = time.monotonic()
        sid = slice_id(raw, order)
        trigger = await run_trigger(
            normalize_slice(raw),
            base_url=base_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=trigger_client,
        )
        notes = {"trigger": trigger.verdict, "trigger_case": trigger.case_id}
        if trigger.verdict == "EXECUTED" and trigger.residue == 0:
            inject = await run_inject(
                raw,
                base_url=base_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=inject_client,
            )
            refs = [step.evidence_ref for step in inject.trace if step.evidence_ref]
            outcome = CaseOutcome(
                slice_id=sid,
                case_id=inject.case_id,
                verdict=inject.verdict,
                evidence_refs=refs,
                residue=inject.residue or 0,
                notes={**notes, "inject": inject.verdict, "inject_case": inject.case_id},
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        else:
            refs = [step.evidence_ref for step in trigger.trace if step.evidence_ref]
            outcome = CaseOutcome(
                slice_id=sid,
                case_id=trigger.case_id,
                verdict=trigger.verdict,
                evidence_refs=refs,
                residue=trigger.residue or 0,
                notes=notes,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        result.outcomes.append(outcome)
        if outcome.verdict in {"EXECUTED", "NOT_EXECUTABLE", "WRITTEN_NOT_VISIBLE"}:
            failures = 0
        else:
            failures += 1
            if failures >= max_consecutive_failures:
                result.stop_reason = "BLOCKED_NEEDS_HUMAN"
                break
    result.report = _report(result)
    return result


def _report(result: MainResult) -> str:
    lines = [
        "# TIA Scheduling Report",
        "",
        f"- Attempted slices: {len(result.outcomes)}",
        f"- Stop reason: {result.stop_reason}",
        "",
        "| Slice | Conclusion | residue | Description |",
        "| --- | --- | --- | --- |",
    ]
    for item in result.outcomes:
        detail = ", ".join(f"{key}={value}" for key, value in item.notes.items())
        lines.append(f"| {item.slice_id} | {item.verdict} | {item.residue} | {detail} |")
    return "\n".join(lines)
