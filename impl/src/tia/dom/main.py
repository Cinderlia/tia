"""Main agent: slice queue → trigger → inject → archive (deterministic version of M0–M6).

First get the "scheduling + archiving" main path working: queue ordering, budget, consecutive failure circuit breaker, DONE determination.
LLM planner (reasoning for slice selection) can be added later, simply replacing :func:`pick`; tool semantics remain unchanged.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.ad.fs import FsAdapter
from tia.dom.inject import run_inject
from tia.dom.trigger import normalize_slice, run_trigger
from tia.inf.runtime import get_runtime
from tia.orch.kernel import ToolClient
from tia.orch.learning import hints_for
from tia.orch.pairing import Reader, resolve_entry
from tia.orch.slicing import score_slice
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
    ordered = pick(raw_slices)
    attempted = ordered[: max(limit, 0)]
    for order, raw in enumerate(attempted):
        started = time.monotonic()
        sid = slice_id(raw, order)
        trigger = await run_trigger(
            normalize_slice(raw),
            base_url=base_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=trigger_client,
            slice_id=sid,
        )
        notes: dict[str, Any] = {"trigger": trigger.verdict, "trigger_case": trigger.case_id}
        if trigger.verdict == "EXECUTED" and trigger.residue == 0:
            inject = await run_inject(
                raw,
                base_url=base_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=inject_client,
                slice_id=sid,
                learning=hints_for(get_runtime().store, raw),
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
        if outcome.verdict in {
            "EXECUTED",
            "EXECUTABLE",
            "NOT_EXECUTABLE",
            "WRITTEN_NOT_VISIBLE",
        }:
            failures = 0
        else:
            failures += 1
            if failures >= max_consecutive_failures:
                result.stop_reason = "BLOCKED_NEEDS_HUMAN"
                break
    if result.stop_reason == "DONE" and len(ordered) > len(attempted):
        result.stop_reason = "LIMIT_REACHED"
    result.report = _report(result)
    return result


async def run_injection_queue(
    queue_store: Any,
    base_url: str,
    run_id: str | None = None,
    limit: int = 100,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    trigger_client: ToolClient | None = None,
    inject_client: ToolClient | None = None,
    url_for: Callable[[dict[str, Any]], str] | None = None,
) -> MainResult:
    """Walk the pairing queue: trigger the read slice, inject the paired write slice.

    Only matched read/write candidates are queued, so the trigger agent never
    receives an unrelated slice. The walk continues after a success (the queue
    is a candidate list, not a search for the first hit) and stops only when
    the queue is exhausted or the time-control limit is reached.
    """
    result = MainResult()
    for _ in range(max(limit, 0)):
        item = queue_store.next_injection_item(run_id)
        if item is None:
            result.stop_reason = "DONE"
            break
        read_row = queue_store.get_slice(str(item["read_slice_id"]))
        write_row = queue_store.get_slice(str(item["write_slice_id"]))
        if read_row is None or write_row is None:
            queue_store.archive_injection_item(str(item["item_id"]), "MISSING_SLICE")
            continue
        read_raw = dict(read_row["slice"])
        write_raw = dict(write_row["slice"])
        read_url = url_for(read_raw) if url_for is not None else base_url
        write_url = url_for(write_raw) if url_for is not None else base_url
        started = time.monotonic()
        trigger = await run_trigger(
            normalize_slice(read_raw),
            base_url=read_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=trigger_client,
            slice_id=str(item["read_slice_id"]),
        )
        notes: dict[str, Any] = {
            "item": item["item_id"],
            "pair_score": item["score"],
            "table": item["table"],
            "columns": item["columns"],
            "direction": item["direction"],
            "trigger": trigger.verdict,
            "trigger_case": trigger.case_id,
        }
        inject_verdict = ""
        case_id = trigger.case_id
        residue = trigger.residue or 0
        refs = [step.evidence_ref for step in trigger.trace if step.evidence_ref]
        if trigger.verdict == "EXECUTED" and trigger.residue == 0:
            hint = {
                "pair_id": item["pair_id"],
                "table": item["table"],
                "columns": item["columns"],
                "confidence": item["score"],
                "direction": item["direction"],
                "peer_slice_id": str(item["read_slice_id"]),
            }
            inject = await run_inject(
                write_raw,
                base_url=write_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=inject_client,
                learning=hints_for(queue_store, read_raw),
                pair_hints=[hint],
                slice_id=str(item["write_slice_id"]),
                read_target=_read_target(read_raw, trigger.notes),
            )
            inject_verdict = inject.verdict
            case_id = inject.case_id
            residue = inject.residue or 0
            refs = refs + [step.evidence_ref for step in inject.trace if step.evidence_ref]
            notes["inject"] = inject.verdict
            notes["inject_case"] = inject.case_id
        verdict = inject_verdict or trigger.verdict
        queue_store.archive_injection_item(str(item["item_id"]), verdict, case_id=case_id)
        queue_store.archive_slice(str(item["read_slice_id"]), trigger.verdict, case_id=trigger.case_id)
        queue_store.archive_slice(
            str(item["write_slice_id"]), inject_verdict or "NOT_EXECUTED", case_id=case_id
        )
        result.outcomes.append(
            CaseOutcome(
                slice_id=str(item["item_id"]),
                case_id=case_id,
                verdict=verdict,
                evidence_refs=[ref for ref in refs if ref],
                residue=residue,
                notes=notes,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        )
    else:
        if queue_store.next_injection_item(run_id) is not None:
            result.stop_reason = "LIMIT_REACHED"
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


def _sink_file(raw: dict[str, Any]) -> str:
    sink_value = raw.get("sink")
    sink: dict[str, Any] = sink_value if isinstance(sink_value, dict) else {}
    return str(sink.get("file") or raw.get("sinkFile") or "")


def _source_reader() -> Reader | None:
    """Read-only source window from ``app_root``; pairing degrades without it."""
    try:
        adapter = FsAdapter(get_runtime().settings.app_root)
    except Exception:  # noqa: BLE001 - pairing is optional, the queue still works
        return None

    def read(path: str, line_from: int, line_to: int) -> list[tuple[int, str]]:
        return adapter.read(path, line_from, line_to).lines

    return read


def _read_target(
    raw: dict[str, Any] | None,
    notes: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the trigger-proven (file, line), if the slice carries one."""

    if not raw:
        return None
    probe = raw.get("sqlProbe")
    probe_cfg = probe.get("extensionConfig") if isinstance(probe, dict) else None
    raw_sink = raw.get("sink")
    sink: dict[str, Any] = raw_sink if isinstance(raw_sink, dict) else {}
    file = str(raw.get("sinkFile") or sink.get("file") or "")
    line = int(raw.get("sinkLine") or sink.get("line") or 0)
    if not file and ":" in str(raw.get("sink") or ""):
        path, _, number = str(raw.get("sink")).rpartition(":")
        file = path
        line = int(number) if number.isdigit() else 0
    if not file:
        return None
    from_notes = int((notes or {}).get("read_line") or 0)
    if from_notes > 0:
        return {"file": file, "line": from_notes}
    if isinstance(probe_cfg, dict) and probe_cfg.get("line"):
        # Debug dumps carry the SQL read line; keep the app-relative file from
        # the slice because the analysis path is not mounted in the target.
        return {"file": file, "line": int(probe_cfg["line"])}
    if not line:
        return None
    return {"file": file, "line": line}


def seed_queue(
    queue_store: Any,
    run_id: str,
    slices: list[dict[str, Any]],
    *,
    order_mode: str = "second",
) -> list[str]:
    """Seed slices (score only); pairing runs later, on proven second-order slices.

    ``order_mode`` is dictated by where the slice came from (the navi ``direct/``
    tree versus the joined/inject trees), never inferred from slice features.
    """
    usable = [raw for raw in slices if _sink_file(raw)]
    ids = queue_store.seed_slices(run_id, usable, order_mode=order_mode)
    history = queue_store.verdict_history()
    for index, (slice_id_, raw) in enumerate(zip(ids, usable, strict=False)):
        entry = resolve_entry(raw, index)
        scored = score_slice(
            raw,
            paired=False,
            history=history.get(f"{entry.file}:{entry.line}", []),
            order_mode=order_mode,
            learning=hints_for(queue_store, raw),
        )
        queue_store.set_slice_score(slice_id_, scored.score, scored.reasons, scored.digest)
    return [str(item) for item in ids]


def _switch_target(
    queue_store: Any,
    run_id: str | None,
    pairs: list[dict[str, Any]],
    seen: set[str],
) -> dict[str, Any] | None:
    """Lease the paired peer of a pair hint (highest confidence first)."""
    for pair in pairs:
        peer_id = str(pair.get("peer_slice_id") or "")
        if not peer_id or peer_id in seen:
            continue
        row = queue_store.lease_slice(peer_id)
        if row is None:
            continue
        if run_id and str(row.get("run_id")) != run_id:
            queue_store.skip_slice(peer_id, f"run mismatch: {row.get('run_id')}", status="pending")
            continue
        return dict(row)
    return None


async def run_queue(
    queue_store: Any,
    base_url: str,
    run_id: str | None = None,
    limit: int = 10,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    trigger_client: ToolClient | None = None,
    inject_client: ToolClient | None = None,
    max_consecutive_failures: int = 3,
    max_switches: int = 3,
    url_for: Callable[[dict[str, Any]], str] | None = None,
    trigger_only: bool = False,
) -> MainResult:
    """M0->M6 over the persisted queue: lease, run, archive; the queue is the source of truth.

    When injection on one slice proves futile, the agent may hop to a paired
    slice (a read/write hint of the same table and column) instead of walking
    the queue blindly. Switch hops are bounded by ``max_switches``.
    """
    result = MainResult()
    failures = 0
    switches = 0
    seen: set[str] = set()
    leased: dict[str, Any] | None = None
    for _ in range(max(limit, 0)):
        item = leased if leased is not None else queue_store.next_slice(run_id=run_id)
        leased = None
        if item is None:
            result.stop_reason = "DONE"
            break
        raw = item["slice"]
        sid = str(item["id"])
        seen.add(sid)
        pairs = queue_store.pairs_for_slice(sid, limit=3)
        page_url = url_for(raw) if url_for is not None else base_url
        started = time.monotonic()
        trigger = await run_trigger(
            normalize_slice(raw),
            base_url=page_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=trigger_client,
            slice_id=sid,
        )
        notes: dict[str, Any] = {"trigger": trigger.verdict, "trigger_case": trigger.case_id}
        if pairs:
            notes["pairs"] = [
                {
                    "pair_id": pair["pair_id"],
                    "confidence": pair["confidence"],
                    "side": pair.get("side"),
                    "peer": pair.get("peer_slice_id"),
                    "table": pair["table"],
                    "columns": pair["columns"],
                }
                for pair in pairs
            ]
        injected = False
        if not trigger_only and trigger.verdict == "EXECUTED" and trigger.residue == 0:
            injected = True
            inject = await run_inject(
                raw,
                base_url=page_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=inject_client,
                pair_hints=pairs,
                slice_id=sid,
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
        queue_store.archive_slice(sid, outcome.verdict, case_id=outcome.case_id)
        if outcome.verdict not in {"EXECUTED", "EXECUTABLE", "NOT_EXECUTABLE", "WRITTEN_NOT_VISIBLE"}:
            # Demote failures so lower-quality slices fall behind on the next read.
            queue_store.bump_slice_score(sid, -15)
        if (
            injected
            and outcome.verdict not in {"EXECUTABLE", "EXECUTED"}
            and switches < max_switches
        ):
            peer = _switch_target(queue_store, run_id, pairs, seen)
            if peer is not None:
                switches += 1
                outcome.notes["switched_to"] = str(peer["id"])
                leased = peer
        result.outcomes.append(outcome)
        if outcome.verdict in {"EXECUTED", "EXECUTABLE", "NOT_EXECUTABLE", "WRITTEN_NOT_VISIBLE"}:
            failures = 0
        elif not trigger_only:
            # In trigger-only mode a non-reflecting slice is data, not a blocker:
            # the pairing stage only consumes the ones that proved reachable.
            failures += 1
            if failures >= max_consecutive_failures:
                result.stop_reason = "BLOCKED_NEEDS_HUMAN"
                break
    else:
        if leased is not None or queue_store.next_slice(run_id=run_id) is not None:
            result.stop_reason = "LIMIT_REACHED"
    result.report = _report(result)
    return result
