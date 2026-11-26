"""Pipeline: main-agent loop over trigger slices.

The main agent keeps leasing the highest-score trigger slice. For each one the
trigger agent proves it reachable; only then does the pairing agent match
injection slices for that single proven slice; only then does the inject agent
walk the candidate queue. A failed stage never runs its downstream stages, but
the loop moves on to the next trigger slice.

The loop ends when the trigger queue is exhausted or the run hits its wall-clock
timeout. Pairing/verdict failures are data for the report, not loop ends.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.cap.entry import infer_read_entry
from tia.dom.direct import run_direct
from tia.dom.inject import run_inject
from tia.dom.main import seed_queue
from tia.dom.pairing_agent import PairingConfig, build_pairing_queue
from tia.dom.trigger import normalize_slice, run_trigger
from tia.inf.runtime import get_runtime
from tia.orch.kernel import ToolCallError, ToolClient
from tia.orch.learning import hints_for
from tia.schemas.objects import CaseOutcome


def _read_target(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the (file, line) the trigger agent proved reachable, if known."""

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
    if isinstance(probe_cfg, dict) and probe_cfg.get("line") and file:
        # The navi slice may carry the SQL read line; keep the app-relative file
        # from the slice because the analysis path is not mounted in the target.
        return {"file": file, "line": int(probe_cfg["line"])}
    if not file or not line:
        return None
    return {"file": file, "line": line}


def _read_entry(
    reader: Callable[[str, int, int], list[tuple[int, str]]] | None,
    raw: dict[str, Any],
) -> dict[str, Any] | None:
    """Infer the read page's own entry parameters (second-order read side)."""
    path = str(raw.get("sinkFile") or "")
    line = int(raw.get("sinkLine") or 0)
    if reader is None or not path or not line:
        return None
    try:
        lines = reader(path, max(1, line - 80), line + 10)
    except Exception:  # noqa: BLE001 - entry inference is best-effort
        return None
    text = "\n".join(str(text) for _, text in lines)
    method, fields = infer_read_entry(text)
    if not fields:
        return None
    return {
        "method": method,
        "fields": [
            {"name": field.name, "usage": field.usage, "numeric": field.numeric} for field in fields
        ],
    }


@dataclass
class PipelineResult:
    rounds: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[CaseOutcome] = field(default_factory=list)
    stop_reason: str = "DONE"
    report: str = ""


MODES = ("direct", "second", "direct-first", "second-first", "hybrid")


def pick_family(
    mode: str, direct_left: int, second_left: int, round_index: int
) -> str | None:
    """Choose which slice family to lease next.

    ``direct``/``second`` pin one family; the ``-first`` modes drain one family
    before touching the other; ``hybrid`` interleaves in proportion to what is
    still pending, so neither family starves while both have work.
    """
    if direct_left <= 0 and second_left <= 0:
        return None
    if mode == "direct":
        return "direct" if direct_left > 0 else None
    if mode == "second":
        return "second" if second_left > 0 else None
    if mode == "direct-first":
        return "direct" if direct_left > 0 else ("second" if second_left > 0 else None)
    if mode == "second-first":
        return "second" if second_left > 0 else ("direct" if direct_left > 0 else None)
    # hybrid: Bresenham-style proportional split of the remaining slices.
    if direct_left <= 0:
        return "second"
    if second_left <= 0:
        return "direct"
    total = direct_left + second_left
    before = (round_index * direct_left) // total
    after = ((round_index + 1) * direct_left) // total
    return "direct" if after > before else "second"


def _reader() -> Callable[[str, int, int], list[tuple[int, str]]] | None:
    try:
        from tia.ad.fs import FsAdapter

        adapter = FsAdapter(get_runtime().settings.app_root)
    except Exception:  # noqa: BLE001 - pairing degrades without the source tree
        return None

    def read(path: str, line_from: int, line_to: int) -> list[tuple[int, str]]:
        return list(adapter.read(path, line_from, line_to).lines)

    return read


async def run_pipeline(
    store: Any,
    trigger_run_id: str,
    trigger_slices: list[dict[str, Any]],
    write_slices: list[dict[str, Any]],
    base_url: str,
    *,
    timeout_sec: float = 600.0,
    max_slices: int = 0,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    queue_cap: int = 10,
    trigger_client: ToolClient | None = None,
    inject_client: ToolClient | None = None,
    url_for: Callable[[dict[str, Any]], str] | None = None,
    direct_slices: list[dict[str, Any]] | None = None,
    mode: str = "second",
) -> PipelineResult:
    """Loop over trigger/direct slices until the queue is empty or the timeout expires."""
    if mode not in MODES:
        raise ValueError(f"unknown mode: {mode!r} (expected one of {MODES})")
    result = PipelineResult()
    if mode != "direct":
        seed_queue(store, trigger_run_id, trigger_slices, order_mode="second")
    if mode != "second" and direct_slices:
        seed_queue(store, trigger_run_id, direct_slices, order_mode="direct")
    deadline = time.monotonic() + max(timeout_sec, 0.0)
    reader = _reader()

    while True:
        if time.monotonic() >= deadline:
            result.stop_reason = "TIMEOUT"
            break
        if max_slices and len(result.rounds) >= max_slices:
            result.stop_reason = "SLICE_LIMIT"
            break
        family = pick_family(
            mode,
            store.count_pending(trigger_run_id, "direct"),
            store.count_pending(trigger_run_id, "second"),
            len(result.rounds),
        )
        if family is None:
            result.stop_reason = "EXHAUSTED" if result.rounds else "NO_TRIGGER_SLICE"
            break
        leased = store.next_slice(run_id=trigger_run_id, order_mode=family)
        if leased is None:
            result.stop_reason = "EXHAUSTED" if result.rounds else "NO_TRIGGER_SLICE"
            break
        if family == "direct":
            await _run_direct_round(store, result, leased, base_url, url_for)
            continue

        round_index = len(result.rounds)
        raw = dict(leased["slice"])
        trigger_url = url_for(raw) if url_for is not None else base_url
        try:
            trigger = await run_trigger(
                normalize_slice(raw),
                base_url=trigger_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=trigger_client,
                slice_id=str(leased["id"]),
            )
        except ToolCallError as exc:
            # A broken slice must not stop the loop: archive it and pick the next.
            store.archive_slice(str(leased["id"]), "ERROR")
            result.rounds.append(
                {
                    "round": round_index,
                    "trigger_slice": str(leased["id"]),
                    "trigger_case": None,
                    "trigger_verdict": "ERROR",
                    "queue_items": 0,
                    "injections": [],
                    "stopped_at": "error",
                    "error": exc.envelope.model_dump(),
                }
            )
            continue
        store.archive_slice(str(leased["id"]), trigger.verdict, case_id=trigger.case_id)
        result.outcomes.append(
            CaseOutcome(
                slice_id=str(leased["id"]),
                case_id=trigger.case_id,
                verdict=trigger.verdict,
                evidence_refs=[step.evidence_ref for step in trigger.trace if step.evidence_ref],
                residue=trigger.residue or 0,
                notes={"stage": "trigger"},
                duration_ms=0,
            )
        )
        record: dict[str, Any] = {
            "round": round_index,
            "trigger_slice": str(leased["id"]),
            "trigger_case": trigger.case_id,
            "trigger_verdict": trigger.verdict,
            "queue_items": 0,
            "injections": [],
        }
        if trigger.verdict != "EXECUTED" or (trigger.residue or 0) != 0:
            # Not reachable: the rest of this chain is skipped, loop continues.
            record["stopped_at"] = "trigger"
            result.rounds.append(record)
            continue

        pair_run_id = f"{trigger_run_id}-pair-{round_index}"
        proven = store.get_slice(str(leased["id"]))
        pairing = build_pairing_queue(
            store,
            pair_run_id,
            write_slices,
            [proven] if proven is not None else [],
            reader=reader,
            config=PairingConfig(queue_cap=queue_cap),
        )
        record["queue_items"] = len(pairing.queue)
        if not pairing.queue:
            record["stopped_at"] = "pairing"
            result.rounds.append(record)
            continue

        try:
            injected = await walk_injection_queue(
                store,
                pair_run_id,
                base_url,
                payload_base=payload_base,
                budget=budget,
                inject_client=inject_client,
                url_for=url_for,
                payload_constraints=(trigger.notes or {}).get("payload_constraints"),
            )
        except ToolCallError as exc:
            record["stopped_at"] = "inject_error"
            record["error"] = exc.envelope.model_dump()
            result.rounds.append(record)
            continue
        record["injections"] = [
            {"item": item.slice_id, "verdict": item.verdict} for item in injected.outcomes
        ]
        result.outcomes.extend(injected.outcomes)
        result.rounds.append(record)

    result.report = _report(result)
    return result


async def _run_direct_round(
    store: Any,
    result: PipelineResult,
    leased: dict[str, Any],
    base_url: str,
    url_for: Callable[[dict[str, Any]], str] | None,
) -> None:
    """One first-order round: direct agent, no pairing, no injection queue."""
    round_index = len(result.rounds)
    raw = dict(leased["slice"])
    page_url = url_for(raw) if url_for is not None else base_url
    try:
        direct = await run_direct(
            normalize_slice(raw),
            base_url=page_url,
            slice_id=str(leased["id"]),
        )
    except ToolCallError as exc:
        store.archive_slice(str(leased["id"]), "ERROR")
        result.rounds.append(
            {
                "round": round_index,
                "stage": "direct",
                "trigger_slice": str(leased["id"]),
                "trigger_case": None,
                "trigger_verdict": "ERROR",
                "queue_items": 0,
                "injections": [],
                "stopped_at": "error",
                "error": exc.envelope.model_dump(),
            }
        )
        return
    store.archive_slice(str(leased["id"]), direct.verdict, case_id=direct.case_id)
    result.outcomes.append(
        CaseOutcome(
            slice_id=str(leased["id"]),
            case_id=direct.case_id,
            verdict=direct.verdict,
            evidence_refs=[step.evidence_ref for step in direct.trace if step.evidence_ref],
            residue=direct.residue or 0,
            notes={"stage": "direct", "attempts": len(direct.notes.get("attempts") or [])},
            duration_ms=0,
        )
    )
    result.rounds.append(
        {
            "round": round_index,
            "stage": "direct",
            "trigger_slice": str(leased["id"]),
            "trigger_case": direct.case_id,
            "trigger_verdict": direct.verdict,
            "queue_items": 0,
            "injections": [],
            "stopped_at": None,
        }
    )


async def walk_injection_queue(
    store: Any,
    pair_run_id: str,
    base_url: str,
    *,
    payload_base: str,
    budget: int,
    inject_client: ToolClient | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    reader: Callable[[str, int, int], list[tuple[int, str]]] | None = None,
    payload_constraints: dict[str, Any] | None = None,
) -> PipelineResult:
    """Inject every candidate in queue order; the read side is already proven."""
    result = PipelineResult()
    while True:
        item = store.next_injection_item(pair_run_id)
        if item is None:
            break
        write_row = store.get_slice(str(item["write_slice_id"]))
        if write_row is None:
            store.archive_injection_item(str(item["item_id"]), "MISSING_SLICE")
            continue
        write_raw = dict(write_row["slice"])
        write_url = url_for(write_raw) if url_for is not None else base_url
        read_row = store.get_slice(str(item["read_slice_id"]))
        read_raw = dict(read_row["slice"]) if read_row is not None else {}
        read_url = url_for(read_raw) if (url_for is not None and read_raw) else base_url
        entry = _read_entry(reader, read_raw) if read_raw else None
        hint = {
            "pair_id": item["pair_id"],
            "table": item["table"],
            "columns": item["columns"],
            "confidence": item["score"],
            "direction": item["direction"],
        }
        inject = await run_inject(
            write_raw,
            base_url=write_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=inject_client,
            pair_hints=[hint],
            verify_url=read_url,
            verify_entry=entry,
            payload_constraints=payload_constraints,
            slice_id=str(item["write_slice_id"]),
            learning=hints_for(store, read_raw or write_raw),
            read_target=_read_target(read_raw),
        )
        store.archive_injection_item(str(item["item_id"]), inject.verdict, case_id=inject.case_id)
        store.archive_slice(str(item["write_slice_id"]), inject.verdict, case_id=inject.case_id)
        result.outcomes.append(
            CaseOutcome(
                slice_id=str(item["item_id"]),
                case_id=inject.case_id,
                verdict=inject.verdict,
                evidence_refs=[step.evidence_ref for step in inject.trace if step.evidence_ref],
                residue=inject.residue or 0,
                notes={
                    "stage": "inject",
                    "pair_score": item["score"],
                    "table": item["table"],
                    "columns": item["columns"],
                },
                duration_ms=0,
            )
        )
    return result


def _report(result: PipelineResult) -> str:
    lines = [
        "# TIA Pipeline Report",
        "",
        f"- Rounds: {len(result.rounds)}",
        f"- Stop reason: {result.stop_reason}",
        "",
        "| Stage | Slice | Verdict |",
        "| --- | --- | --- |",
    ]
    for item in result.outcomes:
        lines.append(f"| {item.notes.get('stage', '')} | {item.slice_id} | {item.verdict} |")
    return "\n".join(lines)
