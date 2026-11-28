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

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.cap.entry import infer_read_entry
from tia.dom.direct import run_direct
from tia.dom.inject import run_inject
from tia.dom.main import seed_queue
from tia.dom.pairing_agent import PairingConfig, build_pairing_queue, respond
from tia.dom.trigger import normalize_slice, run_trigger
from tia.inf.findings import finding_db_only, finding_first_order, finding_second_order
from tia.inf.reports import RunReports
from tia.inf.runtime import get_runtime
from tia.orch.kernel import ToolCallError, ToolClient
from tia.orch.learning import hints_for
from tia.schemas.objects import CaseOutcome

_RETRYABLE_INJECT = frozenset(
    {"WRITE_NOT_REACHED", "WRITE_NOT_REACHED_ENV", "ENV_ERROR", "TIMEOUT", "PATH_UNREACHABLE"}
)



def _read_target(
    raw: dict[str, Any] | None,
    notes: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the (file, line) the trigger agent proved reachable, if known.

    The NAVI chain contract no longer ships the debug ``sqlProbe`` block, so the
    read line recorded by the trigger agent (``notes["read_line"]``) is the
    primary source; the debug hint stays as a fallback for old dumps.
    """

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
        # The navi slice may carry the SQL read line; keep the app-relative file
        # from the slice because the analysis path is not mounted in the target.
        return {"file": file, "line": int(probe_cfg["line"])}
    if not line:
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
    report_path: str = ""


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
    reports = RunReports(store, trigger_run_id)
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
            await _run_direct_round(store, result, leased, base_url, url_for, reports)
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
        reports.add(trigger.case_id, "trigger", trigger.verdict, _slice_label(raw))
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
            finding_db_only(store, trigger.case_id)
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
                reader=reader,
                payload_constraints=(trigger.notes or {}).get("payload_constraints"),
                constraint_plan=(trigger.notes or {}).get("constraint_plan"),
                read_values=(trigger.notes or {}).get("read_entry_values"),
                read_notes=trigger.notes or {},
            )
        except ToolCallError as exc:
            record["stopped_at"] = "inject_error"
            record["error"] = exc.envelope.model_dump()
            result.rounds.append(record)
            continue
        except Exception as exc:  # noqa: BLE001 - keep the pipeline alive across one bad candidate
            record["stopped_at"] = "inject_error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            result.rounds.append(record)
            continue
        record["injections"] = [
            {"item": item.slice_id, "verdict": item.verdict} for item in injected.outcomes
        ]
        result.outcomes.extend(injected.outcomes)
        confirmed = [
            item for item in injected.outcomes if item.verdict in ("EXECUTABLE", "EXECUTED")
        ]
        for outcome in confirmed:
            finding_second_order(store, outcome.case_id)
        if not confirmed:
            finding_db_only(store, trigger.case_id)
        for outcome in injected.outcomes:
            reports.add(
                outcome.case_id,
                "inject",
                outcome.verdict,
                f"{outcome.notes.get('table', '?')}.{_columns_label(outcome.notes.get('columns'))}",
            )
        result.rounds.append(record)

    index = reports.finish(result.stop_reason, len(result.rounds), len(result.outcomes))
    result.report_path = str(index)
    result.report = _report(result)
    return result


async def _run_direct_round(
    store: Any,
    result: PipelineResult,
    leased: dict[str, Any],
    base_url: str,
    url_for: Callable[[dict[str, Any]], str] | None,
    reports: RunReports,
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
    reports.add(direct.case_id, "direct", direct.verdict, _slice_label(raw))
    if direct.verdict == "EXECUTED":
        finding_first_order(store, direct.case_id)
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



async def _prepare_constraints(
    store: Any,
    run_id: str,
    read_slice_id: str,
    plan: dict[str, Any] | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    base_url: str,
) -> dict[str, list[dict[str, Any]]]:
    """Ask the pairing agent for a write slice per database-branch condition."""
    constraints = list((plan or {}).get("constraints") or [])
    if not constraints:
        return {}
    requests: list[str] = []
    for constraint in constraints:
        request = store.add_pair_request(
            run_id=run_id,
            read_slice_id=read_slice_id,
            kind="constraint",
            table=str(constraint.get("table") or ""),
            column=str(constraint.get("column") or ""),
            op=str(constraint.get("op") or "set"),
            value=str(constraint.get("value") or ""),
            direction="payload_then_write",
        )
        requests.append(str(request))
    await respond(store, run_id)
    mapping: dict[str, list[dict[str, Any]]] = {}
    for constraint, request_id in zip(constraints, requests, strict=False):
        row = store.get_pair_request(request_id) or {}
        options: list[dict[str, Any]] = []
        for candidate in row.get("candidates") or []:
            slice_id = str(candidate.get("write_slice_id") or "")
            option = dict(candidate)
            option["page_url"] = base_url
            if url_for is not None:
                write_row = store.get_slice(slice_id)
                if write_row is not None:
                    option["page_url"] = url_for(dict(write_row["slice"]))
            options.append(option)
        mapping[str(constraint.get("constraint_id") or "")] = options
    return mapping


def _chain_with_raw(store: Any, item: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for step in item.get("chain") or []:
        row = store.get_slice(str(step.get("write_slice_id") or ""))
        if row is None:
            continue
        walked = dict(step)
        walked["raw"] = row["slice"]
        steps.append(walked)
    return steps


def _copy_paths_with_raw(
    store: Any, item: dict[str, Any], url_for: Callable[[dict[str, Any]], str] | None
) -> list[dict[str, Any]]:
    """Attach each hop's slice payload and page URL to the queue's copy paths."""
    paths: list[dict[str, Any]] = []
    for path in (item.get("copy_paths") or [])[:2]:
        hops: list[dict[str, Any]] = []
        for hop in path.get("hops") or []:
            row = store.get_slice(str(hop.get("write_slice_id")))
            raw = dict(row["slice"]) if row is not None else {}
            hops.append(
                {
                    **hop,
                    "raw": raw,
                    "url": url_for(raw) if (url_for is not None and raw) else "",
                }
            )
        paths.append({**path, "hops": hops})
    return paths


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
    read_values: dict[str, str] | None = None,
    constraint_plan: dict[str, Any] | None = None,
    read_notes: dict[str, Any] | None = None,
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
        pair_map = await _prepare_constraints(
            store,
            pair_run_id,
            str(item["read_slice_id"]),
            constraint_plan,
            url_for,
            read_url,
        )
        copy_paths = _copy_paths_with_raw(store, item, url_for)
        hint = {
            "pair_id": item["pair_id"],
            "table": item["table"],
            "columns": item["columns"],
            "confidence": item["score"],
            "direction": item["direction"],
        }
        # Duplicate slices of the same site stay as alternates: if the primary
        # attempt fails before reaching the sink, one alternate gets a chance.
        hints = [hint]
        for alternate in (item.get("alternates") or [])[:1]:
            hints.append(
                {
                    "pair_id": alternate.get("pair_id") or item["pair_id"],
                    "table": item["table"],
                    "columns": item["columns"],
                    "confidence": alternate.get("score") or item["score"],
                    "direction": item["direction"],
                    "alternate_write_slice_id": alternate.get("write_slice_id"),
                }
            )
        inject = await run_inject(
            write_raw,
            base_url=write_url,
            payload_base=payload_base,
            budget=min(budget, 40),
            client=inject_client,
            pair_hints=hints[:1],
            verify_url=read_url,
            verify_entry=entry,
            verify_values=read_values,
            payload_constraints=payload_constraints,
            slice_id=str(item["write_slice_id"]),
            learning=hints_for(store, read_raw or write_raw),
            read_target=_read_target(read_raw, read_notes),
            constraint_plan=constraint_plan,
            pair_candidates=pair_map,
            copy_paths=copy_paths,
            copy_only=item.get("kind") == "copy",
            chain_steps=(
                _chain_with_raw(store, item) if item.get("kind") == "chain" else None
            ),
            chain_only=item.get("kind") == "chain",
        )
        if (
            len(hints) > 1
            and inject.verdict in _RETRYABLE_INJECT
            and hints[1].get("alternate_write_slice_id")
        ):
            alternate_raw = store.get_slice(str(hints[1]["alternate_write_slice_id"]))
            if alternate_raw is not None:
                retry = await run_inject(
                    dict(alternate_raw["slice"]),
                    base_url=write_url,
                    payload_base=payload_base,
                    budget=min(budget, 40),
                    client=inject_client,
                    pair_hints=hints[1:],
                    verify_url=read_url,
                    verify_entry=entry,
                    verify_values=read_values,
                    payload_constraints=payload_constraints,
                    slice_id=str(hints[1]["alternate_write_slice_id"]),
                    learning=hints_for(store, read_raw or write_raw),
                    read_target=_read_target(read_raw, read_notes),
                    constraint_plan=constraint_plan,
                    pair_candidates=pair_map,
                    copy_paths=copy_paths,
                    copy_only=item.get("kind") == "copy",
                    chain_steps=(
                        _chain_with_raw(store, item) if item.get("kind") == "chain" else None
                    ),
                    chain_only=item.get("kind") == "chain",
                )
                inject.notes["alternate_attempt"] = {
                    "slice_id": hints[1]["alternate_write_slice_id"],
                    "verdict": retry.verdict,
                }
                if retry.verdict in ("EXECUTABLE", "EXECUTED"):
                    inject = retry
                store.archive_slice(
                    str(hints[1]["alternate_write_slice_id"]), retry.verdict,
                    case_id=retry.case_id,
                )
        read_sink = _slice_label(read_raw) if read_raw else ""
        extra = {
            "read_url": read_url,
            "read_sink": read_sink,
            "read_sink_code": str((read_raw.get("sink") or {}).get("code") or "")
            if isinstance(read_raw.get("sink"), dict)
            else str(read_raw.get("sinkCode") or ""),
        }
        inject.notes.update(extra)
        if inject.case_id:
            store.merge_case_notes(inject.case_id, extra)
        store.archive_injection_item(str(item["item_id"]), inject.verdict, case_id=inject.case_id)
        store.archive_slice(str(item["write_slice_id"]), inject.verdict, case_id=inject.case_id)
        read_identity = str(item.get("read_identity") or "")
        write_identity = str(item.get("write_identity") or "")
        if inject.verdict in ("EXECUTABLE", "EXECUTED") and read_identity and write_identity:
            store.record_conclusion(read_identity, write_identity, inject.verdict, inject.case_id)
            store.close_identity_group(read_identity, inject.verdict, inject.case_id,
                                       keep=str(item["read_slice_id"]))
            store.close_identity_group(write_identity, inject.verdict, inject.case_id,
                                       keep=str(item["write_slice_id"]))
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


def _columns_label(value: Any) -> str:
    """Render a column set compactly (it may arrive as JSON text or a list)."""
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    text = str(value or "?")
    try:
        parsed = json.loads(text.replace("'", '"'))
    except (ValueError, TypeError):
        return text
    if isinstance(parsed, list):
        return ",".join(str(item) for item in parsed)
    return text


def _slice_label(raw: dict[str, Any]) -> str:
    """Short human label for a slice in the run index (``file:line``)."""
    sink = raw.get("sink")
    if isinstance(sink, dict):
        return f"{sink.get('file', '?')}:{sink.get('line', '?')}"
    file = str(raw.get("sinkFile") or raw.get("sink") or "?")
    line = raw.get("sinkLine")
    return f"{file}:{line}" if line else file


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
