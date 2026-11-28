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

import asyncio
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tia.cap.entry import infer_read_entry
from tia.cap.read_evidence import collect_read_sql
from tia.cap.scoring import (
    CANDIDATE_PROMPT,
    CONFIRMED_SCORE,
    compact,
    score_records,
)
from tia.dom.direct import run_direct
from tia.dom.inject import run_inject
from tia.dom.lanes import publish_pairing, start_workers
from tia.dom.main import seed_queue
from tia.dom.pairing_agent import PairingConfig, build_pairing_queue, respond
from tia.dom.trigger import normalize_slice, run_trigger
from tia.inf.findings import finding_db_only, finding_first_order
from tia.inf.queue_probe import QUEUE_LOG_ENV, QueueProbe
from tia.inf.reports import RunReports
from tia.inf.runtime import get_runtime
from tia.orch.kernel import LocalToolClient, ToolCallError, ToolClient
from tia.orch.learning import hints_for
from tia.orch.slicing import score_slice, slice_digest
from tia.schemas.objects import CaseOutcome
from tia.sinks.registry import sink_class_for

_RETRYABLE_INJECT = frozenset(
    {"WRITE_NOT_REACHED", "WRITE_NOT_REACHED_ENV", "ENV_ERROR", "TIMEOUT", "PATH_UNREACHABLE"}
)


def _default_scorer() -> Any | None:
    """The LLM that turns slice facts into a prior; disabled with TIA_SLICE_SCORING=0."""
    if os.environ.get("TIA_SLICE_SCORING", "1").strip().lower() in {"0", "off", "false", "no"}:
        return None
    try:
        from tia.ad.llm import LlmClient

        return LlmClient.from_env()
    except Exception:  # noqa: BLE001 - a missing model only leaves the local prior
        return None


def _history_for(history: dict[str, list[str]], raw: dict[str, Any]) -> list[str]:
    digest = slice_digest(raw)
    key = f"{digest['sink']['file']}:{digest['sink']['line']}"
    return list(history.get(key, []))[:5]


def _already_ran(history: list[str]) -> bool:
    return any(verdict in {"EXECUTED", "EXECUTABLE"} for verdict in history)


async def _score_seeded_slices(store: Any, run_id: str, *, scorer: Any | None = None) -> int:
    """Ask the model to score every pending slice before the consumers start.

    A site that already executed is pinned at 100 without a model call; the model
    never sees those, so it cannot overrule a fact.
    """
    if scorer is None:
        return 0
    rows = [row for row in store.list_slice_rows(run_id=run_id) if row.get("status") == "pending"]
    if not rows:
        return 0
    history = store.verdict_history()
    records: list[dict[str, Any]] = []
    digests: dict[str, dict[str, Any]] = {}
    for row in rows:
        raw = dict(row.get("slice") or {})
        slice_id = str(row.get("id") or "")
        digest = slice_digest(raw)
        past = _history_for(history, raw)
        if _already_ran(past):
            store.set_slice_score(
                slice_id,
                CONFIRMED_SCORE,
                ["100 confirmed: this site already executed in an earlier run"],
                digest,
            )
            continue
        prior = score_slice(
            raw,
            history=past,
            order_mode=str(row.get("order_mode") or "second"),
            learning=hints_for(store, raw),
        )
        records.append(
            {
                "id": slice_id,
                "prompt": {
                    "slice_id": slice_id,
                    "order_mode": row.get("order_mode"),
                    "kind": digest["kind"],
                    "slice": compact(raw),
                    "history": past,
                    "learning": hints_for(store, raw),
                    "local_prior": {"score": prior.score, "reasons": prior.reasons[:8]},
                },
                "fallback": {"score": prior.score, "reason": "model silent; local prior kept"},
            }
        )
        digests[slice_id] = digest
    if not records:
        return 0
    results = await score_records(scorer, records)
    for slice_id, value in results.items():
        digest_value = digests.get(slice_id)
        if digest_value is None:
            continue
        store.set_slice_score(
            slice_id,
            int(value["score"]),
            [f"{value['score']} ({value['band']}): {value['reason']}"],
            digest_value,
        )
    return len(results)


async def _score_pairing_candidates(
    store: Any,
    pairing: Any,
    proven_raw: dict[str, Any],
    *,
    scorer: Any | None = None,
) -> int:
    """Score (read slice + write slice) candidates before they enter the lanes."""
    if scorer is None or not getattr(pairing, "queue", None):
        return 0
    history = store.verdict_history()
    records: list[dict[str, Any]] = []
    items: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(pairing.queue):
        candidate_id = str(item.get("item_id") or f"cand-{index}")
        write_row = store.get_slice(str(item.get("write_slice_id") or "")) or {}
        write_raw = dict(write_row.get("slice") or {})
        past = _history_for(history, write_raw)
        if _already_ran(past):
            item["score"] = CONFIRMED_SCORE
            item["reasons"] = list(item.get("reasons") or []) + ["100 confirmed: write site already ran"]
            continue
        records.append(
            {
                "id": candidate_id,
                "prompt": {
                    "candidate_id": candidate_id,
                    "read_slice": compact(proven_raw),
                    "write_slice": compact(write_raw),
                    "match": {
                        "table": item.get("table_name"),
                        "columns": item.get("columns"),
                        "confidence": item.get("confidence"),
                        "direction": item.get("direction"),
                        "reasons": list(item.get("reasons") or [])[:6],
                    },
                    "history": past,
                    "local_prior": {"score": item.get("score")},
                },
                "fallback": {"score": item.get("score") or 0, "reason": "model silent; pairing prior kept"},
            }
        )
        items[candidate_id] = item
    if not records:
        return 0
    results = await score_records(scorer, records, prompt=CANDIDATE_PROMPT)
    for candidate_id, value in results.items():
        item = items.get(candidate_id)
        if item is None:
            continue
        item["score"] = int(value["score"])
        item["reasons"] = list(item.get("reasons") or []) + [
            f"{value['score']} ({value['band']}): {value['reason']}"
        ]
    pairing.queue.sort(key=lambda entry: -int(entry.get("score") or 0))
    return len(results)




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



async def _constraint_plan_for(
    store: Any,
    client: ToolClient,
    raw: dict[str, Any],
    *,
    trigger: Any,
    pair_run_id: str,
    pairing: Any,
    base_url: str,
    url_for: Callable[[dict[str, Any]], str] | None,
) -> dict[str, Any]:
    """Translate the predicate the read page proved into inject replay steps."""

    sink = sink_class_for(str(raw.get("kind") or "Xss"))
    first = pairing.queue[0] if pairing.queue else {}
    table = str(first.get("table") or "")
    columns = [str(column) for column in (first.get("columns") or [])]
    if not sink.writes_database() or not table or not columns:
        return {}
    writers: list[tuple[str, dict[str, Any]]] = []
    for row in store.list_slice_rows(run_id=pair_run_id, limit=2000):
        if str(row.get("role") or "") != "write":
            continue
        candidate = row.get("slice")
        if isinstance(candidate, dict):
            writers.append((str(row.get("id")), dict(candidate)))
    if not writers:
        return {}
    page_url = url_for(raw) if url_for is not None else base_url

    async def calling(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        envelope = await client.call(name, arguments)
        data = getattr(envelope, "data", envelope)
        return dict(data or {})

    read_sql = ""
    read_trace: dict[str, Any] = {}
    try:
        evidence = await collect_read_sql(
            calling,
            case_id=str(trigger.case_id),
            url=page_url,
            sink_file=str(raw.get("sinkFile") or ""),
            sink_line=int(raw.get("sinkLine") or 0),
        )
        read_trace = evidence.get("trace") or {}
        statements = evidence.get("statements") or []
        if statements:
            read_sql = str(statements[0])
    except Exception:  # noqa: BLE001 - evidence is best effort
        read_sql = ""
    flow = {
        "flow_id": pair_run_id,
        "table_name": table,
        "columns": columns,
        "writer_slice_ids": [writer_id for writer_id, _ in writers],
    }
    from tia.dom.constraint_steps import build_steps
    from tia.inf.accounts import public_catalog

    planner = None
    try:
        from tia.ad.llm import LlmClient

        planner = LlmClient.from_env()
    except Exception:  # noqa: BLE001 - the planner is optional
        planner = None
    plan = await build_steps(
        calling,
        flow,
        writers,
        base_url,
        url_for,
        public_catalog(get_runtime().settings.accounts_path),
        read_raw=raw,
        read_sql=read_sql,
        read_trace=read_trace,
        planner=planner,
    )
    return plan if isinstance(plan, dict) else {}


async def _run_second_order_round(
    *,
    store: Any,
    result: PipelineResult,
    leased: dict[str, Any],
    write_slices: list[dict[str, Any]],
    trigger_run_id: str,
    base_url: str,
    payload_base: str,
    budget: int,
    queue_cap: int,
    trigger_client: ToolClient | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    published: dict[str, str],
    reports: RunReports,
    reader: Any,
    scorer: Any | None = None,
) -> None:
    """Trigger, second-order variant: prove the read, pair writes, publish a task."""

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
        return
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
        return

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
    if pairing.queue:
        proven_raw = dict((proven or {}).get("slice") or raw)
        await _score_pairing_candidates(store, pairing, proven_raw, scorer=scorer)
    if not pairing.queue:
        record["stopped_at"] = "pairing"
        finding_db_only(store, trigger.case_id)
        result.rounds.append(record)
        return

    task_id = pairing.run_id or f"task-{round_index}"
    notes = dict(trigger.notes or {})
    if not notes.get("constraint_plan"):
        plan = await _constraint_plan_for(
            store,
            trigger_client or LocalToolClient("trigger"),
            raw,
            trigger=trigger,
            pair_run_id=pair_run_id,
            pairing=pairing,
            base_url=base_url,
            url_for=url_for,
        )
        if plan.get("constraints"):
            notes["constraint_plan"] = plan
    queue_items = publish_pairing(
        store,
        run_id=trigger_run_id,
        task_id=task_id,
        trigger_case=trigger.case_id,
        pairing=pairing,
        notes=notes,
        base_url=base_url,
        payload_base=payload_base,
    )
    published[task_id] = str(trigger.case_id or "")
    record["task_id"] = task_id
    record["queue_items"] = queue_items
    if not queue_items:
        record["stopped_at"] = "no_injection_candidate"
        result.stop_reason = "NO_INJECTION_CANDIDATE"
        result.rounds.append(record)
        return
    result.rounds.append(record)


async def run_trigger_round(
    *,
    store: Any,
    result: PipelineResult,
    leased: dict[str, Any],
    write_slices: list[dict[str, Any]],
    trigger_run_id: str,
    base_url: str,
    payload_base: str,
    budget: int,
    queue_cap: int,
    trigger_client: ToolClient | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    published: dict[str, str],
    reports: RunReports,
    reader: Any,
    scorer: Any | None = None,
) -> None:
    """Trigger consumer: the leased slice chooses which variant runs.

    The queue no longer knows "direct" as a separate agent. A first-order
    slice runs the request/direct variant (formerly the direct agent); a
    second-order slice runs the prove → pair → replay variant (formerly the
    trigger agent). Both are the same trigger consumer.
    """

    if str(leased.get("order_mode") or "second") == "direct":
        await _run_first_order_round(
            store,
            result,
            leased,
            base_url,
            url_for,
            reports,
            payload_base=payload_base,
            budget=budget,
            client=trigger_client,
        )
        return
    await _run_second_order_round(
        store=store,
        result=result,
        leased=leased,
        write_slices=write_slices,
        trigger_run_id=trigger_run_id,
        base_url=base_url,
        payload_base=payload_base,
        budget=budget,
        queue_cap=queue_cap,
        trigger_client=trigger_client,
        url_for=url_for,
        published=published,
        reports=reports,
        reader=reader,
        scorer=scorer,
    )


async def _consume_rounds(
    *,
    store: Any,
    result: PipelineResult,
    trigger_run_id: str,
    write_slices: list[dict[str, Any]],
    base_url: str,
    payload_base: str,
    budget: int,
    queue_cap: int,
    trigger_client: ToolClient | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    deadline: float,
    max_slices: int,
    mode: str,
    published: dict[str, str],
    reports: RunReports,
    reader: Any,
    scorer: Any | None = None,
) -> None:
    """Consume the slice queues until the budget or the slices run out."""

    while True:
        if time.monotonic() >= deadline:
            result.stop_reason = "TIMEOUT"
            break
        if max_slices and len(result.rounds) >= max_slices:
            result.stop_reason = "SLICE_LIMIT"
            break
        # One global queue: the highest scoring slice wins, whatever its order.
        # The consumer then dispatches on the slice itself: a first-order slice
        # goes to direct/prover, a second-order slice goes to trigger+pairing.
        leased = store.next_slice(run_id=trigger_run_id)
        if leased is None:
            result.stop_reason = "EXHAUSTED" if result.rounds else "NO_TRIGGER_SLICE"
            break
        await run_trigger_round(
            store=store,
            result=result,
            leased=leased,
            write_slices=write_slices,
            trigger_run_id=trigger_run_id,
            base_url=base_url,
            payload_base=payload_base,
            budget=budget,
            queue_cap=queue_cap,
            trigger_client=trigger_client,
            url_for=url_for,
            published=published,
            reports=reports,
            reader=reader,
            scorer=scorer,
        )




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
    inject_workers: int = 2,
    trigger_workers: int = 1,
    queue_log: str = "",
    scorer: Any | None = None,
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
    scorer = scorer if scorer is not None else _default_scorer()
    if scorer is not None:
        await _score_seeded_slices(store, trigger_run_id, scorer=scorer)
    deadline = time.monotonic() + max(timeout_sec, 0.0)
    reader = _reader()
    published: dict[str, str] = {}
    stop_lane, tasks = start_workers(
        store,
        trigger_run_id,
        workers=inject_workers,
        deadline=deadline,
        base_url=base_url,
        payload_base=payload_base,
        budget=budget,
        inject_client=inject_client,
        url_for=url_for,
        reader=reader,
        reports=reports,
        outcomes=result.outcomes,
    )

    probe: QueueProbe | None = None
    probe_stop: asyncio.Event | None = None
    probe_task: asyncio.Task[None] | None = None
    log_path = queue_log or os.environ.get(QUEUE_LOG_ENV, "")
    if log_path:
        probe = QueueProbe(store, log_path, trigger_run_id)
        probe_stop = asyncio.Event()
        probe_task = asyncio.create_task(probe.run(probe_stop))
    worker_count = max(1, trigger_workers)
    consumers = [
        asyncio.create_task(
            _consume_rounds(
                store=store,
                result=result,
                trigger_run_id=trigger_run_id,
                write_slices=write_slices,
                base_url=base_url,
                payload_base=payload_base,
                budget=budget,
                queue_cap=queue_cap,
                trigger_client=trigger_client,
                url_for=url_for,
                deadline=deadline,
                max_slices=max_slices,
                mode=mode,
                published=published,
                reports=reports,
                reader=reader,
                scorer=scorer,
            )
        )
        for _ in range(worker_count)
    ]
    await asyncio.gather(*consumers)
    if probe_stop is not None and probe_task is not None:
        probe_stop.set()
        await asyncio.gather(probe_task)

    stop_lane.set()
    await asyncio.gather(*tasks)
    _close_unproven_tasks(store, trigger_run_id, published)

    index = reports.finish(result.stop_reason, len(result.rounds), len(result.outcomes))
    result.report_path = str(index)
    result.report = _report(result)
    return result


async def _run_first_order_round(
    store: Any,
    result: PipelineResult,
    leased: dict[str, Any],
    base_url: str,
    url_for: Callable[[dict[str, Any]], str] | None,
    reports: RunReports,
    *,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 120,
    client: ToolClient | None = None,
) -> None:
    """Trigger, first-order variant: the sink class decides how it is proved."""
    round_index = len(result.rounds)
    raw = dict(leased["slice"])
    page_url = url_for(raw) if url_for is not None else base_url
    sink_class = sink_class_for(str(raw.get("kind") or "Xss"))
    try:
        if sink_class.writes_database():
            direct = await run_direct(
                normalize_slice(raw),
                base_url=page_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=client,
                slice_id=str(leased["id"]),
            )
        else:
            from tia.dom.request_prover import run_request_prover

            direct = await run_request_prover(
                raw,
                base_url=page_url,
                payload_base=payload_base,
                budget=min(budget, 40),
                client=client,
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
    result = PipelineResult()
    while True:
        item = store.next_injection_item(pair_run_id)
        if item is None:
            break
        try:
            outcome = await _run_injection_item(
                store,
                item,
                pair_run_id=pair_run_id,
                base_url=base_url,
                payload_base=payload_base,
                budget=budget,
                inject_client=inject_client,
                url_for=url_for,
                reader=reader,
                payload_constraints=payload_constraints,
                read_values=read_values,
                constraint_plan=constraint_plan,
                read_notes=read_notes,
            )
        except ToolCallError:
            store.archive_injection_item(str(item["item_id"]), "ERROR")
            continue
        if outcome is not None:
            result.outcomes.append(outcome)
    return result


async def _run_injection_item(
    store: Any,
    item: dict[str, Any],
    *,
    pair_run_id: str,
    base_url: str,
    payload_base: str,
    budget: int,
    inject_client: ToolClient | None,
    url_for: Callable[[dict[str, Any]], str] | None,
    reader: Callable[[str, int, int], list[tuple[int, str]]] | None = None,
    payload_constraints: dict[str, Any] | None = None,
    read_values: dict[str, str] | None = None,
    constraint_plan: dict[str, Any] | None = None,
    read_notes: dict[str, Any] | None = None,
) -> CaseOutcome | None:
    """Run one leased injection item and archive what it touched."""
    write_row = store.get_slice(str(item["write_slice_id"]))
    if write_row is None:
        store.archive_injection_item(str(item["item_id"]), "MISSING_SLICE")
        return None
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
    return CaseOutcome(
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


def _close_unproven_tasks(store: Any, run_id: str, published: dict[str, str]) -> None:
    """Write the db-only finding for every task whose slices all failed."""
    successes: set[str] = set()
    for item in store.list_injection_queue(run_id=run_id):
        if item.get("verdict") in ("EXECUTABLE", "EXECUTED"):
            successes.add(str(item.get("task_id") or ""))
    for task_id, trigger_case in published.items():
        if not trigger_case or task_id in successes:
            continue
        finding_db_only(store, trigger_case)
