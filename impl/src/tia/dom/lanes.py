"""Cross-layer lanes: trigger publishes tasks, inject workers drain a global queue.

The trigger lane is the producer: it proves a read site, asks pairing for the
slices that can carry the payload there, and publishes them as one task.  The
highest scoring slice of a task goes to the high-priority queue, the rest to
the low-priority queue; a low slice is only visible after the high queue is
empty.  Workers never see a slice twice: leasing parks it, and a failed run
returns it with its score lowered.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from tia.inf.findings import finding_second_order
from tia.inf.reports import RunReports

SUCCESS = ("EXECUTABLE", "EXECUTED")


def publish_pairing(
    store: Any,
    *,
    run_id: str,
    task_id: str,
    trigger_case: str,
    pairing: Any,
    notes: dict[str, Any] | None,
    base_url: str,
    payload_base: str,
) -> int:
    """Queue one trigger task: best slice high, the rest low."""
    entries = [dict(entry) for entry in (pairing.queue or [])]
    entries.sort(key=lambda entry: int(entry.get("score") or 0), reverse=True)
    if not entries:
        return 0
    context = {
        "pair_run_id": f"{run_id}-pair-{task_id}",
        "payload_base": payload_base,
        "base_url": base_url,
        "payload_constraints": (notes or {}).get("payload_constraints"),
        "constraint_plan": (notes or {}).get("constraint_plan"),
        "read_values": (notes or {}).get("read_entry_values"),
        "read_notes": notes or {},
    }
    items: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        items.append(
            {
                **entry,
                "run_id": run_id,
                "task_id": task_id,
                "priority": "high" if index == 0 else "low",
                "is_payload": index == 0,
                "trigger_case": trigger_case,
                "context": context,
            }
        )
    store.append_injection_items(items)
    return len(items)


async def inject_worker(
    store: Any,
    run_id: str,
    *,
    stop: asyncio.Event,
    deadline: float,
    base_url: str,
    payload_base: str,
    budget: int,
    inject_client: Any,
    url_for: Callable[[dict[str, Any]], str] | None,
    reader: Callable[[str, int, int], list[tuple[int, str]]] | None,
    reports: RunReports,
    outcomes: list[Any],
) -> None:
    """Drain the global queue until the producer says stop and the queue is empty."""
    while True:
        if time.monotonic() >= deadline:
            return
        item = store.next_injection_item(run_id)
        if item is None:
            if stop.is_set():
                return
            await asyncio.sleep(0.2)
            continue
        ctx = item.get("context") or {}
        # Imported here so pipeline can import this module without a cycle.
        from tia.dom.pipeline import _run_injection_item  # noqa: PLC0415

        try:
            outcome = await _run_injection_item(
                store,
                item,
                pair_run_id=str(ctx.get("pair_run_id") or run_id),
                base_url=base_url,
                payload_base=str(ctx.get("payload_base") or payload_base),
                budget=budget,
                inject_client=inject_client,
                url_for=url_for,
                reader=reader,
                payload_constraints=ctx.get("payload_constraints"),
                read_values=ctx.get("read_values"),
                constraint_plan=ctx.get("constraint_plan"),
                read_notes=ctx.get("read_notes"),
            )
        except Exception:  # noqa: BLE001 - one bad candidate must not kill the lane
            store.requeue_injection_item(str(item["item_id"]), delta=-12)
            continue
        if outcome is None:
            continue
        outcomes.append(outcome)
        if outcome.verdict in SUCCESS:
            store.archive_injection_item(
                str(item["item_id"]), outcome.verdict, case_id=outcome.case_id
            )
            store.archive_slice(
                str(item["write_slice_id"]), outcome.verdict, case_id=outcome.case_id
            )
            if outcome.case_id:
                finding_second_order(store, outcome.case_id)
        else:
            # Park the slice back at a lower score; a payload that cannot carry
            # the marker abandons its whole task so the worker takes a new one.
            if item.get("is_payload"):
                # The payload slice itself failed: the task cannot prove this
                # read path, so drop its siblings and let the worker take a new one.
                store.abandon_injection_task(str(item.get("task_id") or ""))
                store.archive_injection_item(str(item["item_id"]), "ABANDONED_PAYLOAD")
            else:
                store.requeue_injection_item(str(item["item_id"]), delta=-6)
        reports.add(
            outcome.case_id,
            "inject",
            outcome.verdict,
            f"{item.get('table') or '?'}.{','.join(item.get('columns') or []) or '?'}",
        )


def start_workers(
    store: Any,
    run_id: str,
    *,
    workers: int,
    deadline: float,
    base_url: str,
    payload_base: str,
    budget: int,
    inject_client: Any,
    url_for: Callable[[dict[str, Any]], str] | None,
    reader: Callable[[str, int, int], list[tuple[int, str]]] | None,
    reports: RunReports,
    outcomes: list[Any],
) -> tuple[asyncio.Event, list[asyncio.Task[None]]]:
    stop = asyncio.Event()
    tasks = [
        asyncio.create_task(
            inject_worker(
                store,
                run_id,
                stop=stop,
                deadline=deadline,
                base_url=base_url,
                payload_base=payload_base,
                budget=budget,
                inject_client=inject_client,
                url_for=url_for,
                reader=reader,
                reports=reports,
                outcomes=outcomes,
            )
        )
        for _ in range(max(1, workers))
    ]
    return stop, tasks
