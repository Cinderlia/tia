"""Worker lane: leases are exclusive and a failure lowers the parked score."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from tia.dom.lanes import publish_pairing, start_workers
from tia.inf.store import Store
from tia.schemas.objects import CaseOutcome


class _Reports:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, case_id: str, agent: str, verdict: str, label: str = "") -> None:
        self.rows.append((case_id, agent, verdict))


class _Pairing:
    run_id = "pair-run"

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.queue = items


def _items() -> list[dict[str, Any]]:
    return [
        {"item_id": "iq-high", "write_slice_id": "s-high", "read_slice_id": "r", "score": 90},
        {"item_id": "iq-low", "write_slice_id": "s-low", "read_slice_id": "r", "score": 50},
    ]


async def test_workers_share_one_queue_without_duplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "lane.db")
    publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_Pairing(_items()),
        notes={},
        base_url="http://app/",
        payload_base="x",
    )
    seen: list[str] = []

    async def fake_run(store: Any, item: dict[str, Any], **kwargs: Any) -> CaseOutcome:
        seen.append(str(item["item_id"]))
        await asyncio.sleep(0.01)
        return CaseOutcome(
            slice_id=str(item["write_slice_id"]),
            case_id=f"case-{item['item_id']}",
            verdict="EXECUTABLE",
        )

    monkeypatch.setattr("tia.dom.pipeline._run_injection_item", fake_run)
    outcomes: list[CaseOutcome] = []
    reports = _Reports()
    stop, tasks = start_workers(
        store,
        "r",
        workers=2,
        deadline=asyncio.get_running_loop().time() + 5,
        base_url="http://app/",
        payload_base="x",
        budget=10,
        inject_client=None,
        url_for=None,
        reader=None,
        reports=reports,  # type: ignore[arg-type]
        outcomes=outcomes,
    )
    await asyncio.sleep(0.2)
    stop.set()
    await asyncio.gather(*tasks)

    assert sorted(seen) == ["iq-high", "iq-low"]
    assert len(seen) == len(set(seen))
    assert {o.case_id for o in outcomes} == {"case-iq-high", "case-iq-low"}
    statuses = {i["item_id"]: i["status"] for i in store.list_injection_queue(run_id="r")}
    assert statuses == {"iq-high": "done", "iq-low": "done"}
    assert [row[1] for row in reports.rows] == ["inject", "inject"]


async def test_a_failed_payload_parks_low_and_drops_its_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Store(tmp_path / "lane.db")
    publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_Pairing(_items()),
        notes={},
        base_url="http://app/",
        payload_base="x",
    )

    async def fake_run(store: Any, item: dict[str, Any], **kwargs: Any) -> CaseOutcome:
        return CaseOutcome(
            slice_id=str(item["write_slice_id"]),
            case_id=f"case-{item['item_id']}",
            verdict="WRITE_NOT_REACHED",
        )

    monkeypatch.setattr("tia.dom.pipeline._run_injection_item", fake_run)
    outcomes: list[CaseOutcome] = []
    reports = _Reports()
    stop, tasks = start_workers(
        store,
        "r",
        workers=1,
        deadline=asyncio.get_running_loop().time() + 5,
        base_url="http://app/",
        payload_base="x",
        budget=10,
        inject_client=None,
        url_for=None,
        reader=None,
        reports=reports,  # type: ignore[arg-type]
        outcomes=outcomes,
    )
    await asyncio.sleep(0.15)
    stop.set()
    await asyncio.gather(*tasks)

    parked = {i["item_id"]: i for i in store.list_injection_queue(run_id="r")}
    assert parked["iq-high"]["status"] == "done"
    assert parked["iq-high"]["verdict"] == "ABANDONED_PAYLOAD"
    assert parked["iq-low"]["status"] == "abandoned"
