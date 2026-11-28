"""Global lanes: two priorities, one task, one lease per slice."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.lanes import publish_pairing
from tia.inf.store import Store


def _pairing() -> Any:
    class Pairing:
        run_id = "pair-run"
        queue = [
            {"item_id": "iq-low", "write_slice_id": "s-low", "score": 40, "table": "t1"},
            {"item_id": "iq-high", "write_slice_id": "s-high", "score": 90, "table": "t2"},
            {"item_id": "iq-mid", "write_slice_id": "s-mid", "score": 60, "table": "t3"},
        ]

    return Pairing()


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "lane.db")


def test_publish_puts_the_best_slice_on_the_high_lane(store: Store) -> None:
    published = publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_pairing(),
        notes={"constraint_plan": {"steps": []}, "read_entry_values": {"q": "x"}},
        base_url="http://app/",
        payload_base="<script>alert(1)</script>",
    )

    assert published == 3
    items = {item["item_id"]: item for item in store.list_injection_queue(run_id="r")}
    assert items["iq-high"]["priority"] == "high"
    assert items["iq-high"]["is_payload"] is True
    assert items["iq-low"]["priority"] == "low"
    assert items["iq-mid"]["is_payload"] is False
    ctx = items["iq-high"]["context"]
    assert ctx["pair_run_id"] == "r-pair-t-1"
    assert ctx["constraint_plan"] == {"steps": []}
    assert items["iq-high"]["task_id"] == "t-1"


def test_low_lane_waits_until_the_high_lane_is_taken(store: Store) -> None:
    publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_pairing(),
        notes={},
        base_url="http://app/",
        payload_base="x",
    )

    first = store.next_injection_item("r")
    assert first is not None and first["priority"] == "high"
    # The high slice is leased, so the low lane becomes visible.
    second = store.next_injection_item("r")
    assert second is not None and second["priority"] == "low"


def test_a_failed_payload_abandons_its_task(store: Store) -> None:
    publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_pairing(),
        notes={},
        base_url="http://app/",
        payload_base="x",
    )
    item = store.next_injection_item("r")
    assert item is not None and item["is_payload"] is True

    # What the worker does when this payload cannot carry the marker.
    store.abandon_injection_task(str(item["task_id"]), keep_item_id=str(item["item_id"]))
    store.requeue_injection_item(str(item["item_id"]), delta=-12)

    pending = [i for i in store.list_injection_queue(run_id="r") if i["status"] == "pending"]
    assert [i["item_id"] for i in pending] == [item["item_id"]]
    assert pending[0]["score"] == int(item["score"]) - 12
    # Its siblings are gone, so the next lease is a new task's slice.
    abandoned = [i for i in store.list_injection_queue(run_id="r") if i["status"] == "abandoned"]
    assert {i["item_id"] for i in abandoned} == {"iq-low", "iq-mid"}


def test_two_leases_never_return_the_same_slice(store: Store) -> None:
    publish_pairing(
        store,
        run_id="r",
        task_id="t-1",
        trigger_case="case-1",
        pairing=_pairing(),
        notes={},
        base_url="http://app/",
        payload_base="x",
    )

    first = store.next_injection_item("r")
    second = store.next_injection_item("r")
    assert first is not None and second is not None
    assert first["item_id"] != second["item_id"]
