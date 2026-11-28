"""Producer/consumer campaign: incremental scoring, atomic leases, time budget."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

from tia.dom.flow_main import SiteProducer, run_flow_queue
from tia.inf.store import Store

READ_SLICE: dict[str, Any] = {
    "kind": "Xss",
    "sinkFile": "templates/list.php",
    "sinkLine": 13,
    "sinkCode": "echo $row['comment'];",
    "sources": [
        {"file": "list.php", "line": 26, "code": "select comment from posts", "param": "search"}
    ],
}

WRITE_SLICE: dict[str, Any] = {
    "kind": "SqlWriteLoose",
    "sinkFile": "actions/write.php",
    "sinkLine": 27,
    "sinkCode": 'bindParam(":comment", $comment)',
    "params": ["comment"],
    "sources": [
        {"file": "actions/write.php", "line": 23, "code": "insert into posts (comment)"}
    ],
}


def _sites() -> list[dict[str, Any]]:
    return [
        {"raw": dict(READ_SLICE), "family": "second", "role": "read"},
        {"raw": dict(WRITE_SLICE), "family": "second", "role": "write"},
    ]


def test_producer_scores_batches_and_seeds_late_writers(tmp_path: Path) -> None:
    store = Store(tmp_path / "campaign.db")
    producer = SiteProducer(store, "run-1", _sites(), batch_size=1)

    # The read batch seeds the read-only flow; the writer batch upgrades it.
    assert producer.next_batch() == 1
    assert not producer.done

    assert producer.next_batch() == 1
    assert producer.done
    assert store.count_pending_flows("run-1") == 2


def test_reseeding_does_not_reset_a_leased_flow(tmp_path: Path) -> None:
    store = Store(tmp_path / "campaign.db")
    producer = SiteProducer(store, "run-1", _sites(), batch_size=2)
    producer.next_batch()
    leased = store.next_flow("run-1")
    assert leased is not None
    assert leased["status"] == "running"

    again = SiteProducer(store, "run-1", _sites(), batch_size=2)
    again.next_batch()

    row = store.get_flow(str(leased["flow_id"]))
    assert row is not None
    assert row["status"] == "running"


def test_two_consumers_lease_a_flow_only_once(tmp_path: Path) -> None:
    store = Store(tmp_path / "campaign.db")
    SiteProducer(store, "run-1", _sites(), batch_size=2).next_batch()
    other = Store(tmp_path / "campaign.db")

    leased: list[dict[str, Any] | None] = [None, None]

    def lease(index: int, target: Store) -> None:
        leased[index] = target.next_flow("run-1")

    threads = [
        threading.Thread(target=lease, args=(0, store)),
        threading.Thread(target=lease, args=(1, other)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for item in leased if item is not None) == 1


def test_time_budget_keeps_the_tail_pending(tmp_path: Path) -> None:
    store = Store(tmp_path / "campaign.db")
    SiteProducer(store, "run-1", _sites(), batch_size=2).next_batch()
    assert store.count_pending_flows("run-1") == 1

    result = asyncio.run(
        run_flow_queue(
            store,
            "http://target.example/",
            "run-1",
            limit=10,
            max_minutes=1e-9,
        )
    )

    assert result.stop_reason == "TIME_BUDGET"
    assert result.outcomes == []
    assert store.count_pending_flows("run-1") == 1
