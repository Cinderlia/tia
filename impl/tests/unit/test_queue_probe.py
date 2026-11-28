"""The queue probe writes one line per change and never mutates the store."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from tia.inf.queue_probe import QueueProbe


def _seed(store: Any, run_id: str) -> None:
    store.seed_slices(
        run_id,
        [
            {"kind": "Xss", "sinkFile": "a.php", "sinkLine": 1, "sinkCode": "echo 1"},
            {"kind": "Xss", "sinkFile": "b.php", "sinkLine": 2, "sinkCode": "echo 2"},
        ],
        order_mode="direct",
    )


@pytest.mark.asyncio
async def test_probe_logs_queue_lengths_on_change(tmp_path: Path) -> None:
    from tia.inf.store import Store

    store = Store(tmp_path / "q.db")
    _seed(store, "run-q")
    probe = QueueProbe(store, tmp_path / "queues.log", "run-q")

    stop = asyncio.Event()
    task = asyncio.create_task(probe.run(stop))
    await asyncio.sleep(0.1)
    leased = store.next_slice(run_id="run-q")
    assert leased is not None
    await asyncio.sleep(0.8)
    stop.set()
    await task

    lines = (tmp_path / "queues.log").read_text(encoding="utf-8").splitlines()
    assert lines
    assert "direct.pending=2" in lines[0]
    assert any("direct.pending=1" in line and "direct.running=1" in line for line in lines)
    assert "stop" in lines[-1]
    assert store.queue_stats("run-q")["slices"]["direct.running"] == 1


@pytest.mark.asyncio
async def test_one_queue_leases_the_highest_score_across_modes(tmp_path: Path) -> None:
    from tia.inf.store import Store

    store = Store(tmp_path / "one.db")
    store.seed_slices(
        "run-one",
        [{"kind": "Xss", "sinkFile": "low.php", "sinkLine": 1, "sinkCode": "echo 1"}],
        order_mode="second",
    )
    store.seed_slices(
        "run-one",
        [{"kind": "Xss", "sinkFile": "high.php", "sinkLine": 2, "sinkCode": "echo 2"}],
        order_mode="direct",
    )
    rows = store.list_slices("run-one")
    for row in rows:
        if row["order_mode"] == "direct":
            store.bump_slice_score(str(row["id"]), 99)
    leased = store.next_slice(run_id="run-one")
    assert leased is not None
    assert leased["order_mode"] == "direct"
