"""One agent owns a table while it writes and verifies it."""

from __future__ import annotations

from pathlib import Path

import pytest

from tia.cap.locks import TableLocks
from tia.inf.store import Store
from tia.schemas.envelope import ToolError


def test_a_lease_is_exclusive_and_releasable(tmp_path: Path) -> None:
    store = Store(tmp_path / "locks.db")
    assert store.acquire_table_lock("comments", owner="case-a")
    assert not store.acquire_table_lock("comments", owner="case-b")
    assert store.list_table_locks()[0]["owner"] == "case-a"
    store.release_table_lock("comments", owner="case-a")
    assert store.acquire_table_lock("comments", owner="case-b")


def test_an_expired_lease_can_be_taken(tmp_path: Path) -> None:
    store = Store(tmp_path / "locks.db")
    assert store.acquire_table_lock("comments", owner="case-a", ttl_sec=-1)
    assert store.acquire_table_lock("comments", owner="case-b")


def test_refresh_and_release_all_by_owner(tmp_path: Path) -> None:
    store = Store(tmp_path / "locks.db")
    assert store.acquire_table_lock("a", owner="case-a")
    assert store.acquire_table_lock("b", owner="case-a")
    assert store.refresh_table_lock("a", owner="case-a")
    store.release_table_locks(owner="case-a")
    assert store.list_table_locks() == []


async def test_waiting_for_another_agent_then_locking(tmp_path: Path) -> None:
    store = Store(tmp_path / "locks.db")
    assert store.acquire_table_lock("comments", owner="case-a")
    waiter = TableLocks(store, owner="case-b", tables=["comments"], timeout_sec=0.4)
    with pytest.raises(ToolError):
        await waiter.acquire()
    store.release_table_lock("comments", owner="case-a")

    other = TableLocks(store, owner="case-b", tables=["comments"], timeout_sec=2.0)
    await other.acquire()
    assert other.held == ["comments"]
    other.release()
    assert store.list_table_locks() == []
