"""Every write this framework makes must be reverted, also when a run dies."""

from __future__ import annotations

from typing import Any

import pytest

from tia.dom import inject as inject_mod
from tia.dom import trigger as trigger_mod
from tia.inf.config import Settings
from tia.inf.runtime import configure, get_runtime, reset_runtime
from tia.inf.store import Store, now_iso


class FakeKernel:
    """Records tool calls; a delete leaves nothing behind."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        args = dict(arguments or {})
        self.calls.append((tool, args))
        if tool == "db_write":
            return {"change": {"change_id": "ch-clean"}}
        if tool == "db_read":
            return {"rows": [{"n": 0}]}
        return {}


@pytest.mark.asyncio
async def test_cleanup_deletes_every_row_with_the_tag() -> None:
    kernel = FakeKernel()
    state = {
        "kernel": kernel,
        "case_id": "case-1",
        "table": "comments",
        "column": "comment",
        "tag": "ab12",
        "pending": True,
    }

    residue = await inject_mod._cleanup_tagged_rows(kernel, state)

    assert residue == 0
    delete = [args for tool, args in kernel.calls if tool == "db_write"][0]
    assert delete["sql"] == "DELETE FROM `comments` WHERE `comment` LIKE '%ab12%'"
    # Two rows with the same tag must both go: a fixed expect_affected=1 used to
    # abort the cleanup and leave every row behind.
    assert delete["allow_multi"] is True
    assert "expect_affected" not in delete


@pytest.mark.asyncio
async def test_inject_cleanup_runs_when_the_agent_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = FakeKernel()

    async def boom(*args: Any, **kwargs: Any) -> Any:
        inject_mod._ACTIVE_CLEANUP.set(
            {
                "kernel": kernel,
                "case_id": "case-1",
                "table": "comments",
                "column": "comment",
                "tag": "cd34",
                "pending": True,
            }
        )
        raise RuntimeError("request killed")

    monkeypatch.setattr(inject_mod, "_run_inject", boom)

    with pytest.raises(RuntimeError):
        await inject_mod.run_inject({"sinkFile": "home.php", "sinkLine": 1}, "http://app/")

    deletes = [args for tool, args in kernel.calls if tool == "db_write"]
    assert deletes and "cd34" in deletes[0]["sql"]


@pytest.fixture()
def runtime(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure(settings=Settings.load("trigger", store_path=tmp_path / "tia.db"))
    yield
    reset_runtime()


def _change(case_id: str, change_id: str) -> dict[str, Any]:
    return {
        "change_id": change_id,
        "agent": "trigger",
        "case_id": case_id,
        "table": "comments",
        "op": "insert",
        "sql": "INSERT INTO comments (comment) VALUES ('x')",
        "undo_sql": "DELETE FROM comments WHERE id = 1",
        "affected": 1,
        "before_image": [],
        "after_image": [{"id": 1}],
        "ts": now_iso(),
    }


@pytest.mark.asyncio
async def test_trigger_guard_reverts_pending_writes(runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    store = get_runtime().store
    assert isinstance(store, Store)
    store.add_change(_change("case-9", "ch-9"))
    undone: list[str] = []

    async def fake_undo(arguments: dict[str, Any]) -> dict[str, Any]:
        undone.append(str(arguments.get("case_id") or ""))
        return {"residue": 0}

    monkeypatch.setattr("tia.cap.db.db_undo", fake_undo)

    await trigger_mod._revert_pending_writes("case-9")

    assert undone == ["case-9"]


@pytest.mark.asyncio
async def test_trigger_guard_is_quiet_without_pending_writes(runtime, monkeypatch: pytest.MonkeyPatch) -> None:
    undone: list[str] = []

    async def fake_undo(arguments: dict[str, Any]) -> dict[str, Any]:
        undone.append(str(arguments.get("case_id") or ""))
        return {"residue": 0}

    monkeypatch.setattr("tia.cap.db.db_undo", fake_undo)

    await trigger_mod._revert_pending_writes("case-none")

    assert undone == []


@pytest.mark.asyncio
async def test_cleanup_covers_every_text_column() -> None:
    kernel = FakeKernel()
    state = {
        "kernel": kernel,
        "case_id": "case-1",
        "table": "blog",
        "columns": ["entry", "owner"],
        "tag": "ef56",
        "pending": True,
    }

    await inject_mod._cleanup_tagged_rows(kernel, state)

    delete = [args for tool, args in kernel.calls if tool == "db_write"][0]
    assert delete["sql"] == (
        "DELETE FROM `blog` WHERE `entry` LIKE '%ef56%' OR `owner` LIKE '%ef56%'"
    )


@pytest.mark.asyncio
async def test_trigger_sweep_runs_when_the_agent_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = FakeKernel()

    async def boom(*args: Any, **kwargs: Any) -> Any:
        kwargs["case"]["cleanup"] = {
            "kernel": kernel,
            "case_id": "case-2",
            "table": "comments",
            "columns": ["user", "comment"],
            "tag": "gh78",
        }
        raise RuntimeError("timed out")

    monkeypatch.setattr(trigger_mod, "_run_trigger", boom)

    with pytest.raises(RuntimeError):
        await trigger_mod.run_trigger({"sinkFile": "home.php", "sinkLine": 1}, base_url="http://app/")

    deletes = [args for tool, args in kernel.calls if tool == "db_write"]
    assert deletes and "gh78" in deletes[0]["sql"]
