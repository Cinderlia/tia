"""Slice queue: store state machine and the slice_* tool handlers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.cap.slice import slice_archive, slice_next, slice_skip
from tia.dom.main import run_main
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.inf.store import Store
from tia.schemas.envelope import ErrorCode, ToolError

SLICE_A = {
    "kind": "input",
    "sinkFile": "vulnerabilities/stored_xss/home.php",
    "sinkLine": 48,
    "sinkCode": "$stmt->bindParam(\":user\", $user);",
    "sources": [{"file": "vulnerabilities/stored_xss/home.php", "line": 39, "param": "name"}],
}
SLICE_B = {
    "kind": "input",
    "sinkFile": "vulnerabilities/stored_xss/home.php",
    "sinkLine": 49,
    "sinkCode": "$stmt->bindParam(\":comment\", $comment);",
    "sources": [{"file": "vulnerabilities/stored_xss/home.php", "line": 40, "param": "msg"}],
}


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "tia.db")


@pytest.fixture()
def configured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Store:
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "tia.db"))
    monkeypatch.setenv("TIA_APP_ROOT", str(tmp_path))
    settings = Settings.load("main")
    reset_runtime()
    runtime = configure(settings)
    yield runtime.store
    reset_runtime()


def test_seed_deduplicates_by_sink(store: Store) -> None:
    first = store.seed_slices("run-1", [SLICE_A, SLICE_B])
    second = store.seed_slices("run-1", [SLICE_A])
    assert len(first) == 2
    assert second == [first[0]]
    assert [item["sink_line"] for item in store.list_slices(status="pending")] == [48, 49]


def test_next_slice_leases_in_order_and_counts_attempts(store: Store) -> None:
    store.seed_slices("run-1", [SLICE_B, SLICE_A])
    leased = store.next_slice()
    assert leased is not None
    assert leased["sink_line"] == 48
    assert leased["attempts"] == 1
    assert leased["slice"]["kind"] == "input"
    assert store.next_slice() is not None
    assert store.next_slice() is None


def test_expired_running_slice_returns_to_pending(store: Store) -> None:
    store.seed_slices("run-1", [SLICE_A])
    assert store.next_slice() is not None
    with store._conn() as conn:  # noqa: SLF001 - deliberate clock manipulation
        conn.execute("UPDATE slice SET updated_at='2000-01-01T00:00:00+00:00'")
    requeued = store.next_slice(ttl_minutes=30)
    assert requeued is not None
    assert requeued["attempts"] == 2


def test_run_id_filter_skips_foreign_slices(store: Store) -> None:
    store.seed_slices("run-1", [SLICE_A])
    leased = store.next_slice()
    assert leased is not None
    assert leased["run_id"] == "run-1"


def test_archive_and_skip(store: Store) -> None:
    ids = store.seed_slices("run-1", [SLICE_A, SLICE_B])
    assert store.archive_slice(ids[0], "EXECUTABLE", case_id="case-1") is True
    assert store.skip_slice(ids[1], "dup", status="skipped") is True
    rows = {row["id"]: row for row in store.list_slices()}
    assert rows[ids[0]]["status"] == "executed"
    assert rows[ids[0]]["verdict"] == "EXECUTABLE"
    assert rows[ids[1]]["status"] == "skipped"
    assert store.archive_slice("missing", "EXECUTABLE") is False


async def test_slice_next_tool_returns_envelope(configured: Store) -> None:
    configured.seed_slices("run-1", [SLICE_A])
    output = await slice_next({"run_id": "run-1"})
    assert output.data["found"] is True
    assert output.data["slice_id"]
    empty = await slice_next({"run_id": "run-1"})
    assert empty.data["found"] is False


async def test_slice_archive_and_skip_tools(configured: Store) -> None:
    ids = configured.seed_slices("run-1", [SLICE_A, SLICE_B])
    archived = await slice_archive({"slice_id": ids[0], "verdict": "EXECUTABLE"})
    assert archived.data["archived"] is True
    skipped = await slice_skip({"slice_id": ids[1], "reason": "already covered"})
    assert skipped.data["status"] == "skipped"


async def test_slice_tools_validate_arguments(configured: Store) -> None:
    with pytest.raises(ToolError) as invalid:
        await slice_next({"ttl_minutes": 0})
    assert invalid.value.code == ErrorCode.BAD_ARGS
    with pytest.raises(ToolError) as missing:
        await slice_archive({"slice_id": "nope", "verdict": "EXECUTABLE"})
    assert missing.value.code == ErrorCode.NOT_FOUND
    with pytest.raises(ToolError) as bad_status:
        await slice_skip({"slice_id": "nope", "reason": "x", "status": "done"})
    assert bad_status.value.code == ErrorCode.BAD_ARGS


class StubTrigger:
    def __init__(self, verdict: str = "EXECUTED") -> None:
        self.verdict = verdict

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("not used")


async def test_main_reports_done_on_executable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tia.dom import main as main_module

    class Trigger:
        verdict = "EXECUTED"
        residue = 0
        case_id = "case-t"
        trace: list[Any] = []

    class Inject:
        verdict = "EXECUTABLE"
        residue = 0
        case_id = "case-i"
        trace: list[Any] = []

    async def fake_trigger(*args: Any, **kwargs: Any) -> Any:
        return Trigger()

    async def fake_inject(*args: Any, **kwargs: Any) -> Any:
        return Inject()

    monkeypatch.setattr(main_module, "run_trigger", fake_trigger)
    monkeypatch.setattr(main_module, "run_inject", fake_inject)
    result = await run_main([SLICE_A], base_url="http://127.0.0.1/xvwa/")
    assert result.stop_reason == "DONE"
    assert result.outcomes[0].verdict == "EXECUTABLE"


async def test_main_reports_limit_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    from tia.dom import main as main_module

    class Trigger:
        verdict = "EXECUTED"
        residue = 0
        case_id = "case-t"
        trace: list[Any] = []

    class Inject:
        verdict = "EXECUTABLE"
        residue = 0
        case_id = "case-i"
        trace: list[Any] = []

    async def fake_trigger(*args: Any, **kwargs: Any) -> Any:
        return Trigger()

    async def fake_inject(*args: Any, **kwargs: Any) -> Any:
        return Inject()

    monkeypatch.setattr(main_module, "run_trigger", fake_trigger)
    monkeypatch.setattr(main_module, "run_inject", fake_inject)
    result = await run_main([SLICE_A, SLICE_B], base_url="http://127.0.0.1/xvwa/", limit=1)
    assert result.stop_reason == "LIMIT_REACHED"
    assert len(result.outcomes) == 1


def test_seed_is_scoped_to_run_id(store: Store) -> None:
    first = store.seed_slices("run-1", [SLICE_A])
    assert store.seed_slices("run-2", [SLICE_A]) != first
    assert len([row for row in store.list_slices() if row["status"] == "pending"]) == 2


async def test_run_queue_leases_and_archives(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tia.dom import main as main_module

    class Trigger:
        verdict = "EXECUTED"
        residue = 0
        case_id = "case-t"
        trace: list[Any] = []

    class Inject:
        verdict = "EXECUTABLE"
        residue = 0
        case_id = "case-i"
        trace: list[Any] = []

    async def fake_trigger(*args: Any, **kwargs: Any) -> Any:
        return Trigger()

    async def fake_inject(*args: Any, **kwargs: Any) -> Any:
        return Inject()

    monkeypatch.setattr(main_module, "run_trigger", fake_trigger)
    monkeypatch.setattr(main_module, "run_inject", fake_inject)
    queue = Store(tmp_path / "queue.db")
    queue.seed_slices("run-q", [SLICE_A, SLICE_B])
    result = await main_module.run_queue(
        queue, base_url="http://127.0.0.1/xvwa/", run_id="run-q", limit=5
    )
    assert result.stop_reason == "DONE"
    assert [item.verdict for item in result.outcomes] == ["EXECUTABLE", "EXECUTABLE"]
    rows = queue.list_slices()
    assert {row["status"] for row in rows} == {"executed"}
    assert {row["verdict"] for row in rows} == {"EXECUTABLE"}


def test_score_prefers_reflection_and_pairs() -> None:
    from tia.orch.slicing import pair_files, score_slice

    read_slice = {
        "kind": "Xss",
        "sinkFile": "vulnerabilities/stored_xss/home.php",
        "sinkLine": 61,
        "sinkCode": "echo ucfirst($rows[0])",
        "sources": [{"file": "x", "line": 55, "param": "msg"}],
        "sqlProbe": {"extensionConfig": {"file": "x", "line": "55", "output": "r.json"}},
    }
    exec_slice = {
        "kind": "Xss",
        "sinkFile": "vulnerabilities/cmd/home.php",
        "sinkLine": 9,
        "sinkCode": "system($_GET['cmd'])",
        "sources": [{"file": "x", "line": 8, "param": None}],
    }
    high = score_slice(read_slice, paired=True, history=["EXECUTABLE"])
    low = score_slice(exec_slice)
    assert high.score > low.score + 20
    assert any("reflection" in reason for reason in high.reasons)
    write_slice = {
        "kind": "Xss",
        "sinkFile": "vulnerabilities/stored_xss/home.php",
        "sinkLine": 48,
        "sinkCode": '$stmt->bindParam(":user", $user);',
    }
    assert pair_files([read_slice, write_slice, exec_slice]) == {
        "vulnerabilities/stored_xss/home.php"
    }


def test_score_penalises_guards() -> None:
    from tia.orch.slicing import score_slice

    raw = {"kind": "Xss", "sinkFile": "a/b.php", "sinkLine": 3, "sinkCode": "echo $x"}
    guarded = dict(raw, optionalGuards=["htmlspecialchars"])
    assert score_slice(guarded).score < score_slice(raw).score


def test_queue_orders_by_score_and_leases_choice(store: Store) -> None:

    ids = store.seed_slices("run-s", [SLICE_A, SLICE_B])
    store.set_slice_score(ids[0], 20, ["low"], {"sink": "a"})
    store.set_slice_score(ids[1], 80, ["high"], {"sink": "b"})
    candidates = store.peek_slices(limit=5, run_id="run-s")
    assert [row["slice_id"] for row in candidates] == [ids[1], ids[0]]
    leased = store.lease_slice(ids[0])
    assert leased is not None
    assert leased["attempts"] == 1
    assert store.lease_slice(ids[0]) is None
    assert store.next_slice(run_id="run-s")["id"] == ids[1]  # type: ignore[index]


async def test_slice_next_peek_then_lease_choice(configured: Store) -> None:
    from tia.dom.main import seed_queue

    seed_queue(configured, "run-p", [SLICE_A, SLICE_B])
    peek = await slice_next({"peek": True, "run_id": "run-p", "limit": 5})
    candidates = peek.data["candidates"]
    assert len(candidates) == 2
    assert all("score" in item and "reasons" in item for item in candidates)
    chosen = candidates[-1]["slice_id"]
    leased = await slice_next({"slice_id": chosen})
    assert leased.data["slice_id"] == chosen
    again = await slice_next({"peek": True, "run_id": "run-p"})
    assert chosen not in [item["slice_id"] for item in again.data["candidates"]]


async def test_slice_next_lease_conflict(configured: Store) -> None:
    with pytest.raises(ToolError) as conflict:
        await slice_next({"slice_id": "missing"})
    assert conflict.value.code == ErrorCode.CONFLICT
