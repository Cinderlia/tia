"""Pairing agent: only matched read/write candidates reach the injection queue."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom import main as main_mod
from tia.dom.pairing_agent import PairingConfig, build_pairing_queue
from tia.inf.store import Store


def _sink(code: str, line: int, kind: str = "xss") -> dict[str, Any]:
    return {
        "kind": kind,
        "sinkFile": "app/view.php",
        "sinkLine": line,
        "sinkCode": code,
        "params": ["msg"],
    }


def _reads() -> list[dict[str, Any]]:
    return [
        _sink("echo $row['comment'];", 61),
        _sink("echo $row['name'];", 62),
        _sink("select id, title from articles", 80, kind="sqli"),
    ]


def _writes() -> list[dict[str, Any]]:
    return [
        _sink('$stmt->bindParam(":comment", $comment);', 49),
        _sink('$stmt->bindParam(":title", $title);', 20),
        _sink("insert into articles (title) values (:title)", 90, kind="sqli"),
    ]


def _proven(store: Store, run_id: str) -> list[dict[str, Any]]:
    """Seed the trigger side and return it as proven rows (the agent's precondition)."""
    store.seed_slices(run_id, _reads())
    for row in store.list_slice_rows(run_id):
        store.archive_slice(str(row["id"]), "EXECUTED")
    return store.list_slice_rows(run_id, verdicts=("EXECUTED",))


def _config(**overrides: Any) -> PairingConfig:
    base: dict[str, Any] = {"min_confidence": 20, "queue_cap": 10}
    base.update(overrides)
    return PairingConfig(**base)


def test_queue_contains_only_matched_pairs(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    proven = _proven(store, "trig-1")
    result = build_pairing_queue(store, "run-1", _writes(), proven, config=_config())
    assert result.n_slices == 3
    assert result.queue, "the stored-then-rendered pair must be queued"
    for item in result.queue:
        assert item["table"] or item["columns"], item
    # The unrelated articles write/read pair is a different table and stays separate.
    tables = {item["table"] for item in result.queue}
    assert "articles" in tables


def test_queue_cap_is_a_bound_not_a_target(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    proven = _proven(store, "trig-2")
    small = build_pairing_queue(store, "run-2", _writes(), proven, config=_config(queue_cap=1))
    assert len(small.queue) <= 1
    assert small.notes["queue_basis"] in {"quality", "relative"}
    assert all(item["score"] >= 40 for item in small.queue)


def test_unrelated_write_is_not_queued(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    proven = _proven(store, "trig-3")
    writes = _writes() + [_sink("insert into sessions (token) values (:token)", 10)]
    result = build_pairing_queue(store, "run-3", writes, proven, config=_config())
    write_tables = {item["table"] for item in result.queue}
    assert result.queue, "matched candidates must still be queued"
    assert "sessions" not in write_tables


def test_injection_queue_store_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    items = [
        {
            "item_id": "iq-1",
            "write_slice_id": "w1",
            "read_slice_id": "r1",
            "pair_id": "p1",
            "table": "comments",
            "columns": ["comment"],
            "score": 90,
            "direction": "write_then_read",
            "reasons": ["same table"],
            "copy_paths": [{"path_id": "cp-1", "hops": []}],
        }
    ]
    assert store.replace_injection_queue("run-1", items) == 1
    listed = store.list_injection_queue("run-1")
    assert listed[0]["columns"] == ["comment"]
    assert listed[0]["copy_paths"][0]["path_id"] == "cp-1"
    leased = store.next_injection_item("run-1")
    assert leased is not None and leased["status"] == "running"
    assert store.archive_injection_item("iq-1", "EXECUTABLE", case_id="case-1")
    assert store.list_injection_queue("run-1")[0]["status"] == "done"


class _FakeTrigger:
    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.residue = 0
        self.case_id = "case-trigger"
        self.trace: list[Any] = []
        self.stages: list[Any] = []
        self.notes: dict[str, Any] = {}


class _FakeInject:
    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.residue = 0
        self.case_id = "case-inject"
        self.trace: list[Any] = []
        self.notes: dict[str, Any] = {}


@pytest.mark.asyncio
async def test_injection_queue_walk_continues_after_success(tmp_path: Path, monkeypatch: Any) -> None:
    store = Store(tmp_path / "tia.db")
    proven = _proven(store, "trig-4")
    build_pairing_queue(store, "run-4", _writes(), proven, config=_config())
    calls: list[str] = []

    async def fake_trigger(raw: dict[str, Any], **kwargs: Any) -> _FakeTrigger:
        calls.append("trigger")
        return _FakeTrigger("EXECUTED")

    async def fake_inject(raw: dict[str, Any], **kwargs: Any) -> _FakeInject:
        calls.append("inject")
        return _FakeInject("EXECUTABLE")

    monkeypatch.setattr(main_mod, "run_trigger", fake_trigger)
    monkeypatch.setattr(main_mod, "run_inject", fake_inject)
    result = await main_mod.run_injection_queue(store, "http://x/", run_id="run-4", limit=10)
    assert result.outcomes
    assert len(calls) == 2 * len(result.outcomes)
    assert result.stop_reason == "DONE"


@pytest.mark.asyncio
async def test_queue_item_carries_its_copy_path_into_the_injector(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = Store(tmp_path / "tia-copy.db")
    proven = _proven(store, "trig-5")
    proof_row = proven[0]
    write_raw = {
        "kind": "xss",
        "sinkFile": "app/drafts.php",
        "sinkLine": 10,
        "sinkCode": "insert into drafts (body) values (:body)",
        "params": ["body"],
    }
    ids = store.seed_slices("run-5", [write_raw])
    write_id = ids[0]
    store.replace_injection_queue(
        "run-5",
        [
            {
                "item_id": "iq-copy",
                "write_slice_id": write_id,
                "read_slice_id": str(proof_row["id"]),
                "pair_id": "p-copy",
                "table": "comments",
                "columns": ["comment"],
                "score": 88,
                "direction": "write_then_read",
                "reasons": ["copy"],
                "kind": "copy",
                "copy_paths": [
                    {
                        "path_id": "cp-x",
                        "table": "comments",
                        "column": "comment",
                        "hops": [
                            {"write_slice_id": write_id, "table": "drafts", "column": "body"}
                        ],
                    }
                ],
            }
        ],
    )
    captured: list[dict[str, Any]] = []

    async def fake_inject(raw: dict[str, Any], **kwargs: Any) -> _FakeInject:
        captured.append(kwargs)
        return _FakeInject("EXECUTABLE")

    from tia.dom import pipeline as pipeline_mod

    monkeypatch.setattr(pipeline_mod, "run_inject", fake_inject)
    await pipeline_mod.walk_injection_queue(
        store,
        "run-5",
        "http://x/",
        payload_base="<script>alert(1)</script>",
        budget=40,
        inject_client=None,
        url_for=None,
        reader=lambda file, line, width: [],
    )
    assert captured
    paths = captured[0]["copy_paths"]
    assert paths[0]["path_id"] == "cp-x"
    assert paths[0]["hops"][0]["raw"]["sinkFile"] == "app/drafts.php"
    assert captured[0]["copy_only"] is True
