"""Read/write pairing: database operation recovery and pair hints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom import main as main_module
from tia.inf.store import Store
from tia.orch.pairing import (
    build_pairs,
    extract_ops,
    group_by_slice,
    resolve_entry,
)

READ_SLICE = {
    "kind": "Xss",
    "sinkFile": "vulnerabilities/stored_xss/home.php",
    "sinkLine": 61,
    "sinkCode": "select user,comment,date from comments",
    "params": ["msg"],
    "sqlProbe": {"extensionConfig": {"file": "x", "line": "55", "output": "r.json"}},
}
WRITE_SLICE = {
    "kind": "SQL",
    "sinkFile": "vulnerabilities/stored_xss/home.php",
    "sinkLine": 49,
    "sinkCode": '$stmt->bindParam(":comment", $comment)',
    "params": ["msg"],
}
SOURCE = [
    (46, '$sql = "insert into comments (user,comment,date) values(:user,:comment,:date)";'),
    (48, '$stmt->bindParam(":user", $user);'),
    (49, '$stmt->bindParam(":comment", $comment);'),
]


def _reader(path: str, line_from: int, line_to: int) -> list[tuple[int, str]]:
    return SOURCE


def test_extract_ops_recovers_tables_and_columns() -> None:
    text = (
        'select u.name as n, comment from comments where id = 1; '
        'insert into logs (msg, level) values (?, ?); '
        'update users set name=?, age=? where id = 3; '
        'delete from sessions where id = 2;'
    )
    ops = extract_ops(text)
    by_op = {op.op: op for op in ops}
    assert by_op["select"].table == "comments"
    assert by_op["select"].columns == ("name", "comment")
    assert by_op["insert"].columns == ("msg", "level")
    assert by_op["update"].columns == ("name", "age")
    assert by_op["update"].has_where is True
    assert by_op["delete"].table == "sessions"


def test_extract_ops_skips_expressions_and_star() -> None:
    ops = extract_ops("select count(*) as n, user, * from comments")
    assert ops[0].columns == ("user",)


def test_resolve_entry_uses_source_window_for_write_slice() -> None:
    entry = resolve_entry(WRITE_SLICE, reader=_reader, history={})
    assert entry.file == "vulnerabilities/stored_xss/home.php"
    assert entry.line == 49
    tables = {op.table for op in entry.ops if op.op == "insert"}
    assert "comments" in tables
    columns = {column for op in entry.ops for column in op.columns}
    assert "comment" in columns


def test_build_pairs_matches_same_table_and_column() -> None:
    entries = [
        resolve_entry(READ_SLICE, index=0, reader=_reader),
        resolve_entry(WRITE_SLICE, index=1, reader=_reader),
    ]
    pairs = build_pairs(entries)
    assert len(pairs) == 1
    pair = pairs[0]
    assert pair["table"] == "comments"
    assert "comment" in pair["columns"]
    assert pair["read_slice_id"] == entries[0].slice_id
    assert pair["write_slice_id"] == entries[1].slice_id
    assert pair["direction"] == "write_then_read"
    assert pair["confidence"] >= 60
    assert len(pair["reasons"]) >= 3


def test_build_pairs_ignores_unrelated_tables() -> None:
    other = dict(WRITE_SLICE, sinkCode='$stmt->bindParam(":title", $title)')
    entries = [resolve_entry(READ_SLICE, 0, reader=_reader), resolve_entry(other, 1)]
    assert build_pairs(entries) == []


def test_build_pairs_is_bidirectional_and_deduped() -> None:
    read = resolve_entry(READ_SLICE, 0, reader=_reader)
    write = resolve_entry(WRITE_SLICE, 1, reader=_reader)
    pairs = build_pairs([read, write])
    grouped = group_by_slice(pairs)
    assert len(grouped[read.slice_id]) == 1
    assert len(grouped[write.slice_id]) == 1
    peer = grouped[read.slice_id][0]
    assert peer["write_slice_id"] == write.slice_id


def test_confidence_is_clamped() -> None:
    history = {"vulnerabilities/stored_xss/home.php:49": ["EXECUTABLE", "EXECUTABLE"]}
    entries = [
        resolve_entry(READ_SLICE, 0, reader=_reader, history=history),
        resolve_entry(WRITE_SLICE, 1, reader=_reader, history=history),
    ]
    for pair in build_pairs(entries):
        assert 0 <= pair["confidence"] <= 100


def test_store_pairs_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "pair.db")
    ids = store.seed_slices("run-p", [READ_SLICE, WRITE_SLICE])
    entries = [resolve_entry(READ_SLICE, 0, reader=_reader), resolve_entry(WRITE_SLICE, 1, reader=_reader)]
    entries[0].slice_id, entries[1].slice_id = ids
    pairs = build_pairs(entries)
    assert store.replace_pairs("run-p", pairs) == len(pairs)
    assert len(store.list_pairs("run-p")) == len(pairs)
    hints = store.pairs_for_slice(ids[0])
    assert hints and hints[0]["side"] == "read"
    assert hints[0]["peer_slice_id"] == ids[1]
    peeked = store.peek_slices(5, run_id="run-p")
    assert any(item["pairs"] for item in peeked)


async def test_run_queue_switches_to_paired_slice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Trigger:
        verdict = "EXECUTED"
        residue = 0
        case_id = "case-t"
        trace: list[Any] = []

    class Inject:
        def __init__(self, verdict: str) -> None:
            self.verdict = verdict
            self.residue = 0
            self.case_id = "case-i"
            self.trace: list[Any] = []

    current: dict[str, int] = {"line": 0}

    async def fake_trigger(raw: dict[str, Any], **kwargs: Any) -> Any:
        current["line"] = int(raw.get("sinkLine") or 0)
        return Trigger()

    async def fake_inject(raw: dict[str, Any], **kwargs: Any) -> Any:
        if current["line"] == 49:
            return Inject("WRITE_NOT_REACHED")
        return Inject("EXECUTABLE")

    monkeypatch.setattr(main_module, "run_trigger", fake_trigger)
    monkeypatch.setattr(main_module, "run_inject", fake_inject)
    store = Store(tmp_path / "switch.db")
    ids = store.seed_slices("run-s", [WRITE_SLICE, READ_SLICE])
    entries = [resolve_entry(WRITE_SLICE, 0, reader=_reader), resolve_entry(READ_SLICE, 1, reader=_reader)]
    entries[0].slice_id, entries[1].slice_id = ids
    pairs = build_pairs(entries)
    # Peer ids must be queue ids for the switch hop to find them.
    for pair in pairs:
        pair["read_slice_id"] = ids[1]
        pair["write_slice_id"] = ids[0]
        pair["pair_id"] = "pair-switch"
    store.replace_pairs("run-s", pairs)
    for slice_id in ids:
        store.set_slice_score(slice_id, 90 if slice_id == ids[0] else 50, [], {})
    result = await main_module.run_queue(store, base_url="http://127.0.0.1/xvwa/", run_id="run-s", limit=3)
    verdicts = [item.verdict for item in result.outcomes]
    assert verdicts[0] == "WRITE_NOT_REACHED"
    assert "EXECUTABLE" in verdicts
    assert any("switched_to" in item.notes for item in result.outcomes)
