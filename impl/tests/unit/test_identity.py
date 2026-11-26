"""Semantic identities: duplicates are one site, not one taint path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tia.dom.pairing_agent import PairingConfig, build_pairing_queue
from tia.inf.store import Store
from tia.orch.identity import (
    identity_of,
    pair_key,
    read_identity,
    write_identity,
)


def _write_slice(line: int, code: str) -> dict[str, Any]:
    return {
        "kind": "xss",
        "sinkFile": "vulnerabilities/stored_xss/home.php",
        "sinkLine": line,
        "sinkCode": code,
        "params": ["msg"],
    }


def _read_slice(line: int, probe_line: int = 0) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "kind": "xss",
        "sinkFile": "vulnerabilities/stored_xss/home.php",
        "sinkLine": line,
        "sinkCode": "select user,comment,date from comments",
        "params": [],
    }
    if probe_line:
        raw["sqlProbe"] = {"extensionConfig": {"file": "home.php", "line": probe_line}}
    return raw


INSERT = 'insert into comments (user,comment,date) values (:user,:comment,:date)'


def test_write_identity_ignores_the_taint_path() -> None:
    first = _write_slice(48, INSERT)
    second = _write_slice(49, INSERT)
    assert write_identity(first) == write_identity(second)
    assert write_identity(first).endswith("|insert|comments|comment,date,user")


def test_read_identity_groups_render_lines_of_one_query() -> None:
    lines = [_read_slice(line, probe_line=55) for line in (61, 62, 63)]
    assert {read_identity(raw) for raw in lines} == {"vulnerabilities/stored_xss/home.php|read|sql:55"}


def test_read_identity_falls_back_to_projected_columns() -> None:
    raw = {
        "kind": "xss",
        "sinkFile": "vulnerabilities/sqli/home.php",
        "sinkLine": 70,
        "sinkCode": "select comment from caffaine",
        "params": [],
    }
    assert read_identity(raw) == 'vulnerabilities/sqli/home.php|read|caffaine|comment'


def test_identity_of_separates_reads_from_writes_without_bind_columns() -> None:
    insert = _write_slice(20, "insert into notes (body) values (:body)")
    select = _write_slice(21, "select body from notes")
    assert "|insert|" in identity_of(insert, "second")
    assert "|read|" in identity_of(select, "second")


def test_pair_key_is_stable() -> None:
    assert pair_key("a", "b") == "a||b"


def test_seeded_duplicates_point_at_the_canonical_slice(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    ids = store.seed_slices(
        "run-1",
        [_read_slice(61, 55), _read_slice(62, 55), _read_slice(63, 55)],
        order_mode="second",
    )
    rows = {row["id"]: row for row in store.list_slice_rows(run_id="run-1")}
    canonical = ids[0]
    assert rows[canonical]["duplicate_of"] is None
    assert rows[ids[1]]["duplicate_of"] == canonical
    assert rows[ids[2]]["duplicate_of"] == canonical
    # The queue lease still starts with the canonical slice.
    leased = store.next_slice(run_id="run-1")
    assert leased is not None
    assert leased["id"] == canonical


def test_conclusion_closes_the_identity_group(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    ids = store.seed_slices(
        "run-1",
        [_read_slice(61, 55), _read_slice(62, 55)],
        order_mode="second",
    )
    store.record_conclusion("read-id", "write-id", "EXECUTABLE", "case-1")
    assert store.get_conclusion("read-id", "write-id") is not None
    identity = str(store.list_slice_rows(run_id="run-1")[0]["identity"])
    store.close_identity_group(identity, "EXECUTABLE", "case-1", keep=ids[0])
    statuses = {row["id"]: row["status"] for row in store.list_slice_rows(run_id="run-1")}
    assert statuses[ids[1]] == "executed"


def test_pairing_skips_pairs_with_a_successful_conclusion(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    read = _read_slice(63, 55)
    write = _write_slice(49, INSERT)
    read_row = store.seed_slices("trigger-run", [read], order_mode="second")
    store.list_slice_rows(run_id="trigger-run")
    proven = {"id": read_row[0], "slice": read}
    rid = identity_of(read, "second")
    wid = identity_of(write, "second")
    store.record_conclusion(rid, wid, "EXECUTABLE", "case-1")

    result = build_pairing_queue(
        store,
        "pair-run",
        [write],
        [proven],
        config=PairingConfig(queue_cap=5),
    )
    assert result.queue == []
    assert result.notes["skipped_concluded"] == 1
