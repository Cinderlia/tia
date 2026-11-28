"""Pairing cache: content-addressed reuse across runs and processes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tia.dom.pairing_agent import PairingConfig, build_pairing_queue
from tia.inf.pair_cache import PairCache, fingerprint
from tia.inf.store import Store


def _sink(code: str, line: int, kind: str = "xss") -> dict[str, Any]:
    return {
        "kind": kind,
        "sinkFile": "app/view.php",
        "sinkLine": line,
        "sinkCode": code,
        "params": ["msg"],
    }


def _proven(store: Store, run_id: str) -> list[dict[str, Any]]:
    reads = [
        _sink("echo $row['comment'];", 61),
        _sink("select id, title from articles", 80, kind="sqli"),
    ]
    store.seed_slices(run_id, reads)
    for row in store.list_slice_rows(run_id):
        store.archive_slice(str(row["id"]), "EXECUTED")
    return store.list_slice_rows(run_id, verdicts=("EXECUTED",))


def _writes() -> list[dict[str, Any]]:
    return [
        _sink('$stmt->bindParam(":comment", $comment);', 49),
        _sink("insert into articles (title) values (:title)", 90, kind="sqli"),
    ]


def test_store_round_trips_and_prunes(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    store.set_pair_cache("window:abc", "window", [{"op": "insert", "table": "comments"}])
    assert store.get_pair_cache("window:abc") == [{"op": "insert", "table": "comments"}]
    store.set_pair_cache("window:abc", "window", [{"op": "update", "table": "comments"}])
    assert store.get_pair_cache("window:abc") == [{"op": "update", "table": "comments"}]
    for index in range(5):
        store.set_pair_cache(f"k{index}", "window", index)
    assert store.prune_pair_cache(keep=3) == 3
    assert store.get_pair_cache("k4") == 4


def test_local_cache_hits_without_the_store() -> None:
    cache = PairCache(None)
    assert cache.get("window", "x") is None
    cache.put("window", "x", [{"op": "insert"}])
    assert cache.get("window", "x") == [{"op": "insert"}]
    assert cache.stats() == {"hits": 1, "misses": 1, "local_size": 1}


def test_pairing_reuses_a_window_parse_across_runs(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    proven = _proven(store, "trig-cache")
    cache = PairCache(store)
    calls: list[str] = []

    def modeler(window: str) -> list[Any]:
        calls.append(window)
        from tia.orch.pairing import DbOp

        return [DbOp(op="insert", table="comments", columns=("comment",))]

    def reader(file: str, start: int, end: int) -> list[tuple[int, str]]:
        # No literal INSERT in the window: only the modeler can resolve it,
        # so a cache hit is observable through modeler call count.
        return [(49, "<?php $stmt->bindParam(:comment, $comment);")]

    config = PairingConfig(min_confidence=20, queue_cap=10)
    first = build_pairing_queue(
        store, "run-a", _writes(), proven, reader=reader, modeler=modeler,
        config=config, cache=cache,
    )
    second = build_pairing_queue(
        store, "run-b", _writes(), proven, reader=reader, modeler=modeler,
        config=config, cache=cache,
    )
    assert calls, "the first run needs the modeler"
    assert len(calls) == 1, "the second run must reuse the cached window parse"
    assert first.notes["pair_cache"]["misses"] >= 1
    assert second.notes["pair_cache"]["hits"] >= 1
    assert fingerprint("a", "b") != fingerprint("a", "c")
