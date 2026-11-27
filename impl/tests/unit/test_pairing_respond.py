"""Pairing agent answers on-demand constraint requests from inject."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.pairing_agent import respond
from tia.inf.store import Store


def _write_slice(file: str, line: int, code: str) -> dict[str, Any]:
    return {
        "kind": "Xss",
        "sinkFile": file,
        "sinkLine": line,
        "sinkCode": code,
        "sources": [{"file": file, "line": line, "code": code, "param": "status"}],
    }


def _seed(store: Store, run_id: str, slices: list[dict[str, Any]]) -> list[str]:
    return store.seed_slices(run_id, slices, order_mode="second")


async def test_respond_matches_a_write_slice(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    ids = _seed(
        store,
        "pair-run",
        [
            _write_slice(
                "posts.php",
                40,
                '''$stmt = $conn->prepare("update posts set status=:status where id=:id");''',
            )
        ],
    )
    request = store.add_pair_request(
        run_id="pair-run",
        read_slice_id="read-slice",
        kind="constraint",
        table="posts",
        column="status",
        op="set",
        value="publish",
        direction="payload_then_write",
    )

    result = await respond(store, "pair-run")

    assert result["answered"] == 1
    assert result["no_path"] == 0
    candidates = result["requests"][0]["candidates"]
    assert candidates and candidates[0]["write_slice_id"] == ids[0]
    stored = store.get_pair_request(request)
    assert stored is not None and stored["status"] == "answered"


async def test_respond_marks_no_path_when_nothing_matches(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    _seed(
        store,
        "pair-run",
        [_write_slice("comments.php", 30, '''$stmt->bindParam(":msg", $msg);''')],
    )
    request = store.add_pair_request(
        run_id="pair-run",
        read_slice_id="read-slice",
        kind="constraint",
        table="posts",
        column="status",
        op="set",
        value="publish",
        direction="payload_then_write",
    )

    result = await respond(store, "pair-run")

    assert result["no_path"] == 1
    stored = store.get_pair_request(request)
    assert stored is not None and stored["status"] == "no_path"


async def test_respond_does_not_answer_twice(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    _seed(store, "pair-run", [_write_slice("posts.php", 40, "insert into posts (status) values(:status)")])
    store.add_pair_request(
        run_id="pair-run",
        read_slice_id="read-slice",
        kind="constraint",
        table="posts",
        column="status",
        op="set",
        value="publish",
        direction="payload_then_write",
    )

    first = await respond(store, "pair-run")
    second = await respond(store, "pair-run")

    assert first["answered"] == 1
    assert second == {"answered": 0, "no_path": 0, "requests": []}


async def test_respond_ignores_other_runs(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    store.add_pair_request(
        run_id="another-run",
        read_slice_id="read-slice",
        kind="constraint",
        table="posts",
        column="status",
        op="set",
        value="publish",
        direction="payload_then_write",
    )

    result = await respond(store, "pair-run")

    assert result["answered"] == 0
    assert result["no_path"] == 0


@pytest.mark.parametrize("table", ["posts"])
def test_pair_candidates_rank_column_matches(tmp_path: Path, table: str) -> None:
    from tia.dom.pairing_agent import _pair_candidates

    store = Store(tmp_path / "tia.db")
    ids = _seed(
        store,
        "pair-run",
        [
            _write_slice("a.php", 10, "insert into posts (status) values(:status)"),
            _write_slice("b.php", 20, "insert into posts (title) values(:title)"),
        ],
    )
    request = {
        "request_id": "pr-x",
        "run_id": "pair-run",
        "read_slice_id": "read-slice",
        "table_name": table,
        "column_name": "status",
    }

    candidates = _pair_candidates(store, request)

    assert candidates
    assert candidates[0]["write_slice_id"] == ids[0]
