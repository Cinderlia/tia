"""Pipeline loop: a failed chain stops downstream stages but not the main loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom import pipeline as pipeline_mod
from tia.dom.pipeline import run_pipeline
from tia.inf.store import Store
from tia.orch.kernel import ToolCallError


class _Result:
    def __init__(self, verdict: str, residue: int = 0) -> None:
        self.verdict = verdict
        self.residue = residue
        self.case_id = "case-1"
        self.trace: list[Any] = []
        self.stages: list[Any] = []
        self.notes: dict[str, Any] = {}


def _trigger_slices(n: int) -> list[dict[str, Any]]:
    return [
        {
            "kind": "xss",
            "sinkFile": "app/view.php",
            "sinkLine": 61 + index,
            "sinkCode": "select comment from comments",
            "params": ["msg"],
        }
        for index in range(n)
    ]


def _write_slices() -> list[dict[str, Any]]:
    return [
        {
            "kind": "xss",
            "sinkFile": "app/view.php",
            "sinkLine": 20,
            "sinkCode": "insert into comments (comment) values (:comment)",
            "params": ["msg"],
        }
    ]


@pytest.mark.asyncio
async def test_failed_trigger_skips_downstream_but_loop_continues(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = Store(tmp_path / "tia.db")
    verdicts = iter(["READ_NOT_REFLECTED", "EXECUTED", "EXECUTED"])
    injected: list[str] = []

    async def fake_trigger(raw: dict[str, Any], **kwargs: Any) -> _Result:
        return _Result(next(verdicts))

    async def fake_inject(raw: dict[str, Any], **kwargs: Any) -> _Result:
        injected.append("inject")
        return _Result("EXECUTABLE")

    monkeypatch.setattr(pipeline_mod, "run_trigger", fake_trigger)
    monkeypatch.setattr(pipeline_mod, "run_inject", fake_inject)

    result = await run_pipeline(
        store,
        trigger_run_id="run-1",
        trigger_slices=_trigger_slices(3),
        write_slices=_write_slices(),
        base_url="http://x/",
        timeout_sec=30,
        queue_cap=5,
    )

    assert result.stop_reason == "EXHAUSTED"
    # The failed round does not stop the loop; the next slice still runs, and
    # the two remaining slices of the same read site close with that success.
    assert len(result.rounds) == 3
    assert result.rounds[0]["stopped_at"] == "trigger"
    assert result.rounds[0]["injections"] == []
    # The inject lane is now async: all trigger slices are leased, and the
    # successful one publishes a task for the workers.
    assert injected
    assert any(round_["queue_items"] for round_ in result.rounds)


@pytest.mark.asyncio
async def test_timeout_stops_the_loop(tmp_path: Path, monkeypatch: Any) -> None:
    store = Store(tmp_path / "tia.db")

    async def fake_trigger(raw: dict[str, Any], **kwargs: Any) -> _Result:  # pragma: no cover
        raise AssertionError("trigger must not run when the budget is exhausted")

    monkeypatch.setattr(pipeline_mod, "run_trigger", fake_trigger)

    result = await run_pipeline(
        store,
        trigger_run_id="run-2",
        trigger_slices=_trigger_slices(2),
        write_slices=_write_slices(),
        base_url="http://x/",
        timeout_sec=0,
    )
    assert result.stop_reason == "TIMEOUT"
    assert result.rounds == []


@pytest.mark.asyncio
async def test_slice_error_is_recorded_and_skipped(tmp_path: Path, monkeypatch: Any) -> None:
    from tia.schemas.envelope import Envelope, ErrorBody, ErrorCode

    store = Store(tmp_path / "tia.db")
    calls = {"n": 0}

    async def fake_trigger(raw: dict[str, Any], **kwargs: Any) -> _Result:
        calls["n"] += 1
        if calls["n"] == 1:
            envelope = Envelope.failure(
                tool="db_schema",
                profile="main",
                error=ErrorBody(code=ErrorCode.NOT_FOUND, message="no table"),
            )
            raise ToolCallError("db_schema", envelope)
        return _Result("READ_NOT_REFLECTED")

    monkeypatch.setattr(pipeline_mod, "run_trigger", fake_trigger)

    result = await run_pipeline(
        store,
        trigger_run_id="run-3",
        trigger_slices=_trigger_slices(2),
        write_slices=_write_slices(),
        base_url="http://x/",
        timeout_sec=30,
    )
    assert result.stop_reason == "EXHAUSTED"
    assert result.rounds[0]["stopped_at"] == "error"
    assert result.rounds[1]["trigger_verdict"] == "READ_NOT_REFLECTED"



@pytest.mark.asyncio
async def test_direct_round_dispatches_a_sql_read_slice_to_the_prover(
    tmp_path: Path, monkeypatch: Any
) -> None:
    store = Store(tmp_path / "tia.db")
    calls: list[str] = []

    async def fake_prover(raw: dict[str, Any], **kwargs: Any) -> _Result:
        calls.append("prover")
        return _Result("EXECUTED")

    async def fake_direct(raw: dict[str, Any], **kwargs: Any) -> _Result:
        calls.append("direct")
        return _Result("EXECUTED")

    monkeypatch.setattr("tia.dom.request_prover.run_request_prover", fake_prover)
    monkeypatch.setattr(pipeline_mod, "run_direct", fake_direct)

    result = await run_pipeline(
        store,
        "run-sqlread",
        [],
        [],
        base_url="http://127.0.0.1/xvwa/",
        mode="direct",
        direct_slices=[
            {
                "kind": "SqlRead",
                "sinkFile": "vulnerabilities/sqli/home.php",
                "sinkLine": 61,
                "sinkCode": "select * from caffaine where itemid = :item",
                "params": ["item"],
            }
        ],
        timeout_sec=5,
    )

    assert calls == ["prover"]
    assert result.outcomes[0].verdict == "EXECUTED"
