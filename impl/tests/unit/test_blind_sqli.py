"""Blind SQL injection acceptance: probe diagnosis first, differential second."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from tia.dom.request_prover import run_request_prover
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

PAGE = (
    '<html><body><form action="home.php" method="post">'
    '<input name="item"><input type="submit" name="submit" value="go">'
    "</form></body></html>"
)
PHP = """<?php
$item = $_POST['item'];
$sql = "select * from caffaine where itemid = ".$item;
$rows = $conn->query($sql);
"""

SLICE = {
    "kind": "SqlInjection",
    "sinkFile": "home.php",
    "sinkLine": 3,
    "sinkCode": '$sql = "select * from caffaine where itemid = ".$item;',
    "params": ["item"],
    "sqlProbe": {"extensionConfig": {"line": 3}},
}


class BlindClient:
    """In-band payloads are neutralised; blind pairs reach the engine."""

    def __init__(self, *, boolean_delta: int = 200, sleep_ms: float = 20.0) -> None:
        self.boolean_delta = boolean_delta
        self.sleep_ms = sleep_ms
        self.calls: list[str] = []
        self.values: list[str] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        return Envelope.success(tool=tool, profile="trigger", data=self._data(tool, dict(arguments or {})))

    def _tag(self, value: str) -> str:
        marker = value.rsplit("tia", 1)[-1]
        return marker[:4] if marker else ""

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-blind", "read_point": {"file": "home.php", "line": 3}}
        if tool == "source_read":
            return {
                "file": "home.php",
                "total_lines": len(PHP.splitlines()),
                "sha256": "abc",
                "lines": [
                    {"n": i + 1, "text": line, "in_comment": False, "in_string": False}
                    for i, line in enumerate(PHP.splitlines())
                ],
            }
        if tool == "http_request":
            return {
                "status": 200,
                "body": PAGE,
                "content_type": "text/html",
                "final_url": "http://target/home.php",
            }
        if tool == "probe_arm":
            return {"probe": {"file": "home.php", "line": 3}, "targets": []}
        if tool == "probe_disarm":
            return {"disarmed": True}
        if tool == "case_report":
            return {"markdown": "# blind report"}
        if tool == "case_note":
            return {"ok": True, "revision": 1}
        if tool != "probe_run":
            return {}
        values = {key: item[0] for key, item in parse_qs(str(args.get("body") or "")).items()}
        value = next(iter(values.values()), "")
        self.values.append(value)
        tag = self._tag(value)
        if "SLEEP(0)" in value:
            return {
                "hit": True,
                "queries": [
                    {"sql": f"select * from caffaine where itemid = 1 AND SLEEP(0) -- tia{tag}"}
                ],
                "http": {"status": 200, "bytes": 900, "elapsed_ms": 10.0},
            }
        if "SLEEP" in value:
            return {
                "hit": True,
                "queries": [
                    {"sql": f"select * from caffaine where itemid = 1 AND SLEEP(2) -- tia{tag}"}
                ],
                "http": {"status": 200, "bytes": 900, "elapsed_ms": self.sleep_ms},
            }
        if "AND 1=1" in value:
            return {
                "hit": True,
                "queries": [
                    {"sql": f"select * from caffaine where itemid = 1 AND 1=1 -- tia{tag}"}
                ],
                "http": {"status": 200, "bytes": 900 + self.boolean_delta, "elapsed_ms": 10.0},
            }
        if "AND 1=2" in value:
            return {
                "hit": True,
                "queries": [
                    {"sql": f"select * from caffaine where itemid = 1 AND 1=2 -- tia{tag}"}
                ],
                "http": {"status": 200, "bytes": 900, "elapsed_ms": 10.0},
            }
        # In-band payloads are filtered before the statement is built.
        return {
            "hit": False,
            "queries": [{"sql": "select * from caffaine where itemid = 1"}],
            "http": {"status": 200, "bytes": 900, "elapsed_ms": 10.0},
        }


class SleepClient(BlindClient):
    """The boolean pair is neutralised but the delayed request is not."""

    def __init__(self) -> None:
        super().__init__(sleep_ms=2400.0)

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        data = super()._data(tool, args)
        if tool == "probe_run":
            value = next(iter(parse_qs(str(args.get("body") or "")).items()), ("", [""]))[1][0]
            if "AND 1=1" in value or "AND 1=2" in value:
                # Both branches are filtered: no differential and no diagnosis.
                return {
                    "hit": False,
                    "queries": [{"sql": "select * from caffaine where itemid = 1"}],
                    "http": {"status": 200, "bytes": 900, "elapsed_ms": 10.0},
                }
        return data


@pytest.fixture()
def runtime(tmp_path: Path) -> None:
    configure(
        Settings.load("trigger", db_name="xvwa", db_user="tia_xvwa", store_path=tmp_path / "tia.db")
    )
    yield
    reset_runtime()


async def test_boolean_differential_confirms_blind_sqli(runtime: None) -> None:
    client = BlindClient()
    result = await run_request_prover(SLICE, base_url="http://target/home.php", client=client)
    assert result.verdict == "EXECUTED"
    assert result.notes["blind"]["kind"] == "boolean"
    assert result.notes["blind"]["diagnosis"] is True
    assert any(stage.stage == "P4.5" and stage.ok for stage in result.stages)


async def test_time_delay_confirms_blind_sqli(runtime: None) -> None:
    client = SleepClient()
    result = await run_request_prover(SLICE, base_url="http://target/home.php", client=client)
    assert result.verdict == "EXECUTED"
    assert result.notes["blind"]["kind"] == "time"
    assert result.notes["blind"]["detail"]["time"]["delta_ms"] >= 1100


async def test_differential_without_diagnosis_is_rejected(runtime: None) -> None:
    class NoDiagnosis(BlindClient):
        def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
            data = super()._data(tool, args)
            if tool == "probe_run":
                data["queries"] = [{"sql": "select * from caffaine where itemid = 1"}]
                data["error"] = ""
            return data

    result = await run_request_prover(
        SLICE, base_url="http://target/home.php", client=NoDiagnosis()
    )
    assert result.verdict == "NOT_EXECUTED"
    assert result.notes["blind"]["confirmed"] is False
