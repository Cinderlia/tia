"""SQLi flow tests: the payload must be seen inside an executed statement."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from tia.dom.request_prover import run_request_prover
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

SOURCE = """<?php
$item = isset($_POST['item']) ? $_POST['item'] : '';
$sql = "select * from caffaine where itemid = ".$item;
$result = $conn->query($sql);
"""

SLICE = {
    "kind": "SqlInjection",
    "sinkFile": "home.php",
    "sinkLine": 3,
    "sinkCode": '$sql = "select * from caffaine where itemid = ".$item;',
    "params": ["item"],
    "sqlProbe": {"extensionConfig": {"file": "home.php", "line": "3"}},
}


WRITE_SOURCE = """<?php
$entry = isset($_POST['entry']) ? $_POST['entry'] : '';
$sql = "INSERT INTO blog (date, entry, owner) VALUES (now(),'".$entry."','".$owner."')";
$result = $conn->query($sql);
"""

WRITE_SLICE = {
    "kind": "SqlWriteLoose",
    "sinkFile": "blog.php",
    "sinkLine": 3,
    "sinkCode": "INSERT INTO blog (date, entry, owner)",
    "params": ["entry"],
    "sqlProbe": {"extensionConfig": {"file": "blog.php", "line": "3"}},
}


class FakeSqliClient:
    def __init__(self, *, hit: bool, source: str = SOURCE) -> None:
        self.hit = hit
        self.source = source
        self.calls: list[str] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        return Envelope.success(tool=tool, profile="trigger", data=self._data(tool, arguments or {}))

    def _data(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-sqli", "read_point": {"file": "home.php", "line": 3}}
        if tool == "source_read":
            return {
                "file": "home.php",
                "total_lines": len(SOURCE.splitlines()),
                "sha256": "abc",
                "lines": [
                    {"n": index + 1, "text": line, "in_comment": False, "in_string": False}
                    for index, line in enumerate(self.source.splitlines())
                ],
            }
        if tool == "http_request":
            return {
                "status": 200,
                "body": (
                    '<form action="home.php" method="post">'
                    '<input name="item"><input name="entry"><button name="blog" value="add">'
                    "</form>"
                ),
                "content_type": "text/html",
                "final_url": "http://target/home.php",
            }
        if tool == "probe_arm":
            return {"probe_id": "p1", "target": {"file": "home.php", "line": 3}}
        if tool == "probe_run":
            if not self.hit:
                return {"hit": False, "queries": [], "error": ""}
            body = str(arguments.get("body") or "")
            payload = (parse_qs(body).get("item") or [""])[0]
            sql = f"select * from caffaine where itemid = {payload}"
            return {"hit": True, "queries": [{"sql": sql}], "error": ""}
        if tool == "probe_disarm":
            return {"disarmed": True}
        if tool in {"case_note", "case_report"}:
            return {"ok": True}
        return {}


@pytest.fixture()
def runtime(tmp_path: Path) -> None:
    settings = Settings.load(
        "trigger", db_name="xvwa", db_user="tia_xvwa", store_path=tmp_path / "tia.db"
    )
    configure(settings)
    yield
    reset_runtime()


@pytest.mark.asyncio
async def test_marker_in_executed_sql_is_executed(runtime: None) -> None:
    client = FakeSqliClient(hit=True)
    result = await run_request_prover(SLICE, base_url="http://target/home.php", client=client)
    assert result.verdict == "EXECUTED"
    assert result.notes["payload_shape"] == "numeric_or"
    assert result.notes["attempts"][0]["marker_seen"] is True


@pytest.mark.asyncio
async def test_no_probe_output_is_not_executed(runtime: None) -> None:
    client = FakeSqliClient(hit=False)
    result = await run_request_prover(SLICE, base_url="http://target/home.php", client=client)
    assert result.verdict == "NOT_EXECUTED"
    assert result.notes["attempts"][0]["marker_seen"] is False


def test_sql_body_reduces_a_source_assignment_to_its_statement() -> None:
    from tia.dom.request_prover import _sql_body

    raw = '$sql = "INSERT INTO blog (date, entry) VALUES (now(), 1)";'
    assert _sql_body(raw) == "INSERT INTO blog (date, entry) VALUES (now(), 1)"


@pytest.mark.asyncio
async def test_write_statement_registers_a_cleanup_target(runtime: None) -> None:
    case: dict[str, Any] = {}
    client = FakeSqliClient(hit=True, source=WRITE_SOURCE)

    await run_request_prover(
        WRITE_SLICE, base_url="http://target/blog.php", client=client, case=case
    )

    cleanup = case.get("cleanup") or {}
    assert cleanup.get("table") == "blog"
    assert "entry" in (cleanup.get("columns") or [])
    assert cleanup.get("tag")
