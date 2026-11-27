"""Second-order SQLi: the trigger stores a payload, the read page executes it.

The class owns the acceptance channel, so the stored-value path must not call
``verify_tag`` for a SQL sink: the probe is the only valid witness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from tia.dom.trigger import run_trigger
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

SOURCE = """<?php
$item = $_POST['item'];
$sql = "insert into caffaine (itemname) values ('$item')";
$conn->query($sql);
$rows = $conn->query("SELECT * FROM caffaine WHERE itemid = " . $item);
"""

SLICE = {
    "kind": "SqlInjection",
    "sinkFile": "home.php",
    "sinkLine": 3,
    "sinkCode": '$sql = "insert into caffaine (itemname) values (\'$item\')";',
    "params": ["item"],
}


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        return Envelope.success(
            tool=tool, profile="trigger", data=self._data(tool, arguments or {})
        )

    def _data(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-sqli2", "read_point": {"file": "home.php", "line": 5}}
        if tool == "source_read":
            return {
                "file": "home.php",
                "total_lines": len(SOURCE.splitlines()),
                "sha256": "abc",
                "lines": [
                    {"n": index + 1, "text": line, "in_comment": False, "in_string": False}
                    for index, line in enumerate(SOURCE.splitlines())
                ],
            }
        if tool == "db_schema":
            return {
                "tables": [
                    {
                        "name": "caffaine",
                        "primary_key": ["id"],
                        "columns": [
                            {"name": "id", "type": "int", "length": 11},
                            {"name": "itemname", "type": "varchar", "length": 100},
                        ],
                    }
                ]
            }
        if tool == "db_write":
            return {"change": {"change_id": "ch-1"}, "affected_rows": 1}
        if tool == "db_read":
            sql = str(arguments.get("sql") or "")
            if "COUNT(*)" in sql:
                return {"rows": [{"n": 1}], "columns": ["n"]}
            return {"rows": [{"id": 1, "itemname": "tia"}], "columns": ["id", "itemname"]}
        if tool == "http_request":
            return {
                "status": 200,
                "body": (
                    '<form action="home.php" method="post">'
                    '<input name="item"><input type="submit" name="submit" value="go">'
                    "</form>"
                ),
                "content_type": "text/html",
                "final_url": "http://target/home.php",
            }
        if tool == "probe_arm":
            return {"probe": {"file": "home.php", "line": 5}, "targets": []}
        if tool == "probe_run":
            values: dict[str, str] = {}
            body = str(arguments.get("body") or "")
            if body:
                values.update({k: v[0] for k, v in parse_qs(body).items()})
            for key, value in (arguments.get("params") or {}).items():
                values[str(key)] = str(value)
            needle = "".join(values.values())
            sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" + needle + "%'"
            return {
                "queries": [{"sql": sql, "rows": [{"v": needle}]}],
                "error": "",
                "http": {"status": 200},
                "by_target": [],
            }
        if tool == "probe_disarm":
            return {"disarmed": True}
        if tool in {"case_note", "case_report", "verify_tag"}:
            return {"ok": True, "found": False}
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
async def test_stored_payload_is_judged_by_the_probe(runtime: None) -> None:
    client = FakeClient()
    result = await run_trigger(
        SLICE,
        base_url="http://target/home.php",
        client=client,
        flow={"sink_class": "sqli", "writer_slice_ids": ["w1"]},
    )
    assert result.verdict == "EXECUTED"
    assert result.notes["payload_shape"] in {"quote_and", "quote_or"}
    assert "verify_tag" not in client.calls
