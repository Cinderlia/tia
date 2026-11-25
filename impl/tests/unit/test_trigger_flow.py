"""Orchestration tests for the trigger main flow (P0–P6).

Tools are provided by a mock client; no real range is connected. Real range validation is in scripts/smoke-trigger.sh.
This allows CI to run, decoupling flow decisions (stage order, verdict, undo) from network/database.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.trigger import run_trigger
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

SOURCE = """
$user = $_POST['name'];
$comment = $_POST['msg'];
$sql = "insert into comments (user,comment,date) values(:user,:comment,:date)";
$stmt = $conn1->prepare($sql);
$stmt->bindParam(":comment", $comment);
$stmt2 = $conn1->prepare("select user,comment,date from comments");
echo "<p>" . $rows[1] . "</p>";
"""


class FakeClient:
    def __init__(self, *, verify_found: bool = True, executable: bool = True) -> None:
        self.calls: list[str] = []
        self.verify_found = verify_found
        self.executable = executable

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        data = self._data(tool)
        return Envelope.success(tool=tool, profile="trigger", data=data, cost_ms=1)

    def _data(self, tool: str) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-test", "read_point": {"file": "home.php", "line": 5}, "open_questions": []}
        if tool == "source_read":
            return {
                "file": "home.php",
                "total_lines": 20,
                "sha256": "abc",
                "lines": [{"n": index + 1, "text": line, "in_comment": False, "in_string": False}
                          for index, line in enumerate(SOURCE.splitlines())],
            }
        if tool == "http_request":
            return {
                "status": 200,
                "body": '<form action="home.php" method="post"><input name="msg"></form>',
                "content_type": "text/html",
            }
        if tool == "db_schema":
            return {
                "tables": [
                    {
                        "name": "comments",
                        "columns": [
                            {"name": "id", "type": "int", "length": 11},
                            {"name": "user", "type": "varchar", "length": 30},
                            {"name": "comment", "type": "varchar", "length": 100},
                            {"name": "date", "type": "varchar", "length": 30},
                        ],
                        "primary_key": ["id"],
                    }
                ]
            }
        if tool == "db_write":
            return {"change": {"change_id": "ch-test", "affected": 1, "undo_sql": "DELETE FROM comments WHERE id = 9"}}
        if tool == "verify_tag":
            return {
                "found": self.verify_found,
                "occurrence_count": 1 if self.verify_found else 0,
                "encoded_count": 0,
                "occurrences": [],
                "best": {
                    "context_kind": "html_text",
                    "executable": self.executable,
                    "executable_reason": "HTML_EXECUTABLE" if self.executable else "NO_CARRIER",
                    "node_path": "html>body>p",
                },
            }
        if tool == "db_undo":
            return {"reverted": [{"change_id": "ch-test", "ok": True, "rows": 1}], "residue": 0}
        if tool == "case_report":
            return {"markdown": "# report", "evidence_refs": [], "artifacts": []}
        if tool == "case_note":
            return {"ok": True, "revision": 1}
        raise AssertionError(f"unexpected tool: {tool}")


@pytest.fixture()
def runtime(tmp_path: Path):
    settings = Settings.load("trigger", db_name="xvwa", db_user="tia_xvwa", store_path=tmp_path / "tia.db")
    configure(settings)
    yield settings
    reset_runtime()


def _slice() -> dict[str, Any]:
    return {
        "kind": "SQL",
        "sink": "home.php:5  $stmt->bindParam(\":comment\",$comment)",
        "params": ["msg"],
    }


async def test_trigger_stage_order_and_verdict(runtime: Any) -> None:
    client = FakeClient()
    result = await run_trigger(_slice(), base_url="http://127.0.0.1/xvwa/", client=client)
    assert result.verdict == "EXECUTED"
    assert result.residue == 0
    assert [stage.stage for stage in result.stages] == ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P6"]
    assert result.notes["table"] == "comments"
    assert result.notes["tag"] in result.notes["payload"]
    # DB writes and acceptance must actually occur
    assert "db_write" in client.calls and "verify_tag" in client.calls and "db_undo" in client.calls
    # All evidence is attached to the case
    assert result.report == "# report"


async def test_trigger_reflected_encoded_is_not_executed(runtime: Any) -> None:
    result = await run_trigger(_slice(), base_url="http://127.0.0.1/xvwa/", client=FakeClient(executable=False))
    assert result.verdict == "REFLECTED_INERT"


async def test_trigger_not_reflected(runtime: Any) -> None:
    result = await run_trigger(_slice(), base_url="http://127.0.0.1/xvwa/", client=FakeClient(verify_found=False))
    assert result.verdict == "READ_NOT_REFLECTED"
