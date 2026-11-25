"""Orchestration tests for inject (I0–I7) and main scheduling (M0–M6): uses a mock client, no network or MySQL dependency."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.inject import run_inject
from tia.dom.main import run_main
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

PAGE_WITH_FORM = (
    '<html><body><form action="" method="post">'
    '<input type="text" name="name"><textarea name="msg"></textarea>'
    '<input type="submit" value="go"></form></body></html>'
)
PAGE_PLAIN = "<html><body><p>no form here</p></body></html>"
PHP = """
$user = $_POST['name'];
$comment = $_POST['msg'];
$stmt = $conn1->prepare("insert into comments (user,comment,date) values(:user,:comment,:date)");
$stmt->bindParam(":user", $user);
$stmt->bindParam(":comment", $comment);
"""


class FakeInjectClient:
    def __init__(self, *, page: str = PAGE_WITH_FORM, baseline_dirty: bool = False) -> None:
        self.calls: list[str] = []
        self.page = page
        self.baseline_dirty = baseline_dirty
        self.stored = 0
        self.submitted = False

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        return Envelope.success(
            tool=tool, profile="inject", data=self._data(tool, dict(arguments or {})), cost_ms=1
        )

    def _verify(self, args: dict[str, Any]) -> dict[str, Any]:
        found = self.submitted or self.baseline_dirty
        return {
            "found": found,
            "occurrence_count": 1 if found else 0,
            "encoded_count": 0,
            "occurrences": [],
            "best": {"context_kind": "html_text", "executable": True, "executable_reason": "HTML_EXECUTABLE"},
        }

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {"case_id": "case-inject", "read_point": {"file": "home.php", "line": 49}, "open_questions": []}
        if tool == "verify_tag":
            return self._verify(args)
        if tool == "source_read":
            return {
                "file": "home.php",
                "total_lines": 60,
                "sha256": "abc",
                "lines": [{"n": i + 1, "text": line, "in_comment": False, "in_string": False}
                          for i, line in enumerate(PHP.splitlines())],
            }
        if tool == "http_request":
            if str(args.get("method", "GET")).upper() == "POST":
                self.submitted = True
                self.stored = 1
                return {"status": 200, "body": self.page, "content_type": "text/html"}
            return {"status": 200, "body": self.page, "content_type": "text/html"}
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
        if tool == "db_read":
            return {"rows": [{"n": self.stored}], "columns": ["n"]}
        if tool == "db_write":
            self.stored = 0
            return {"change": {"change_id": "ch-inject", "affected": 1, "undo_sql": "INSERT ..."}}
        if tool == "case_report":
            return {"markdown": "# inject report", "evidence_refs": []}
        if tool == "case_note":
            return {"ok": True, "revision": 1}
        raise AssertionError(f"unexpected tool: {tool}")


@pytest.fixture()
def runtime(tmp_path: Path):
    configure(Settings.load("inject", db_name="xvwa", db_user="tia_xvwa", store_path=tmp_path / "tia.db"))
    yield
    reset_runtime()


def _slice() -> dict[str, Any]:
    return {
        "kind": "SQL",
        "sinkFile": "home.php",
        "sinkLine": 49,
        "sinkCode": '$stmt->bindParam(":comment",$comment)',
        "params": ["msg"],
    }


async def test_inject_executable(runtime: Any) -> None:
    client = FakeInjectClient()
    result = await run_inject(_slice(), base_url="http://127.0.0.1/xvwa/", client=client)
    assert result.verdict == "EXECUTABLE"
    assert result.residue == 0
    assert [s.stage for s in result.stages] == ["I0", "I1", "I2", "I3", "I4", "I5", "I6", "I6", "I7"]
    assert result.notes["tag_in_db"] is True
    assert "db_write" in client.calls


async def test_inject_baseline_dirty(runtime: Any) -> None:
    result = await run_inject(_slice(), base_url="http://127.0.0.1/xvwa/", client=FakeInjectClient(baseline_dirty=True))
    assert result.verdict == "BASELINE_DIRTY"


async def test_inject_no_form(runtime: Any) -> None:
    result = await run_inject(_slice(), base_url="http://127.0.0.1/xvwa/", client=FakeInjectClient(page=PAGE_PLAIN))
    assert result.verdict == "NO_HTTP_ENTRY"


class FakeTriggerClient(FakeInjectClient):
    """trigger only requires case_open/source_read/http_request/db_schema/db_write/verify_tag/db_undo."""

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        args = dict(arguments or {})
        if tool == "verify_tag":
            return Envelope.success(
                tool=tool,
                profile="trigger",
                data={
                    "found": True,
                    "occurrence_count": 1,
                    "encoded_count": 0,
                    "occurrences": [],
                    "best": {"context_kind": "html_text", "executable": True, "executable_reason": "HTML_EXECUTABLE"},
                },
                cost_ms=1,
            )
        if tool == "db_undo":
            return Envelope.success(tool=tool, profile="trigger", data={"reverted": [], "residue": 0}, cost_ms=1)
        if tool == "db_read":
            return Envelope.success(tool=tool, profile="trigger", data={"rows": [{"n": 1}], "columns": ["n"]}, cost_ms=1)
        return Envelope.success(tool=tool, profile="trigger", data=self._data(tool, args), cost_ms=1)


async def test_main_runs_trigger_then_inject(runtime: Any) -> None:
    result = await run_main(
        [_slice()],
        base_url="http://127.0.0.1/xvwa/",
        limit=1,
        trigger_client=FakeTriggerClient(),
        inject_client=FakeInjectClient(),
    )
    assert result.stop_reason == "DONE"
    assert len(result.outcomes) == 1
    outcome = result.outcomes[0]
    assert outcome.notes["trigger"] == "EXECUTED"
    assert outcome.verdict == "EXECUTABLE"
    assert outcome.evidence_refs
    assert "# TIA Scheduling Report" in result.report
