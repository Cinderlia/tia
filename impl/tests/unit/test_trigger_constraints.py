"""Trigger discovers database-only branch conditions and records replay steps."""

from __future__ import annotations

from typing import Any

import pytest

from tia.dom import trigger as trigger_module
from tia.dom.trigger import run_trigger
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

SOURCE = """
$title = $_POST['title'];
$content = $_POST['content'];
$sql = "insert into posts (title,content,status) values(:title,:content,:status)";
$stmt = $conn->prepare($sql);
$stmt->bindParam(":content", $content);
$rows = $conn->query("select id,title,content,status from posts");
if ($row['status'] !== 'publish') {
    echo "not visible";
}
echo "<article>" . $row['content'] . "</article>";
"""


class TrackedClient:
    """Minimal tool surface: the page only shows the payload after the UPDATE."""

    def __init__(self, *, publishable: bool = True) -> None:
        self.calls: list[str] = []
        self.publishable = publishable
        self.published = False
        self.undo_ids: list[str] = []
        self.verify_seen = 0

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        args = arguments or {}
        self.calls.append(tool)
        return Envelope.success(
            tool=tool, profile="trigger", data=self._data(tool, args), cost_ms=1
        )

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {
                "case_id": "case-constraint",
                "read_point": {"file": "post.php", "line": 12},
                "open_questions": [],
            }
        if tool in {"source_read", "source_grep"}:
            lines = [
                {"n": index + 1, "text": line, "in_comment": False, "in_string": False}
                for index, line in enumerate(SOURCE.splitlines())
            ]
            return {"file": "post.php", "total_lines": len(lines), "sha256": "x", "lines": lines}
        if tool == "http_request":
            body = "<html><article>payload ab12</article></html>" if self.published else "<html>not visible</html>"
            return {"status": 200, "body": body, "content_type": "text/html"}
        if tool == "db_schema":
            return {
                "tables": [
                    {
                        "name": "posts",
                        "columns": [
                            {"name": "id", "type": "int", "length": 11},
                            {"name": "title", "type": "varchar", "length": 100},
                            {"name": "content", "type": "text", "length": 65535},
                            {"name": "status", "type": "varchar", "length": 20},
                        ],
                        "primary_key": ["id"],
                    }
                ]
            }
        if tool == "db_read":
            return {"rows": [{"id": 7, "title": "t", "content": "payload ab12", "status": "pending"}], "row_count": 1}
        if tool == "db_write":
            sql = str(args.get("sql") or "")
            if sql.upper().startswith("UPDATE"):
                self.published = self.publishable
                return {"change": {"change_id": "ch-update", "affected": 1, "undo_sql": "UPDATE posts SET status='pending'"}}
            return {"change": {"change_id": "ch-insert", "affected": 1, "undo_sql": "DELETE FROM posts WHERE id=7"}}
        if tool == "db_undo":
            if args.get("change_id"):
                self.undo_ids.append(str(args["change_id"]))
            return {"reverted": 1, "residue": 0}
        if tool == "verify_tag":
            self.verify_seen += 1
            executable = self.published
            return {
                "found": executable,
                "occurrence_count": 1 if executable else 0,
                "encoded_count": 0,
                "occurrences": [],
                "best": {
                    "context_kind": "html_text" if executable else None,
                    "executable": executable,
                    "executable_reason": "HTML_EXECUTABLE" if executable else None,
                    "node_path": "html>body>article",
                },
                "verdict_ceiling": "EXECUTABLE",
                "warnings": [],
                "execution": {"executed": executable, "dialogs": []},
            }
        if tool == "case_report":
            return {"markdown": "# report"}
        if tool == "case_note":
            return {"ok": True}
        return {}


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(trigger_module.LlmClient, "from_env", classmethod(lambda cls: None))
    configure(settings=_settings(tmp_path))
    yield
    reset_runtime()


def _settings(tmp_path):
    from tia.inf.config import Settings

    return Settings.load("trigger", store_path=tmp_path / "tia.db")


SLICE = {
    "kind": "Xss",
    "sinkFile": "post.php",
    "sinkLine": 14,
    "sinkCode": 'echo "<article>" . $row[\'content\'] . "</article>";',
}


async def test_constraint_discovered_and_recorded_as_replay_step() -> None:
    client = TrackedClient()
    result = await run_trigger(SLICE, base_url="http://app/post.php", client=client)

    assert result.verdict == "EXECUTED"
    assert result.residue == 0
    constraints = result.notes["constraints"]
    assert len(constraints) == 1
    assert constraints[0]["column"] == "status"
    assert constraints[0]["value"] == "publish"
    assert constraints[0]["replay"] == "app_request"

    plan = result.notes["constraint_plan"]
    assert [step["kind"] for step in plan["steps"]] == ["payload", "constraint"]
    assert plan["final_trigger"]["method"] in {"GET", "POST"}
    assert plan["payload"]["table"] == "posts"


async def test_unsatisfiable_condition_is_rolled_back() -> None:
    client = TrackedClient(publishable=False)
    result = await run_trigger(SLICE, base_url="http://app/post.php", client=client)

    assert result.verdict != "EXECUTED"
    assert result.notes.get("constraints") in (None, [])
    assert "ch-update" in client.undo_ids
