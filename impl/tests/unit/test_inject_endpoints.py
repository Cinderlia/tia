"""Inject entry discovery when the write path is not a <form> (AJAX / link / source)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tia.dom.inject import run_inject
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import Envelope

PAGE_GET = (
    '<html><body><form action="" method="get">'
    '<input type="text" name="comment">'
    '<input type="number" name="qty">'
    '<input type="submit" value="search"></form></body></html>'
)
PAGE_AJAX = (
    "<html><body>"
    '<input type="hidden" name="nonce" value="n-1">'
    '<script>var ajaxurl = "/wp-admin/admin-ajax.php";</script>'
    "<p>settings</p></body></html>"
)
PHP_GET = """
$comment = $_GET['comment'];
$stmt = $conn1->prepare("insert into comments (comment) values(:comment)");
$stmt->bindParam(":comment", $comment);
"""
PHP = """
$text = $_POST['text'];
$.post(ajaxurl, {action: 'save_text', text: text});
$stmt = $conn1->prepare("insert into comments (comment) values(:comment)");
$stmt->bindParam(":comment", $text);
"""


class AjaxEntryClient:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.posted: list[dict[str, Any]] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        args = dict(arguments or {})
        return Envelope.success(
            tool=tool, profile="inject", data=self._data(tool, args), cost_ms=1
        )

    def _verify(self) -> dict[str, Any]:
        return {
            "found": bool(self.posted),
            "occurrence_count": 1,
            "encoded_count": 0,
            "occurrences": [],
            "best": {
                "context_kind": "html_text",
                "executable": True,
                "executable_reason": "HTML_EXECUTABLE",
            },
        }

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "case_open":
            return {
                "case_id": "case-endpoint",
                "read_point": {"file": "settings.php", "line": 20},
                "open_questions": [],
            }
        if tool == "source_read":
            return {
                "file": "settings.php",
                "total_lines": 10,
                "sha256": "abc",
                "lines": [
                    {"n": i + 1, "text": line, "in_comment": False, "in_string": False}
                    for i, line in enumerate(
                        getattr(self, "php", PHP).splitlines()
                    )
                ],
            }
        if tool == "http_request":
            return {
                "status": 200,
                "body": getattr(self, "page", PAGE_AJAX),
                "content_type": "text/html",
            }
        if tool == "probe_arm":
            return {"probe_id": "probe-1", "armed_at": "2026-11-25T00:00:00+00:00"}
        if tool == "probe_run":
            self.posted.append(args)
            return {
                "hit": True,
                "mode": "write",
                "queries": [
                    {
                        "sql": "insert into comments (comment) values('x')",
                        "bindings": ["x"],
                        "affected_rows": 1,
                        "last_insert_id": 3,
                    }
                ],
                "http": {"status": 200, "bytes": 100},
            }
        if tool == "probe_disarm":
            return {"disarmed": True, "removed_output": True, "output": "x.json"}
        if tool == "verify_tag":
            return self._verify()
        if tool == "db_schema":
            return {
                "tables": [
                    {
                        "name": "comments",
                        "columns": [
                            {"name": "id", "type": "int", "length": 11},
                            {"name": "comment", "type": "varchar", "length": 100},
                        ],
                        "primary_key": ["id"],
                    }
                ]
            }
        if tool == "db_read":
            return {"rows": [{"n": 1}], "columns": ["n"]}
        if tool == "db_write":
            return {
                "change": {
                    "change_id": "ch-1",
                    "affected": 1,
                    "undo_sql": "INSERT ...",
                }
            }
        if tool == "case_report":
            return {"markdown": "# report", "evidence_refs": []}
        if tool == "case_note":
            return {"ok": True, "revision": 1}
        raise AssertionError(f"unexpected tool: {tool}")


def _slice() -> dict[str, Any]:
    return {
        "kind": "SQL",
        "sinkFile": "settings.php",
        "sinkLine": 5,
        "sinkCode": '$stmt->bindParam(":comment", $text)',
        "params": ["text"],
    }


@pytest.fixture
def runtime(tmp_path: Path) -> Any:
    configure(
        Settings.load(
            "inject",
            db_name="xvwa",
            db_user="tia_xvwa",
            store_path=tmp_path / "store.db",
        )
    )
    yield
    reset_runtime()


async def test_inject_discovers_an_ajax_endpoint(runtime: Any) -> None:
    client = AjaxEntryClient()
    result = await run_inject(
        _slice(), base_url="http://app.test/wp-admin/options.php", client=client
    )
    assert result.verdict == "EXECUTABLE", result.notes
    assert result.notes["entry_fallback"] == "endpoint"
    endpoint = result.notes["entry_endpoint"][0]
    assert "admin-ajax.php" in endpoint["url"]
    print("POSTED", client.posted)
    assert any("admin-ajax.php" in str(item.get("url")) for item in client.posted)
    sent = client.posted[0]
    assert sent["method"].upper() == "POST"
    assert "nonce=n-1" in str(sent.get("body") or "")


async def test_inject_uses_the_query_string_for_a_get_endpoint(runtime: Any) -> None:
    client = AjaxEntryClient()
    client.page = PAGE_GET
    client.php = PHP_GET
    result = await run_inject(
        {"kind": "SQL", "sinkFile": "search.php", "sinkLine": 2,
         "sinkCode": '$stmt->bindParam(":comment", $comment)', "params": ["comment"]},
        base_url="http://app.test/search.php",
        client=client,
    )
    assert result.verdict == "EXECUTABLE", result.notes
    assert result.notes["entry_method"] == "GET"
    sent = client.posted[0]
    assert sent["method"].upper() == "GET"
    params = sent.get("params") or {}
    assert "comment" in params
    assert params.get("qty") == "1"
    assert not sent.get("body")
