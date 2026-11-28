"""Orchestration tests for inject (I0–I7) and main scheduling (M0–M6): uses a mock client, no network or MySQL dependency."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

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
        if tool == "probe_arm":
            return {"probe_id": "probe-case-inject-51", "armed_at": "2026-11-25T00:00:00+00:00"}
        if tool == "probe_run":
            self.submitted = True
            self.stored = 1
            return {
                "hit": True,
                "mode": "write",
                "queries": [
                    {
                        "sql": "insert into comments (user,comment,date) values('a','b','c')",
                        "bindings": ["a", "b", "c"],
                        "affected_rows": 1,
                        "last_insert_id": 7,
                        "matched_at": "origin",
                    }
                ],
                "http": {"status": 200, "bytes": 1234},
            }
        if tool == "probe_disarm":
            return {"disarmed": True, "removed_output": True, "output": "x.json"}
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


class ConstraintClient(FakeInjectClient):
    """The payload insert works; the read page only shows it after status=publish."""

    def __init__(self) -> None:
        super().__init__()
        self.constraint_applied = False

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "source_read" and str(args.get("file") or "").endswith("posts.php"):
            text = 'update posts set status=:status where id=:id'
            return {
                "file": "posts.php",
                "total_lines": 60,
                "sha256": "abc",
                "lines": [{"n": 40, "text": text, "in_comment": False, "in_string": False}],
            }
        if tool == "db_read":
            sql = str(args.get("sql") or "")
            if "`status`" in sql:
                value = "publish" if self.constraint_applied else "pending"
                return {"rows": [{"v": value}], "columns": ["v"]}
            return {"rows": [{"n": 1}], "columns": ["n"]}
        if tool == "probe_run":
            body = str(args.get("body") or "")
            if "status=publish" in body:
                self.constraint_applied = True
                return {
                    "hit": True,
                    "mode": "write",
                    "queries": [{"sql": "update posts set status='publish'", "affected_rows": 1}],
                    "http": {"status": 200, "html": self.page, "content_type": "text/html"},
                }
        if tool == "probe_arm":
            return {"probe_id": "probe-case-inject", "armed_at": "2026-11-25T00:00:00+00:00"}
        return super()._data(tool, args)


def _constraint_plan() -> dict[str, Any]:
    return {
        "constraints": [
            {
                "constraint_id": "dc-1",
                "table": "posts",
                "column": "status",
                "value": "publish",
                "op": "set",
                "predicate": "page shows the post only when status is publish",
            }
        ],
        "steps": [{"kind": "payload", "ref": "payload"}, {"kind": "constraint", "ref": "dc-1"}],
    }


async def test_inject_replays_database_constraint(runtime: Any) -> None:
    from tia.inf.runtime import get_runtime

    store = get_runtime().store
    ids = store.seed_slices(
        "pair-run",
        [
            {
                "kind": "Xss",
                "sinkFile": "posts.php",
                "sinkLine": 40,
                "sinkCode": "update posts set status=:status where id=:id",
                "params": ["status"],
            }
        ],
        order_mode="second",
    )
    client = ConstraintClient()
    result = await run_inject(
        _slice(),
        base_url="http://127.0.0.1/xvwa/",
        client=client,
        constraint_plan=_constraint_plan(),
        pair_candidates={
            "dc-1": [{"write_slice_id": ids[0], "page_url": "http://127.0.0.1/xvwa/posts.php", "score": 80}]
        },
    )

    assert result.verdict == "EXECUTABLE"
    steps = result.notes["constraint_steps"]
    assert len(steps) == 1
    assert steps[0]["constraint_id"] == "dc-1"
    assert steps[0]["confirmed"] is True


async def test_inject_reports_unsatisfied_constraint(runtime: Any) -> None:
    result = await run_inject(
        _slice(),
        base_url="http://127.0.0.1/xvwa/",
        client=ConstraintClient(),
        constraint_plan=_constraint_plan(),
        pair_candidates={"dc-1": []},
    )

    assert result.verdict == "CONSTRAINT_UNSATISFIED"
    assert result.notes["constraint_steps"][0]["constraint_id"] == "dc-1"


class SqlReadClient(FakeInjectClient):
    """The read page is a SQL sink: only the probe may judge it."""

    def __init__(self) -> None:
        super().__init__()
        self.read_probes = 0
        self.verify_calls: list[dict[str, Any]] = []

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "verify_tag":
            self.verify_calls.append(args)
            return {"found": False, "occurrence_count": 0, "best": {"executable": False}}
        if tool == "probe_run" and "list.php" in str(args.get("url") or ""):
            values = {
                key: item[0] for key, item in parse_qs(str(args.get("body") or "")).items()
            }
            needle = "".join(values.values())
            self.read_probes += 1
            return {
                "hit": True,
                "queries": [
                    {
                        "sql": f"SELECT * FROM comments WHERE comment LIKE '%{needle}%'",
                        "rows": [{"comment": needle}],
                    }
                ],
                "http": {"status": 200},
            }
        return super()._data(tool, args)


async def test_inject_sql_read_channel_uses_probe(runtime: Any) -> None:
    client = SqlReadClient()
    result = await run_inject(
        {**_slice(), "kind": "SqlInjection"},
        base_url="http://127.0.0.1/xvwa/",
        client=client,
        read_target={"file": "list.php", "line": 12},
        verify_url="http://127.0.0.1/xvwa/list.php",
        verify_entry={"method": "POST", "fields": [{"name": "item", "type": "text"}]},
        verify_values={"item": "abcd"},
        flow={"sink_class": "sqli", "flow_id": "flow-sql"},
    )
    assert result.verdict == "EXECUTABLE"
    assert result.notes["verify_on"] == "sql_probe"
    assert client.read_probes >= 1
    assert not [call for call in client.verify_calls if "list.php" in str(call.get("url") or "")]


class FakeNeedsParentClient(FakeInjectClient):
    """The write path only succeeds after a scaffold parent row exists."""

    def __init__(self) -> None:
        super().__init__()
        self.posts = 0
        self.sent: list[dict[str, Any]] = []

    def _data(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "db_schema":
            table = str(args.get("table") or "comments")
            if table == "posts":
                return {
                    "tables": [
                        {
                            "name": "posts",
                            "primary_key": ["id"],
                            "columns": [
                                {"name": "id", "type": "int", "column_type": "int(11)",
                                 "nullable": False, "default": None,
                                 "extra": "auto_increment", "length": None},
                                {"name": "label", "type": "varchar",
                                 "column_type": "varchar(20)", "nullable": False,
                                 "default": None, "extra": "", "length": 20},
                            ],
                            "fks": [],
                        }
                    ]
                }
            return {
                "tables": [
                    {
                        "name": "comments",
                        "primary_key": ["id"],
                        "columns": [
                            {"name": "id", "type": "int", "column_type": "int(11)",
                             "nullable": False, "default": None,
                             "extra": "auto_increment", "length": None},
                            {"name": "parent_id", "type": "int",
                             "column_type": "int(11)", "nullable": False,
                             "default": None, "extra": "", "length": None},
                            {"name": "comment", "type": "varchar",
                             "column_type": "varchar(100)", "nullable": False,
                             "default": None, "extra": "", "length": 100},
                        ],
                        "fks": [
                            {"column": "parent_id", "ref_table": "posts",
                             "ref_column": "id", "delete_rule": "CASCADE"}
                        ],
                    }
                ]
            }
        if tool == "probe_run":
            self.sent.append(dict(parse_qs(str(args.get("body") or ""))))
            if self.posts == 0:
                return {
                    "hit": False,
                    "queries": [],
                    "http": {"status": 200, "bytes": 100, "html": "<html>error</html>"},
                }
            self.submitted = True
            return {
                "hit": True,
                "queries": [
                    {
                        "sql": "insert into comments (parent_id,comment) values(9,'tia')",
                        "affected_rows": 1,
                        "last_insert_id": 3,
                    }
                ],
                "http": {"status": 200, "bytes": 100, "html": PAGE_WITH_FORM},
            }
        if tool == "db_write":
            sql = str(args.get("sql") or "")
            if sql.lower().startswith("insert into `posts`"):
                self.posts = 1
                return {"change": {"change_id": "ch-parent", "after_image": [{"id": 9}]}}
            return {"change": {"change_id": "ch-write", "affected": 1}}
        if tool == "db_read":
            sql = str(args.get("sql") or "")
            if "FROM `posts`" in sql:
                return {"rows": []}
            return {"rows": [{"n": self.posts}], "columns": ["n"]}
        if tool == "verify_tag":
            return self._verify(args)
        return super()._data(tool, args)


async def test_inject_creates_the_parent_row_the_write_path_needs(runtime: Any) -> None:
    client = FakeNeedsParentClient()
    result = await run_inject(_slice(), base_url="http://127.0.0.1/xvwa/", client=client)
    assert result.verdict == "EXECUTABLE"
    assert result.notes["state_plan"]["status"] == "READY"
    assert result.notes["state_plan"]["values"] == {"parent_id": "9"}
    assert result.notes["state_probe_retry"]["probed"] is True
    assert client.posts == 1
