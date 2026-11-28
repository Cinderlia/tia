"""Flow queue: sites -> flows -> prover -> legal replay."""

from __future__ import annotations

from typing import Any

import pytest

from tia.dom.flow_main import run_flow_queue, seed_flow_queue
from tia.inf.runtime import configure, reset_runtime
from tia.inf.store import Store
from tia.orch.flow import READ, WRITE, Site, build_flows
from tia.schemas.envelope import Envelope
from tia.sinks.base import Observation
from tia.sinks.registry import sink_class_for

READ_SLICE = {
    "kind": "Xss",
    "sinkFile": "templates/list.php",
    "sinkLine": 13,
    "sinkCode": "echo $row['comment'];",
    "sources": [{"file": "list.php", "line": 26, "code": "select comment from posts", "param": "search"}],
}

WRITE_SLICE = {
    "kind": "SqlWriteLoose",
    "sinkFile": "actions/write.php",
    "sinkLine": 27,
    "sinkCode": 'bindParam(":comment", $comment)',
    "params": ["comment"],
    "sources": [{"file": "actions/write.php", "line": 23, "code": "insert into posts (comment)"}],
}


def _site(raw: dict[str, Any], role: str, table: str, columns: tuple[str, ...], score: int = 50) -> Site:
    return Site(
        slice_id=f"s-{role}-{raw['sinkLine']}",
        raw=raw,
        role=role,
        kind=str(raw["kind"]),
        file=str(raw["sinkFile"]),
        line=int(raw["sinkLine"]),
        table=table,
        columns=columns,
        score=score,
    )


def test_build_flows_groups_reads_with_matching_writers() -> None:
    read = _site(READ_SLICE, READ, "posts", ("comment",))
    write = _site(WRITE_SLICE, WRITE, "posts", ("comment",))
    other = _site({**WRITE_SLICE, "sinkLine": 99}, WRITE, "users", ("name",))

    flows = build_flows([read, write, other])

    assert len(flows) == 1
    assert flows[0].target_slice_id == read.slice_id
    assert flows[0].writer_slice_ids == [write.slice_id]
    assert flows[0].sink_class == "xss"
    assert "write site(s) feed table posts" in " ".join(flows[0].reasons)


def test_build_flows_direct_has_no_writers() -> None:
    read = _site(READ_SLICE, READ, "", ())
    read.family = "direct"
    flows = build_flows([read])
    assert len(flows) == 1
    assert flows[0].writer_slice_ids == []
    assert flows[0].family == "direct"


def test_sites_keep_read_and_write_roles_separate(tmp_path) -> None:
    store = Store(tmp_path / "tia.db")
    common = {**READ_SLICE, "sinkFile": "same.php", "sinkLine": 10}
    read_id = store.insert_site("run", common, family="second", role="read", chain="xss-second-order")
    write_id = store.insert_site("run", common, family="second", role="write", chain="sqlwrite-direct")
    again = store.insert_site("run", common, family="second", role="read", chain="xss-second-order")

    assert read_id and write_id and read_id != write_id
    assert again == read_id
    row = store.get_slice(str(read_id))
    assert row is not None
    assert row["role"] == "read"
    assert row["chain"] == "xss-second-order"


def test_seed_flow_queue_and_lease(tmp_path) -> None:
    store = Store(tmp_path / "tia.db")
    seeded = seed_flow_queue(
        store,
        "run-1",
        [
            {"raw": READ_SLICE, "family": "second", "role": "read"},
            {"raw": WRITE_SLICE, "family": "second", "role": "write"},
        ],
    )

    assert seeded.sites == 2
    assert seeded.flows == 1
    pending = store.peek_flows("run-1")
    assert len(pending) == 1
    assert pending[0]["sink_class"] == "xss"

    leased = store.next_flow("run-1")
    assert leased is not None
    assert leased["status"] == "running"
    assert store.next_flow("run-1") is None
    assert store.archive_flow(leased["flow_id"], "reported", "EXECUTABLE", case_id="case-1")
    stored = store.get_flow(leased["flow_id"])
    assert stored is not None and stored["verdict"] == "EXECUTABLE"


class FailingTrigger:
    """Minimal tool surface: the page 500s, so the prover stops at P2."""

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        data: dict[str, Any] = {}
        if tool == "case_open":
            data = {"case_id": "case-flow", "read_point": {}, "open_questions": []}
        elif tool == "source_read":
            lines = [
                {"n": 1, "text": "$comment = $_POST['comment'];", "in_comment": False, "in_string": False},
                {"n": 2, "text": 'insert into posts (comment) values(:comment)', "in_comment": False, "in_string": False},
            ]
            data = {"file": "actions/write.php", "total_lines": 2, "sha256": "x", "lines": lines}
        elif tool == "http_request":
            data = {"status": 500, "body": "boom", "content_type": "text/html"}
        elif tool == "case_report":
            data = {"markdown": "# report"}
        return Envelope.success(tool=tool, profile="trigger", data=data, cost_ms=1)


@pytest.fixture()
def _runtime(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tia.inf.config import Settings

    configure(settings=Settings.load("trigger", store_path=tmp_path / "tia.db"))
    yield
    reset_runtime()


async def test_run_flow_queue_archives_failed_flows(tmp_path, _runtime) -> None:
    store = Store(tmp_path / "tia.db")
    seed_flow_queue(
        store,
        "run-2",
        [
            {"raw": READ_SLICE, "family": "second", "role": "read"},
            {"raw": WRITE_SLICE, "family": "second", "role": "write"},
        ],
    )

    result = await run_flow_queue(store, "http://app/list.php", "run-2", trigger_client=FailingTrigger())

    assert result.stop_reason == "DONE"
    assert len(result.outcomes) == 1
    assert result.outcomes[0].verdict in {"READ_EMPTY", "ERROR"}
    flow = store.list_flow_jobs("run-2")[0]
    assert flow["status"] == "failed"


def test_xss_class_accepts_executable_observation() -> None:
    plugin = sink_class_for("Xss")
    verify = {
        "found": True,
        "best": {"executable": True, "executable_reason": "HTML_EXECUTABLE", "context_kind": "html_text"},
    }
    outcome = plugin.accept(Observation("page", facts={"verify": verify}), "html_text")
    assert outcome.confirmed
    assert outcome.level == "EXECUTABLE"

    encoded = {
        "found": True,
        "best": {"executable": False, "match_kind": "encoded", "context_kind": "html_text"},
    }
    assert not plugin.accept(Observation("page", facts={"verify": encoded}), "html_text").confirmed


SQLI_SLICE = {
    "kind": "SqlInjection",
    "sinkFile": "home.php",
    "sinkLine": 3,
    "sinkCode": '$sql = "select * from caffaine where itemid = ".$item;',
    "params": ["item"],
    "sqlProbe": {"extensionConfig": {"file": "home.php", "line": "3"}},
}

SQLI_SOURCE = """<?php
$item = isset($_POST['item']) ? $_POST['item'] : '';
$sql = "select * from caffaine where itemid = ".$item;
$result = $conn->query($sql);
"""


class ProvingSqliClient:
    """Trigger-side tools: the probe sees the payload inside the executed SQL."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        args = arguments or {}
        data: dict[str, Any] = {}
        if tool == "case_open":
            data = {"case_id": "case-sqli-flow", "read_point": {"file": "home.php", "line": 3}}
        elif tool == "source_read":
            data = {
                "file": "home.php",
                "total_lines": len(SQLI_SOURCE.splitlines()),
                "sha256": "x",
                "lines": [
                    {"n": index + 1, "text": line, "in_comment": False, "in_string": False}
                    for index, line in enumerate(SQLI_SOURCE.splitlines())
                ],
            }
        elif tool == "http_request":
            data = {
                "status": 200,
                "body": '<form action="home.php" method="post"><input name="item"></form>',
                "content_type": "text/html",
                "final_url": "http://app/home.php",
            }
        elif tool == "probe_arm":
            data = {"probe_id": "p1", "target": {"file": "home.php", "line": 3}}
        elif tool == "probe_run":
            body = str(args.get("body") or "")
            payload = (body.split("=", 1)[1] if "=" in body else "").split("&", 1)[0]
            data = {"hit": True, "queries": [{"sql": f"select * from caffaine where itemid = {payload}"}]}
        elif tool in {"case_note", "case_report", "case_verdict", "probe_disarm"}:
            data = {"ok": True}
        return Envelope.success(tool=tool, profile="trigger", data=data, cost_ms=1)


class ExplodingInjectClient:
    """The replay step must never run for a class that does not persist a payload."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        self.calls.append(tool)
        raise AssertionError(f"inject client must not be called for a request-only sink ({tool})")


@pytest.mark.asyncio
async def test_request_only_flow_ends_at_the_prover(tmp_path, _runtime) -> None:
    store = Store(tmp_path / "tia.db")
    read_id = store.insert_site(
        "run-sql",
        SQLI_SLICE,
        family="second",
        chain="sqlwrite-second-order",
        role=READ,
        identity="home.php:3:read",
        score=80,
        reasons=[],
        digest={},
    )
    write_id = store.insert_site(
        "run-sql",
        WRITE_SLICE,
        family="second",
        chain="sqlwrite-direct",
        role=WRITE,
        identity="actions/write.php:27:write",
        score=50,
        reasons=[],
        digest={},
    )
    assert read_id and write_id
    flow = build_flows(
        [
            _site(SQLI_SLICE, READ, "caffaine", ("itemid",), score=80),
            _site(WRITE_SLICE, WRITE, "caffaine", ("itemid",), score=50),
        ]
    )[0]
    flow = flow.__class__(**{**flow.__dict__, "target_slice_id": read_id, "writer_slice_ids": [write_id]})
    store.seed_flows("run-sql", [flow.to_row()])

    prover = ProvingSqliClient()
    inject = ExplodingInjectClient()
    result = await run_flow_queue(
        store, "http://app/home.php", "run-sql", trigger_client=prover, inject_client=inject
    )

    assert result.stop_reason == "DONE"
    assert [outcome.verdict for outcome in result.outcomes] == ["EXECUTED"]
    assert inject.calls == []
    assert store.list_flow_jobs("run-sql")[0]["status"] == "reported"


SQLI_READ_SLICE = {
    "kind": "SqlRead",
    "sinkFile": "home.php",
    "sinkLine": 61,
    "sinkCode": "SELECT * FROM caffaine WHERE itemname LIKE '%\".$search.\"%'",
    "params": ["search"],
    "sqlProbe": {"extensionConfig": {"file": "home.php", "line": "61"}},
}


@pytest.mark.asyncio
async def test_direct_flow_with_a_sql_read_sink_uses_the_request_prover(
    tmp_path, _runtime
) -> None:
    store = Store(tmp_path / "tia.db")
    read_id = store.insert_site(
        "run-sqldir",
        SQLI_READ_SLICE,
        family="direct",
        chain="sqlread-direct",
        role=READ,
        identity="home.php:61:read",
        score=70,
        reasons=[],
        digest={},
    )
    flow = build_flows([_site(SQLI_READ_SLICE, READ, "caffaine", ("itemname",), score=70)])[0]
    flow = flow.__class__(
        **{**flow.__dict__, "target_slice_id": read_id, "writer_slice_ids": []}
    )
    store.seed_flows("run-sqldir", [flow.to_row()])

    prover = ProvingSqliClient()
    inject = ExplodingInjectClient()
    result = await run_flow_queue(
        store, "http://app/home.php", "run-sqldir", trigger_client=prover, inject_client=inject
    )

    assert result.stop_reason == "DONE"
    assert [outcome.verdict for outcome in result.outcomes] == ["EXECUTED"]
    assert inject.calls == []
    assert "probe_run" in prover.calls
