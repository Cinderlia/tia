from __future__ import annotations

import pytest

from tia.dom.copy_run import COPY_NOT_REACHED, COPY_TAG_LOST, run_copy_chain

PATH = {
    "path_id": "cp-1",
    "table": "b",
    "column": "body",
    "hops": [
        {"write_slice_id": "s1", "table": "a", "column": "draft", "is_copy": False},
        {"write_slice_id": "s2", "table": "b", "column": "body", "is_copy": True},
    ],
}
RAW = {
    "s1": {"sinkFile": "vulns/write.php", "sinkLine": 10, "params": ["text"]},
    "s2": {"sinkFile": "vulns/copy.php", "sinkLine": 20, "params": ["id"]},
}


class FakeCall:
    def __init__(self, *, stored: int = 1, status: int = 302) -> None:
        self.stored = stored
        self.status = status
        self.armed: list[dict] = []
        self.sent: list[dict] = []
        self.reads: list[str] = []

    async def __call__(self, tool: str, arguments: dict) -> dict:
        if tool == "probe_arm":
            self.armed.append(arguments)
            return {}
        if tool == "probe_disarm":
            return {}
        if tool == "probe_run":
            self.sent.append(arguments)
            queries = (
                [] if self.status >= 400 else [{"sql": "INSERT INTO a (draft) VALUES ('x')"}]
            )
            return {"status": self.status, "queries": queries}
        if tool == "db_read":
            self.reads.append(arguments["sql"])
            return {"rows": [{"n": self.stored}]}
        raise AssertionError(tool)


@pytest.mark.asyncio
async def test_chain_writes_the_marker_and_verifies_the_read_column() -> None:
    call = FakeCall()
    result = await run_copy_chain(
        call,
        case_id="case-1",
        copy_path={**PATH, "hops": [{**hop, "raw": RAW[hop["write_slice_id"]], "url": "http://x/"} for hop in PATH["hops"]]},
        base_url="http://x/vulns/",
        payload="<script>tag</script>",
        tag="tag",
    )
    assert result["ok"] is True
    assert result["stored"] == 1
    assert [hop["ok"] for hop in result["hops"]] == [True, True]
    assert call.sent[0]["body"].startswith("text=")
    assert "1" in call.sent[1]["body"]
    assert "body" in call.reads[0] and "tag" in call.reads[0]


@pytest.mark.asyncio
async def test_a_hop_that_does_not_reach_its_handler_stops_the_chain() -> None:
    call = FakeCall(status=500)
    result = await run_copy_chain(
        call,
        case_id="case-1",
        copy_path={**PATH, "hops": [{**hop, "raw": RAW[hop["write_slice_id"]], "url": "http://x/"} for hop in PATH["hops"]]},
        base_url="http://x/vulns/",
        payload="p",
        tag="tag",
    )
    assert result["ok"] is False
    assert result["failed_kind"] == COPY_NOT_REACHED


@pytest.mark.asyncio
async def test_a_chain_that_runs_but_loses_the_marker_reports_the_column() -> None:
    call = FakeCall(stored=0)
    result = await run_copy_chain(
        call,
        case_id="case-1",
        copy_path={**PATH, "hops": [{**hop, "raw": RAW[hop["write_slice_id"]], "url": "http://x/"} for hop in PATH["hops"]]},
        base_url="http://x/vulns/",
        payload="p",
        tag="tag",
    )
    assert result["ok"] is False
    assert result["failed_kind"] == COPY_TAG_LOST
