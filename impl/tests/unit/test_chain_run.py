"""Tests for walking a chain of application writes (seed, then transforms)."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from tia.dom.chain_run import CHAIN_STEP_NOT_REACHED, CHAIN_TAG_LOST, run_chain


class ChainClient:
    """A tiny application: seed writes table a, transform copies a into b."""

    def __init__(self, *, lose_tag: bool = False) -> None:
        self.a: list[str] = []
        self.b: list[str] = []
        self.lose_tag = lose_tag
        self.armed: list[dict[str, Any]] = []
        self.bodies: list[str] = []

    async def __call__(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "probe_arm":
            self.armed.append(dict(arguments))
            return {"armed": True}
        if tool == "probe_disarm":
            return {"disarmed": True}
        if tool == "db_read":
            sql = str(arguments.get("sql") or "")
            import re

            match = re.search(r"LIKE '%([^']*)%'", sql)
            needle = match.group(1) if match else ""
            rows = self.a if "`a`" in sql else self.b
            return {"rows": [{"n": sum(1 for value in rows if needle in value)}]}
        if tool != "probe_run":
            raise AssertionError(tool)
        body = str(arguments.get("body") or "")
        self.bodies.append(body)
        values = parse_qs(body)
        url = str(arguments.get("url") or "")
        if url.endswith("seed.php"):
            self.a.append(str(values.get("body", [""])[0]))
            return {"status": 200, "queries": [{"sql": "INSERT INTO a (body) VALUES (?)"}]}
        if url.endswith("transform.php"):
            if not self.a:
                return {"status": 200, "queries": []}
            self.b.append("1" if self.lose_tag else self.a[-1])
            return {"status": 200, "queries": [{"sql": "INSERT INTO b SELECT body FROM a"}]}
        return {"status": 404, "queries": []}


def chain() -> list[dict[str, Any]]:
    return [
        {
            "url": "http://app/seed.php",
            "raw": {"sinkFile": "seed.php", "sinkLine": 10, "params": ["body"]},
            "table": "a",
            "columns": ["body"],
            "payload": True,
        },
        {
            "url": "http://app/transform.php",
            "raw": {"sinkFile": "transform.php", "sinkLine": 20, "params": ["copy"]},
            "table": "b",
            "columns": ["body"],
        },
    ]


async def test_chain_seeds_and_transforms() -> None:
    client = ChainClient()
    result = await run_chain(
        client,
        case_id="case-1",
        chain=chain(),
        base_url="http://app/",
        payload="<script>alert(1)</script>t1",
        tag="t1",
    )
    assert result["ok"] is True
    assert [hop["ok"] for hop in result["hops"]] == [True, True]
    assert result["hops"][0]["carries_payload"] is True
    assert result["hops"][1]["carries_payload"] is False
    assert "<script>" not in client.bodies[1]
    assert client.a == ["<script>alert(1)</script>t1"]
    assert result["stored"] == 1


async def test_chain_reports_a_lost_tag() -> None:
    client = ChainClient(lose_tag=True)
    result = await run_chain(
        client,
        case_id="case-1",
        chain=chain(),
        base_url="http://app/",
        payload="<script>alert(1)</script>t1",
        tag="t1",
    )
    assert result["ok"] is False
    assert result["failed_kind"] == CHAIN_TAG_LOST
    assert len(result["hops"]) == 2


async def test_chain_reports_a_step_that_did_not_run() -> None:
    client = ChainClient()

    async def broken(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "probe_run":
            raise RuntimeError("no output")
        return await client(tool, arguments)

    result = await run_chain(
        broken,
        case_id="case-1",
        chain=chain(),
        base_url="http://app/",
        payload="<script>alert(1)</script>t1",
        tag="t1",
    )
    assert result["ok"] is False
    assert result["failed_kind"] == CHAIN_STEP_NOT_REACHED
    assert result["hops"][0]["error"].startswith("RuntimeError")
