"""端到端：真实 stdio 握手，验证 profile 下发的工具集合与调用信封。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import mcp.types as types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _server_params(profile: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "tia.server", "--profile", profile],
        cwd=str(_PROJECT_ROOT),
    )


async def _list_tools(profile: str) -> list[types.Tool]:
    async with (
        stdio_client(_server_params(profile)) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.list_tools()
        return list(result.tools)


@pytest.mark.parametrize(
    ("profile", "expected"),
    [("main", 14), ("trigger", 36), ("inject", 36)],
)
async def test_tool_count_per_profile(profile: str, expected: int) -> None:
    tools = await _list_tools(profile)
    assert len(tools) == expected
    assert len({tool.name for tool in tools}) == expected


async def test_main_profile_has_no_verification_tools() -> None:
    names = {tool.name for tool in await _list_tools("main")}
    # G4 静态断言：main 不得出现任何验证/写类工具。
    forbidden = {
        "verify_tag",
        "probe_arm",
        "probe_run",
        "db_write",
        "db_undo",
        "http_request",
        "form_fill",
        "trace_run",
        "case_open",
    }
    assert names.isdisjoint(forbidden)
    assert {"source_read", "db_read", "slice_next", "slice_archive"} <= names


async def test_call_unknown_tool_returns_error_envelope() -> None:
    async with (
        stdio_client(_server_params("main")) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("verify_tag", {"tag": "abcd"})
    assert result.is_error is True
    text = result.content[0].text
    assert isinstance(text, str)
    envelope = json.loads(text)
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "NOT_FOUND"
    assert envelope["profile"] == "main"


async def test_call_unimplemented_tool_returns_unsupported() -> None:
    async with (
        stdio_client(_server_params("trigger")) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("source_read", {"path": "home.php"})
    envelope = json.loads(result.content[0].text)
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "UNSUPPORTED"


def test_build_server_rejects_unknown_profile() -> None:
    from tia.server import build_server

    with pytest.raises(ValueError):
        build_server("root")
