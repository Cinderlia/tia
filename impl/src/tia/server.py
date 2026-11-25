"""MCP 能力服务（stdio）。

一个进程只服务一个 profile：profile 在构造时确定，运行期不可变（H12 / 闸门 G3）。
main profile 只下发 14 个情报类工具；trigger / inject 下发全部 36 个。
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tia import __version__
from tia.cap import registry
from tia.schemas.envelope import as_json_value

_INSTRUCTIONS = (
    "TIA 能力服务。所有工具返回统一信封：成功 {ok:true, data, evidence_refs, ...}；"
    "失败 {ok:false, error:{code, message, retryable, hint}}。"
    "verify_tag 只回事实，不返回安全结论。"
)


def _tool_definitions(profile: str) -> list[types.Tool]:
    return [
        types.Tool(
            name=spec.name,
            description=spec.description,
            input_schema=spec.input_schema,
        )
        for spec in registry.tools_for_profile(profile)
    ]


def build_server(profile: str) -> Server:
    """构造一个绑定到 ``profile`` 的低层 MCP Server。"""
    if profile not in registry.PROFILES:
        raise ValueError(f"unknown profile: {profile}")

    definitions = _tool_definitions(profile)

    async def on_list_tools(
        _ctx: object, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=definitions)

    async def on_call_tool(
        _ctx: object, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        envelope = await registry.dispatch(profile, params.name, params.arguments)
        payload: Any = as_json_value(envelope.model_dump(mode="json"))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=envelope.model_dump_json())],
            structured_content=payload,
            is_error=not envelope.ok,
        )

    return Server(
        "tia",
        version=__version__,
        instructions=_INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


async def serve(profile: str) -> None:
    server = build_server(profile)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tia-server",
        description="TIA 共享能力服务（MCP stdio）",
    )
    parser.add_argument(
        "--profile",
        choices=registry.PROFILES,
        required=True,
        help="能力集合：main（只读情报）/ trigger / inject",
    )
    parser.add_argument("--version", action="version", version=f"tia-server {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    import asyncio

    args = build_parser().parse_args(argv)
    asyncio.run(serve(args.profile))
    return 0


if __name__ == "__main__":
    sys.exit(main())
