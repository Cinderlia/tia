"""MCP capability service (stdio).

One process serves one profile: the profile is fixed at construction and immutable at runtime (H12 / Gate G3).
The main profile exposes only 14 intelligence tools; trigger / inject expose all 36.
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
    "TIA capability service. All tools return a unified envelope: success {ok:true, data, evidence_refs, ...}; "
    "failure {ok:false, error:{code, message, retryable, hint}}. "
    "verify_tag returns facts only, not security conclusions. "
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
    """Construct a low-level MCP Server bound to ``profile``."""
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
        description="TIA shared capability service (MCP stdio)",
    )
    parser.add_argument(
        "--profile",
        choices=registry.PROFILES,
        required=True,
        help="Capability sets: main (read-only intelligence) / trigger / inject",
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
