"""`tia` 顶层命令行：把子命令转发到各自的入口模块。

三个正式入口（`tia-server` / `tia-agent` / `tia-report`）也能独立执行；
这里只做统一的发现入口与 `--help` / `--version`。
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as dist_version

from tia import __version__

_PROG = "tia"

_COMMANDS: dict[str, str] = {
    "server": "tia.server:main",
    "agent": "tia.agent_cli:main",
    "report": "tia.report:main",
}


def _version() -> str:
    try:
        return dist_version("tia")
    except PackageNotFoundError:  # 未安装（例如直接从源码树运行）
        return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description="TIA —— Trace-based Injection Agent",
        epilog=(
            "入口：tia-server（共享能力服务）/ tia-agent（主、触发、注入编排）"
            " / tia-report（Markdown 报告）"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{_PROG} {_version()}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    server = subparsers.add_parser("server", help="启动 MCP 能力服务（stdio）")
    server.add_argument("args", nargs=argparse.REMAINDER, help="透传给 tia-server 的参数")

    agent = subparsers.add_parser("agent", help="运行编排 agent")
    agent.add_argument("args", nargs=argparse.REMAINDER, help="透传给 tia-agent 的参数")

    report = subparsers.add_parser("report", help="生成 case 的 Markdown 报告")
    report.add_argument("args", nargs=argparse.REMAINDER, help="透传给 tia-report 的参数")

    return parser


def _dispatch(command: str, argv: Sequence[str]) -> int:
    module_path, _, attr = _COMMANDS[command].partition(":")
    module = __import__(module_path, fromlist=[attr])
    entry = getattr(module, attr)
    result: object = entry(list(argv))
    return result if isinstance(result, int) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return _dispatch(args.command, args.args)


if __name__ == "__main__":  # pragma: no cover - 由 __main__ 调用
    sys.exit(main())
