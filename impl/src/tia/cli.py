"""`tia` top-level CLI: forwards subcommands to their respective entry modules.

The three formal entry points (`tia-server` / `tia-agent` / `tia-report`) can also run independently;
this only provides a unified discovery entry and `--help` / `--version`.
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
    except PackageNotFoundError:  # not installed (e.g., running directly from source tree)
        return __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description="TIA —— Trace-based Injection Agent",
        epilog=(
            "Entry: tia-server (shared capability service) / tia-agent (main, trigger, injection orchestration)"
            " / tia-report (Markdown report)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{_PROG} {_version()}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    server = subparsers.add_parser("server", help="Start MCP capability service (stdio)")
    server.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed through to tia-server")

    agent = subparsers.add_parser("agent", help="Run orchestration agent")
    agent.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed through to tia-agent")

    report = subparsers.add_parser("report", help="Generate Markdown report for case")
    report.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed through to tia-report")

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


if __name__ == "__main__":  # pragma: no cover - invoked by __main__
    sys.exit(main())
