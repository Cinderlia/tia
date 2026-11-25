"""`tia-agent` 入口。

主 / 触发 / 注入三种身份在 T04 之后由 `tia.dom.*` 与 `tia.orch.*` 实现；
当前只保留参数骨架，避免入口脚本在安装阶段就失败。
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-agent", description="TIA 编排 agent")
    parser.add_argument("role", choices=["main", "trigger", "inject"], help="编排身份")
    parser.add_argument("--run", metavar="RUN_ID", help="main 身份的 run id")
    parser.add_argument("--case", metavar="CASE_ID", help="trigger / inject 身份的 case id")
    parser.add_argument("--profile", default=None, help="覆盖 profile 文件路径")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    parser.error(f"agent role {args.role!r} 尚未实现（T04 起落地）")
    raise AssertionError("argparse.error 应当退出")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
