"""`tia-report` 入口：按 case 生成 Markdown 报告（T20 起落地）。"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-report", description="生成 case 的 Markdown 报告")
    parser.add_argument("case_id", help="case id，例如 c001")
    parser.add_argument("--out", metavar="PATH", default=None, help="输出文件路径")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    parser.error(f"report for {args.case_id!r} 尚未实现（T20 起落地）")
    raise AssertionError("argparse.error 应当退出")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
