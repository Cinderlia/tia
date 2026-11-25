"""`tia-report` entry point: generate Markdown report per case (implemented from T20)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-report", description="Generate Markdown report for a case")
    parser.add_argument("case_id", help="case id, e.g., c001")
    parser.add_argument("--out", metavar="PATH", default=None, help="Output file path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    parser.error(f"report for {args.case_id!r} not yet implemented (implemented from T20)")
    raise AssertionError("argparse.error should exit")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
