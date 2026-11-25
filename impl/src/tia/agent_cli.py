"""``tia-agent`` 入口：trigger / inject / main。

三个子命令共享同一套 profile / 配置加载；stage 打到 stderr，结果 JSON 打到 stdout。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from tia import __version__
from tia.dom.inject import InjectResult, run_inject
from tia.dom.main import MainResult, run_main
from tia.dom.trigger import TriggerResult, run_trigger
from tia.inf.config import Settings
from tia.inf.runtime import configure
from tia.orch.kernel import ToolCallError

PROFILES = ("trigger", "inject", "main")


def _add_common(parser: argparse.ArgumentParser, *, base_url_required: bool) -> None:
    parser.add_argument("--slice", required=True, help="切片 JSON 文件（navi sink/slice 或 Slice）")
    parser.add_argument("--index", type=int, default=0, help="文件里是数组/多个 sink 时的下标")
    parser.add_argument("--base-url", required=base_url_required, help="目标页面 URL（容器内用 127.0.0.1）")
    parser.add_argument("--payload", default="<script>alert(1)</script>", help="基础 payload")
    parser.add_argument("--budget", type=int, default=40)
    parser.add_argument("--db-name", default=None, help="目标库名（默认读 TIA_DB_NAME）")
    parser.add_argument("--db-user", default=None)
    parser.add_argument("--db-password", default=None)
    parser.add_argument("--store", default=None, help="sqlite 路径（默认 impl/var/tia.db）")
    parser.add_argument("--json", action="store_true", help="stdout 只输出结果 JSON")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-agent", description="TIA agent")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    trigger = sub.add_parser("trigger", help="对切片执行 P0–P6 触发取证")
    _add_common(trigger, base_url_required=True)

    inject = sub.add_parser("inject", help="对切片执行 I0–I7 注入取证")
    _add_common(inject, base_url_required=True)
    inject.add_argument("--no-cleanup", action="store_true", help="保留写入的数据，不删除")

    main_cmd = sub.add_parser("main", help="调度多个切片：trigger → inject → archive")
    main_cmd.add_argument("--slices", required=True, help="切片 JSON 文件（数组/含 sinks|slices 的对象）")
    main_cmd.add_argument("--base-url", required=True)
    main_cmd.add_argument("--limit", type=int, default=1, help="本轮最多调度几个切片")
    main_cmd.add_argument("--payload", default="<script>alert(1)</script>")
    main_cmd.add_argument("--budget", type=int, default=120)
    main_cmd.add_argument("--db-name", default=None)
    main_cmd.add_argument("--db-user", default=None)
    main_cmd.add_argument("--db-password", default=None)
    main_cmd.add_argument("--store", default=None)
    main_cmd.add_argument("--json", action="store_true")
    return parser


def _load_slice(path: str, index: int) -> dict[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    candidates: Any = raw
    if isinstance(raw, dict):
        for key in ("sinks", "slices"):
            if key in raw and isinstance(raw[key], list):
                candidates = raw[key]
                break
    if isinstance(candidates, list):
        if not candidates:
            raise SystemExit("切片文件里没有条目")
        return dict(candidates[index])
    if isinstance(raw, dict):
        return raw
    raise SystemExit("切片文件必须是对象或数组")


def _load_slices(path: str) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [dict(item) for item in raw]
    if isinstance(raw, dict):
        for key in ("sinks", "slices"):
            if isinstance(raw.get(key), list):
                return [dict(item) for item in raw[key]]
        return [dict(raw)]
    raise SystemExit("切片文件必须是对象或数组")


def _print_stages(stages: list[Any]) -> None:
    for stage in stages:
        mark = "ok" if stage.ok else "!!"
        print(f"[{stage.stage}] {mark} {stage.note}", file=sys.stderr)


def _configure(args: argparse.Namespace, profile: str) -> Settings:
    settings = Settings.load(
        profile,
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password,
        store_path=Path(args.store) if args.store else None,
    )
    configure(settings)
    return settings


def _fail(exc: ToolCallError) -> int:
    payload = {
        "ok": False,
        "tool": exc.tool,
        "error": exc.envelope.error.model_dump() if exc.envelope.error else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 2


def _run_trigger(args: argparse.Namespace) -> int:
    _configure(args, "trigger")
    slice_doc = _load_slice(args.slice, args.index)
    try:
        result: TriggerResult = asyncio.run(
            run_trigger(slice_doc, base_url=args.base_url, payload_base=args.payload, budget=args.budget)
        )
    except ToolCallError as exc:
        return _fail(exc)
    _print_stages(result.stages)
    summary = {
        "ok": True,
        "agent": "trigger",
        "case_id": result.case_id,
        "verdict": result.verdict,
        "residue": result.residue,
        "table": result.notes.get("table"),
        "tag": result.notes.get("tag"),
        "occurrence_count": result.notes.get("occurrence_count"),
        "change_id": result.notes.get("change_id"),
        "explanation": result.notes.get("explanation"),
        "tool_calls": len(result.trace),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.json:
        print(result.report)
    return 0


def _run_inject(args: argparse.Namespace) -> int:
    _configure(args, "inject")
    slice_doc = _load_slice(args.slice, args.index)
    try:
        result: InjectResult = asyncio.run(
            run_inject(
                slice_doc,
                base_url=args.base_url,
                payload_base=args.payload,
                budget=args.budget,
                cleanup=not args.no_cleanup,
            )
        )
    except ToolCallError as exc:
        return _fail(exc)
    _print_stages(result.stages)
    summary = {
        "ok": True,
        "agent": "inject",
        "case_id": result.case_id,
        "verdict": result.verdict,
        "residue": result.residue,
        "tag": result.notes.get("tag"),
        "target": result.notes.get("target"),
        "tag_in_db": result.notes.get("tag_in_db"),
        "tag_in_page": result.notes.get("tag_in_page"),
        "context_kind": result.notes.get("context_kind"),
        "explanation": result.notes.get("explanation"),
        "tool_calls": len(result.trace),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.json:
        print(result.report)
    return 0


def _run_main(args: argparse.Namespace) -> int:
    _configure(args, "main")
    slices = _load_slices(args.slices)
    try:
        result: MainResult = asyncio.run(
            run_main(
                slices,
                base_url=args.base_url,
                limit=args.limit,
                payload_base=args.payload,
                budget=args.budget,
            )
        )
    except ToolCallError as exc:
        return _fail(exc)
    for item in result.outcomes:
        print(f"[{item.slice_id}] {item.verdict}", file=sys.stderr)
    summary = {
        "ok": True,
        "agent": "main",
        "attempted": len(result.outcomes),
        "stop_reason": result.stop_reason,
        "outcomes": [item.model_dump() for item in result.outcomes],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not args.json:
        print(result.report)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"tia-agent {__version__}")
        return 0
    if args.command is None:
        parser.error("需要子命令: trigger | inject | main")
    handlers = {"trigger": _run_trigger, "inject": _run_inject, "main": _run_main}
    return handlers[args.command](args)
