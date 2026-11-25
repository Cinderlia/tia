"""``tia-agent`` 入口：trigger / inject / main。

当前阶段只实现 trigger 主流程；inject/main 明确报"未实现"，不假装能跑。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from tia import __version__
from tia.dom.trigger import TriggerResult, run_trigger
from tia.inf.config import Settings
from tia.inf.runtime import configure
from tia.orch.kernel import ToolCallError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tia-agent", description="TIA agent")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    trigger = sub.add_parser("trigger", help="对切片执行 P0–P6 触发取证")
    trigger.add_argument("--slice", required=True, help="切片 JSON 文件（navi sink 或 Slice）")
    trigger.add_argument("--index", type=int, default=0, help="文件里是数组/多个 sink 时的下标")
    trigger.add_argument("--base-url", required=True, help="目标页面 URL（容器内用 127.0.0.1）")
    trigger.add_argument("--payload", default="<script>alert(1)</script>", help="基础 payload")
    trigger.add_argument("--budget", type=int, default=40)
    trigger.add_argument("--db-name", default=None, help="目标库名（默认读 TIA_DB_NAME）")
    trigger.add_argument("--db-user", default=None)
    trigger.add_argument("--db-password", default=None)
    trigger.add_argument("--store", default=None, help="sqlite 路径（默认 impl/var/tia.db）")
    trigger.add_argument("--json", action="store_true", help="stdout 只输出结果 JSON")

    inject = sub.add_parser("inject", help="注入 agent（尚未实现）")
    inject.add_argument("--case", required=True)
    main_cmd = sub.add_parser("main", help="主调度（尚未实现）")
    main_cmd.add_argument("--run", required=True)
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


def _print_stages(result: TriggerResult) -> None:
    for stage in result.stages:
        mark = "ok" if stage.ok else "!!"
        print(f"[{stage.stage}] {mark} {stage.note}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"tia-agent {__version__}")
        return 0
    if args.command is None:
        parser.error("需要子命令: trigger | inject | main")
    if args.command in {"inject", "main"}:
        parser.error(f"{args.command} 尚未实现（当前先跑通 trigger 主流程）")

    settings = Settings.load(
        "trigger",
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password,
    )
    if args.store:
        settings = Settings.load(
            "trigger",
            db_name=settings.db.name,
            db_user=settings.db.user,
            db_password=settings.db.password,
            store_path=Path(args.store),
        )
    configure(settings)

    slice_doc = _load_slice(args.slice, args.index)
    try:
        result = asyncio.run(
            run_trigger(slice_doc, base_url=args.base_url, payload_base=args.payload, budget=args.budget)
        )
    except ToolCallError as exc:
        payload = {
            "ok": False,
            "tool": exc.tool,
            "error": exc.envelope.error.model_dump() if exc.envelope.error else None,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2

    _print_stages(result)
    summary = {
        "ok": True,
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
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print(result.report)
    return 0
