"""控制层：case_open / case_note / case_report。

case 是 agent 的"案卷"：切片、写目标、笔记、证据、change 都挂在 case 上。
报告只允许引用 ``evidence_refs``（H5：不要让模型自由发挥结论）。
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.cap.registry import ToolOutput
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import ErrorCode, ToolError

NOTE_KEYS = {"schema", "entry_urls", "filters", "transform", "candidates", "write_targets"}


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"参数不合法: {exc.errors()[0]['msg']}") from exc


def parse_sink(sink: Any) -> tuple[str, int, str]:
    """把 sink 的三种写法归一成 (file, line, code)。"""
    if isinstance(sink, dict):
        return str(sink.get("file", "")), int(sink.get("line", 0)), str(sink.get("code", ""))
    text = str(sink)
    head, _, tail = text.partition(":")
    line_text = ""
    code = ""
    for index, ch in enumerate(tail):
        if ch.isdigit():
            line_text += ch
        else:
            code = tail[index:].strip()
            break
    return head.strip(), int(line_text or 0), code


class CaseOpenInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slice: dict[str, Any]
    agent: str = "trigger"
    write_targets: list[dict[str, Any]] = Field(default_factory=list)


async def case_open(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(CaseOpenInput, arguments)
    rt = get_runtime()
    if not params.slice.get("sink"):
        raise _bad("slice.sink 不能为空")
    file, line, _ = parse_sink(params.slice.get("sink"))
    case_id = rt.store.open_case(params.agent, params.slice, params.write_targets)
    open_questions: list[str] = []
    if not file or not line:
        open_questions.append("slice.sink 缺少 file:line")
    return ToolOutput(
        data={
            "case_id": case_id,
            "read_point": {"file": file, "line": line},
            "open_questions": open_questions,
            "observed_at": now_iso(),
        }
    )


class CaseNoteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    key: str
    value: Any


async def case_note(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(CaseNoteInput, arguments)
    rt = get_runtime()
    if params.key not in NOTE_KEYS:
        raise _bad(f"key {params.key!r} 不在白名单", f"允许: {sorted(NOTE_KEYS)}")
    try:
        revision = rt.store.add_note(params.case_id, params.key, params.value)
    except KeyError as exc:
        raise ToolError(ErrorCode.NOT_FOUND, f"case 不存在: {params.case_id}") from exc
    return ToolOutput(data={"ok": True, "revision": revision})


class CaseReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    format: str = "markdown"


async def case_report(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(CaseReportInput, arguments)
    rt = get_runtime()
    case = rt.store.get_case(params.case_id)
    if case is None:
        raise ToolError(ErrorCode.NOT_FOUND, f"case 不存在: {params.case_id}")

    evidence = rt.store.list_evidence(params.case_id)
    changes = rt.store.list_changes(params.case_id)
    notes = rt.store.case_notes(params.case_id)
    slice_doc = json.loads(case["slice_json"])
    sink = slice_doc.get("sink")
    try:
        sink_file, sink_line, sink_code = parse_sink(sink)
    except (TypeError, ValueError):
        sink_file, sink_line, sink_code = str(sink), 0, ""

    lines: list[str] = [
        f"# case {params.case_id}",
        "",
        f"- agent: `{case['agent']}`",
        f"- verdict: `{case['verdict'] or '未判定'}`",
        f"- 读点: `{sink_file}:{sink_line}`",
        f"- sink kind: `{slice_doc.get('kind', '')}`",
        f"- 创建时间: {case['created_at']}",
    ]
    if sink_code:
        lines.append(f"- sink code: `{sink_code}`")
    lines.append("")

    lines.append("## 证据")
    if evidence:
        for row in evidence:
            lines.append(f"- `{row['ref']}` — {row['tool']}（{row['observed_at']}）")
    else:
        lines.append("- 无（本 case 没有任何证据引用）")
    lines.append("")

    if changes:
        lines.append("## 写库与回滚")
        for change in changes:
            state = "已回滚" if change["reverted"] else "未回滚"
            lines.append(
                f"- `{change['id']}` {change['op'].upper()} `{change['table_name']}`"
                f" affected={change['affected']} {state}"
            )
            if change["undo_sql"]:
                lines.append(f"  - undo: `{change['undo_sql']}`")
        lines.append("")

    if notes:
        lines.append("## 备注")
        for key, value in notes.items():
            lines.append(f"- {key}: `{json.dumps(value, ensure_ascii=False, default=str)[:500]}`")
        lines.append("")

    warnings: list[str] = []
    if not evidence:
        warnings.append("NO_EVIDENCE:报告无法只靠 evidence_refs 重建")
    refs = [row["ref"] for row in evidence]
    markdown = "\n".join(lines).strip() + "\n"
    return ToolOutput(
        data={"markdown": markdown, "evidence_refs": refs, "artifacts": []},
        warnings=warnings,
    )
