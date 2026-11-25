"""Control layer: case_open / case_note / case_report.

A case is the agent's "dossier": slices, goals, notes, evidence, and changes are all attached to the case.
Reports may only reference ``evidence_refs`` (H5: do not let the model freely conclude).
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
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc


def parse_sink(sink: Any) -> tuple[str, int, str]:
    """Normalize the three sink formats into (file, line, code)."""
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
        raise _bad("slice.sink cannot be empty")
    file, line, _ = parse_sink(params.slice.get("sink"))
    case_id = rt.store.open_case(params.agent, params.slice, params.write_targets)
    open_questions: list[str] = []
    if not file or not line:
        open_questions.append("slice.sink missing file:line")
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
        raise _bad(f"key {params.key!r} not in whitelist", f"Allowed: {sorted(NOTE_KEYS)}")
    try:
        revision = rt.store.add_note(params.case_id, params.key, params.value)
    except KeyError as exc:
        raise ToolError(ErrorCode.NOT_FOUND, f"case not found: {params.case_id}") from exc
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
        raise ToolError(ErrorCode.NOT_FOUND, f"case not found: {params.case_id}")

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
        f"- verdict: `{case['verdict'] or 'undetermined'}`",
        f"- read point: `{sink_file}:{sink_line}`",
        f"- sink kind: `{slice_doc.get('kind', '')}`",
        f"- created at: {case['created_at']}",
    ]
    if sink_code:
        lines.append(f"- sink code: `{sink_code}`")
    lines.append("")

    lines.append("## Evidence")
    if evidence:
        for row in evidence:
            lines.append(f"- `{row['ref']}` — {row['tool']}（{row['observed_at']}）")
    else:
        lines.append("- None (no evidence references in this case)")
    lines.append("")

    if changes:
        lines.append("## Write and Rollback")
        for change in changes:
            state = "reverted" if change["reverted"] else "not reverted"
            lines.append(
                f"- `{change['id']}` {change['op'].upper()} `{change['table_name']}`"
                f" affected={change['affected']} {state}"
            )
            if change["undo_sql"]:
                lines.append(f"  - undo: `{change['undo_sql']}`")
        lines.append("")

    if notes:
        lines.append("## Notes")
        for key, value in notes.items():
            lines.append(f"- {key}: `{json.dumps(value, ensure_ascii=False, default=str)[:500]}`")
        lines.append("")

    warnings: list[str] = []
    if not evidence:
        warnings.append("NO_EVIDENCE: report cannot be reconstructed from evidence_refs alone")
    refs = [row["ref"] for row in evidence]
    markdown = "\n".join(lines).strip() + "\n"
    return ToolOutput(
        data={"markdown": markdown, "evidence_refs": refs, "artifacts": []},
        warnings=warnings,
    )
