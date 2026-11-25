"""触发 agent 主流程（P0–P6）。

P0 建案 → P1 定位读点与入口 → P2 读点可达 → P3 备数据 → P4 写入 payload
→ P5 verify_tag 取证 → P6 回滚 + 报告。

本实现用"确定性规划器"代替 LLM planner：每一步的决策规则写在这里，
LLM 只影响"下一步做什么"，不影响"工具返回什么"。等主流程稳定后再接 planner。
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tia.cap.case import parse_sink
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.orch.judge import judge_trigger
from tia.orch.kernel import Kernel, LocalToolClient, StepRecord, ToolCallError, ToolClient

_INSERT_RE = re.compile(r"insert\s+into\s+`?(\w+)`?\s*\(([^)]*)\)", re.IGNORECASE)
_SELECT_TABLE_RE = re.compile(r"\bfrom\s+`?(\w+)`?", re.IGNORECASE)
_POST_VAR_RE = re.compile(r"\$_(?:POST|GET|REQUEST)\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]")
_FORM_ACTION_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"']", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"<form[^>]*method=[\"']([a-zA-Z]+)[\"']", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"<(?:input|textarea)[^>]*name=[\"']([^\"']+)[\"']", re.IGNORECASE)


@dataclass(slots=True)
class StageRecord:
    stage: str
    ok: bool
    note: str = ""


@dataclass(slots=True)
class TriggerResult:
    case_id: str
    verdict: str
    residue: int | None
    report: str
    stages: list[StageRecord] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    trace: list[StepRecord] = field(default_factory=list)


def normalize_slice(raw: dict[str, Any]) -> dict[str, Any]:
    """把 navi 的 sink/slice JSON 归一成 Slice 形态（sink 统一为 dict）。"""
    doc = dict(raw)
    sink: Any = doc.get("sink")
    if isinstance(sink, dict) and "file" in sink and "line" in sink:
        file_, line_, code_ = str(sink["file"]), int(sink["line"]), str(sink.get("code", ""))
    else:
        file_, line_, code_ = parse_sink(sink)
    doc["sink"] = {"file": file_, "line": line_, "code": code_}
    doc.setdefault("kind", doc.get("sink_kind") or "unknown")
    return doc


def _tag() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(4))


def _today() -> str:
    return datetime.now().strftime("%d %b %Y")


def _infer_target(source_text: str, params: list[str]) -> dict[str, Any]:
    insert = _INSERT_RE.search(source_text)
    select = _SELECT_TABLE_RE.search(source_text)
    columns: list[str] = []
    table = ""
    if insert:
        table = insert.group(1)
        columns = [c.strip().strip("`") for c in insert.group(2).split(",") if c.strip()]
    elif select:
        table = select.group(1)
    return {"table": table, "insert_columns": columns, "params": params or []}


def _column_value(column: str, *, payload: str, tag: str) -> str:
    lowered = column.lower()
    if lowered in {"comment", "msg", "message", "content", "descricao", "description", "text"}:
        return payload
    if lowered in {"user", "name", "author", "username", "nome"}:
        return f"tia-{tag}"
    if lowered in {"date", "created_at", "time", "datetime", "timestamp"}:
        return _today()
    return f"tia-{tag}"


async def run_trigger(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
) -> TriggerResult:
    rt = get_runtime()
    slice_doc = normalize_slice(raw_slice)
    sink = slice_doc["sink"]
    sink_file, sink_line = sink["file"], sink["line"]
    params = [str(p) for p in (slice_doc.get("params") or [])]
    stages: list[StageRecord] = []
    notes: dict[str, Any] = {"base_url": base_url, "sink": f"{sink_file}:{sink_line}"}
    kernel = Kernel(
        profile="trigger", budget=budget, client=client or LocalToolClient(profile="trigger")
    )

    # P0 建案 ------------------------------------------------------------
    opened = await kernel.call("case_open", {"slice": slice_doc, "agent": "trigger", "write_targets": []})
    case_id = str(opened["case_id"])
    kernel.case_id = case_id
    stages.append(StageRecord("P0", True, f"case_id={case_id}"))

    # P1 定位读点与入口 ---------------------------------------------------
    source = await kernel.call("source_read", {"file": sink_file, "around": {"line": sink_line, "n": 40}})
    source_text = "\n".join(str(line["text"]) for line in source["lines"])
    notes["source_sha256"] = source["sha256"]
    inferred = _infer_target(source_text, params)
    table = inferred["table"]
    columns = inferred["insert_columns"]
    if not table:
        stages.append(StageRecord("P1", False, "未能从源码推断目标表"))
        return TriggerResult(case_id=case_id, verdict="SQL_ERROR", residue=None,
                             report=await kernel.report(), stages=stages, notes=notes,
                             trace=kernel.trace)
    post_vars = sorted(set(_POST_VAR_RE.findall(source_text))) or params
    notes.update({"table": table, "columns": columns, "post_vars": post_vars})

    targets = (
        [{"table": table, "column": col, "mode": "insert"} for col in columns]
        if columns
        else [{"table": table, "mode": "insert"}]
    )
    kernel.set_write_targets(targets)
    await kernel.call("case_note", {"case_id": case_id, "key": "write_targets", "value": targets})
    stages.append(StageRecord("P1", True, f"table={table} columns={columns} post_vars={post_vars}"))

    # P2 读点可达（本环境暂无 PHP 探针，用 HTTP + schema 作为降级证据） ----
    page = await kernel.call("http_request", {"method": "GET", "url": base_url})
    body = str(page.get("body", ""))
    status = int(page.get("status", 0))
    form_action = _FORM_ACTION_RE.search(body)
    form_method = _FORM_METHOD_RE.search(body)
    form_fields = sorted(set(_INPUT_NAME_RE.findall(body)))
    notes.update(
        {
            "page_status": status,
            "form_action": form_action.group(1) if form_action else None,
            "form_method": form_method.group(1).upper() if form_method else None,
            "form_fields": form_fields,
        }
    )
    if status >= 400:
        stages.append(StageRecord("P2", False, f"页面返回 {status}"))
        return TriggerResult(case_id=case_id, verdict="READ_EMPTY", residue=None,
                             report=await kernel.report(), stages=stages, notes=notes,
                             trace=kernel.trace)
    stages.append(StageRecord("P2", True, f"HTTP {status}，表单字段 {form_fields}"))

    # P3 备数据 ----------------------------------------------------------
    schema = await kernel.call("db_schema", {"table": table})
    table_meta = schema["tables"][0]
    notes["table_meta"] = {
        "columns": [c["name"] for c in table_meta["columns"]],
        "primary_key": table_meta.get("primary_key", []),
    }
    stages.append(StageRecord("P3", True, f"表 {table} 共 {len(table_meta['columns'])} 列"))

    # P4 设计并写入 payload ----------------------------------------------
    tag = _tag()
    payload = f"{payload_base}{tag}"
    value_columns = columns or [c["name"] for c in table_meta["columns"] if c["name"] not in table_meta.get("primary_key", [])]
    values = [_column_value(col, payload=payload, tag=tag) for col in value_columns]
    sql = (
        f"INSERT INTO `{table}` ({', '.join(f'`{c}`' for c in value_columns)}) "
        f"VALUES ({', '.join(_sql_literal(v) for v in values)})"
    )
    notes.update({"tag": tag, "payload": payload, "insert_sql": sql})
    change: dict[str, Any] | None = None
    db_error: str | None = None
    try:
        written = await kernel.call("db_write", {"sql": sql})
        change = written.get("change") if isinstance(written, dict) else None
        notes["change_id"] = change["change_id"] if change else None
    except ToolCallError as exc:
        db_error = f"{exc.code.value}: {exc.message}"
        notes["db_error"] = db_error
    stages.append(
        StageRecord("P4", db_error is None, "写入成功" if db_error is None else f"写入失败: {db_error}")
    )

    # P5 verify_tag 取证 --------------------------------------------------
    verify: dict[str, Any] | None = None
    if db_error is None:
        try:
            verify = await kernel.call("verify_tag", {"url": base_url, "tag": tag, "payload": payload})
        except ToolCallError as exc:
            notes["verify_error"] = f"{exc.code.value}: {exc.message}"
        if verify is not None:
            notes["occurrence_count"] = verify.get("occurrence_count")
            best = verify.get("best") or {}
            notes["best"] = {
                "context_kind": best.get("context_kind"),
                "executable": best.get("executable"),
                "reason": best.get("executable_reason"),
                "node_path": best.get("node_path"),
            }
        stages.append(
            StageRecord("P5", verify is not None and bool(verify.get("found")),
                        f"found={bool(verify and verify.get('found'))} occurrences={notes.get('occurrence_count')}")
        )

    verdict, explanation = judge_trigger(
        verify=verify, written=change is not None, db_error=db_error
    )
    notes["explanation"] = explanation

    # P6 回滚 + 报告 ------------------------------------------------------
    residue: int | None = None
    try:
        undo = await kernel.call("db_undo", {"case_id": case_id})
        residue = int(undo.get("residue", -1))
        notes["undo"] = undo.get("reverted")
    except ToolCallError as exc:
        notes["undo_error"] = f"{exc.code.value}: {exc.message}"
    stages.append(StageRecord("P6", residue == 0, f"residue={residue}"))

    rt.store.set_case_verdict(case_id, str(verdict), ceiling="EXECUTABLE")
    report = await kernel.report()
    stages.append(StageRecord("P6", True, "报告已生成"))
    notes["observed_at"] = now_iso()
    return TriggerResult(
        case_id=case_id,
        verdict=str(verdict),
        residue=residue,
        report=report,
        stages=stages,
        notes=notes,
        trace=kernel.trace,
    )


def _sql_literal(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"
