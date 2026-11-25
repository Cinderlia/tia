"""Trigger the agent main flow (P0–P6).

P0 Create case → P1 Locate read points and entry → P2 Read point reachable → P3 Prepare data → P4 Write payload
→ P5 verify_tag forensics → P6 Rollback + report.

This implementation uses a "deterministic planner" instead of an LLM planner: decision rules for each step are defined here;
the LLM only affects "what to do next", not "what the tool returns". Integrate the planner once the main flow is stable.
"""

from __future__ import annotations

import contextlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from tia.ad.llm import LlmClient
from tia.cap.case import parse_sink
from tia.cap.entry import (
    EntryCandidate,
    derive_payload_constraints,
    entry_candidates,
    infer_entry,
)
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


_SELECT_RE = re.compile(r"\bselect\b[^;]*?\bfrom\s+`?([A-Za-z_][\w]*)`?", re.I)
def _read_line(lines: list[dict[str, Any]], table: str) -> int | None:
    """Line number of the SELECT that reads the target table, if the source shows it."""
    for item in lines:
        text = str(item.get("text", ""))
        match = _SELECT_RE.search(text)
        if match is not None and match.group(1).lower() == table.lower():
            number = item.get("n")
            if isinstance(number, int):
                return number
    return None


async def _probe_sink_read(
    kernel: Kernel,
    case_id: str,
    sink_file: str,
    read_line: int,
    base_url: str,
    tag: str,
    entry: tuple[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Arm the SQL capture on the read line, fetch the page, and check whether our row was returned."""
    note: dict[str, Any] = {"line": read_line}
    try:
        await kernel.call("probe_arm", {"case_id": case_id, "file": sink_file, "line": read_line})
    except ToolCallError as exc:
        note["error"] = exc.code.value
        return note
    arguments: dict[str, Any] = {"case_id": case_id, "url": base_url}
    if entry:
        arguments["method"] = entry[0]
        if arguments["method"] == "POST":
            arguments["body"] = urlencode(entry[1])
        else:
            arguments["params"] = entry[1]
    try:
        run = await kernel.call("probe_run", arguments)
    except ToolCallError as exc:
        note["error"] = exc.code.value
        return note
    finally:
        with contextlib.suppress(ToolCallError):
            await kernel.call("probe_disarm", {"case_id": case_id})
    queries = run.get("queries") or []
    note["hit"] = bool(run.get("hit"))
    note["mode"] = run.get("mode")
    if queries:
        query = queries[0]
        note["sql"] = query.get("sql")
        note["matched_at"] = query.get("matched_at")
        note["row_count"] = query.get("row_count")
        note["rows_with_tag"] = sum(
            1
            for row in query.get("rows") or []
            if tag in " ".join(str(value) for value in row.values())
        )
    return note


def normalize_slice(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize navi sink/slice JSON into Slice form (sink unified as dict)."""
    doc = dict(raw)
    sink: Any = doc.get("sink")
    if isinstance(sink, dict) and "file" in sink and "line" in sink:
        file_, line_, code_ = str(sink["file"]), int(sink["line"]), str(sink.get("code", ""))
    elif doc.get("sinkFile"):
        # navi slice form: sinkFile / sinkLine / sinkCode
        file_ = str(doc["sinkFile"])
        line_ = int(doc.get("sinkLine") or 0)
        code_ = str(doc.get("sinkCode") or "")
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

    # P0 Create case ------------------------------------------------------------
    opened = await kernel.call("case_open", {"slice": slice_doc, "agent": "trigger", "write_targets": []})
    case_id = str(opened["case_id"])
    kernel.case_id = case_id
    stages.append(StageRecord("P0", True, f"case_id={case_id}"))

    # P1 Locate read points and entry ---------------------------------------------------
    source = await kernel.call("source_read", {"file": sink_file, "around": {"line": sink_line, "n": 40}})
    source_text = "\n".join(str(line["text"]) for line in source["lines"])
    notes["source_sha256"] = source["sha256"]
    inferred = _infer_target(source_text, params)
    table = inferred["table"]
    columns = inferred["insert_columns"]
    if not table:
        stages.append(StageRecord("P1", False, "Failed to infer target table from source code"))
        return TriggerResult(case_id=case_id, verdict="SQL_ERROR", residue=None,
                             report=await kernel.report(), stages=stages, notes=notes,
                             trace=kernel.trace)
    post_vars = sorted(set(_POST_VAR_RE.findall(source_text))) or params
    entry_plan = infer_entry(source_text)
    read_line = _read_line([line for line in source["lines"] if isinstance(line, dict)], table)
    notes.update(
        {
            "table": table,
            "columns": columns,
            "post_vars": post_vars,
            "read_line": read_line,
            "read_entry": {
                "method": entry_plan.method,
                "has_filter": entry_plan.has_filter,
                "mutating": entry_plan.mutating,
                "fields": [
                    {"name": f.name, "usage": f.usage, "numeric": f.numeric} for f in entry_plan.fields
                ],
            },
        }
    )

    targets = (
        [{"table": table, "column": col, "mode": "insert"} for col in columns]
        if columns
        else [{"table": table, "mode": "insert"}]
    )
    kernel.set_write_targets(targets)
    await kernel.call("case_note", {"case_id": case_id, "key": "write_targets", "value": targets})
    stages.append(StageRecord("P1", True, f"table={table} columns={columns} post_vars={post_vars}"))

    # P2 Read point reachable (no PHP probe in this environment; using HTTP + schema as fallback evidence) ----
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
        stages.append(StageRecord("P2", False, f"Page returned {status}"))
        return TriggerResult(case_id=case_id, verdict="READ_EMPTY", residue=None,
                             report=await kernel.report(), stages=stages, notes=notes,
                             trace=kernel.trace)
    stages.append(StageRecord("P2", True, f"HTTP {status}, form fields {form_fields}"))

    # P3 Prepare data ----------------------------------------------------------
    schema = await kernel.call("db_schema", {"table": table})
    table_meta = schema["tables"][0]
    notes["table_meta"] = {
        "columns": [c["name"] for c in table_meta["columns"]],
        "primary_key": table_meta.get("primary_key", []),
    }
    stages.append(StageRecord("P3", True, f"Table {table} has {len(table_meta['columns'])} columns"))

    # P4 Design and write payload ----------------------------------------------
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
        StageRecord("P4", db_error is None, "Write successful" if db_error is None else f"Write failed: {db_error}")
    )

    # Exploration: the entry parameters are ordered attempts, not a proof.
    # The tag identifies the written row; the row's primary key and the tag are
    # the strongest values, weaker candidates follow inside a small budget.
    payload_column = value_columns[values.index(payload)] if payload in values else value_columns[-1]
    pk_columns = list(table_meta.get("primary_key") or [])
    candidates: list[EntryCandidate] = []
    entry_request: tuple[str, dict[str, str]] | None = None
    if db_error is None:
        order = f" ORDER BY `{pk_columns[0]}` DESC" if pk_columns else ""
        row: dict[str, Any] | None = None
        try:
            found = await kernel.call(
                "db_read",
                {
                    "sql": (
                        f"SELECT * FROM `{table}` WHERE `{payload_column}` LIKE '%{tag}%'"
                        f"{order} LIMIT 1"
                    )
                },
            )
            row = (found.get("rows") or [None])[0]
        except ToolCallError:
            row = None
        candidates = await entry_candidates(
            entry_plan,
            tag=tag,
            row=row,
            pk_columns=pk_columns,
            context=source_text,
            client=LlmClient.from_env(),
            limit=3,
        )
        if candidates:
            first = candidates[0]
            entry_request = (first.method, first.values)
            notes["read_entry_values"] = first.values
            notes["read_entry_basis"] = first.basis

    # P5 Sink read probe + verify_tag forensics --------------------------------
    if db_error is None and read_line is not None:
        notes["sink_read"] = await _probe_sink_read(
            kernel, case_id, sink_file, read_line, base_url, tag, entry_request
        )
    verify: dict[str, Any] | None = None
    verify_attempts: list[dict[str, Any]] = []
    if db_error is None:
        for candidate in candidates:
            attempt: dict[str, Any] = {
                "method": candidate.method,
                "values": candidate.values,
                "confidence": candidate.confidence,
                "basis": candidate.basis,
                "found": False,
            }
            verify_html: str | None = None
            verify_content_type = "text/html"
            try:
                if candidate.method == "GET":
                    fetched = await kernel.call(
                        "http_request", {"method": "GET", "url": base_url, "params": candidate.values}
                    )
                else:
                    fetched = await kernel.call(
                        "http_request",
                        {
                            "method": "POST",
                            "url": base_url,
                            "body": urlencode(candidate.values),
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        },
                    )
                verify_html = str(fetched.get("body") or "")
                verify_content_type = str(fetched.get("content_type") or "text/html")
                attempt["status"] = fetched.get("status")
            except ToolCallError as exc:
                attempt["error"] = f"{exc.code.value}: {exc.message}"
                verify_attempts.append(attempt)
                continue
            verify_args: dict[str, Any] = {"tag": tag, "payload": payload}
            if verify_html:
                verify_args["html"] = verify_html
                verify_args["content_type"] = verify_content_type
            else:
                verify_args["url"] = base_url
            try:
                attempt_verify = await kernel.call("verify_tag", verify_args)
            except ToolCallError as exc:
                attempt["error"] = f"{exc.code.value}: {exc.message}"
                verify_attempts.append(attempt)
                continue
            attempt["found"] = bool(attempt_verify.get("found"))
            attempt["occurrence_count"] = attempt_verify.get("occurrence_count")
            verify_attempts.append(attempt)
            if verify is None or (attempt["found"] and not bool(verify.get("found"))):
                verify = attempt_verify
            if attempt["found"]:
                break
        if not candidates:
            try:
                verify = await kernel.call("verify_tag", {"tag": tag, "payload": payload, "url": base_url})
            except ToolCallError as exc:
                notes["verify_error"] = f"{exc.code.value}: {exc.message}"
        notes["entry_attempts"] = verify_attempts
        if verify is not None:
            notes["occurrence_count"] = verify.get("occurrence_count")
            best = verify.get("best") or {}
            notes["best"] = {
                "context_kind": best.get("context_kind"),
                "executable": best.get("executable"),
                "reason": best.get("executable_reason"),
                "node_path": best.get("node_path"),
            }
            column_length = None
            for column in table_meta.get("columns") or []:
                if column.get("name") == payload_column:
                    column_length = column.get("length")
            notes["payload_constraints"] = derive_payload_constraints(
                verify,
                column=payload_column,
                column_length=column_length,
                payload=payload,
            )
        sink_read = notes.get("sink_read") or {}
        stages.append(
            StageRecord(
                "P5",
                verify is not None and bool(verify.get("found")),
                f"found={bool(verify and verify.get('found'))} occurrences={notes.get('occurrence_count')}"
                f" attempts={len(verify_attempts)}"
                f" sink_read={sink_read.get('rows_with_tag')}/{sink_read.get('row_count')}",
            )
        )

    verdict, explanation = judge_trigger(
        verify=verify, written=change is not None, db_error=db_error
    )
    notes["explanation"] = explanation

    # P6 Rollback + report ------------------------------------------------------
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
    stages.append(StageRecord("P6", True, "Report generated"))
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
