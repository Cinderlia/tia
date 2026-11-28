"""Trigger the agent main flow (P0–P6).

P0 Create case → P1 Locate read points and entry → P2 Read point reachable → P3 Prepare data → P4 Write payload
→ P5 verify_tag forensics → P6 Rollback + report.

This implementation uses a "deterministic planner" instead of an LLM planner: decision rules for each step are defined here;
the LLM only affects "what to do next", not "what the tool returns". Integrate the planner once the main flow is stable.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from tia.ad.llm import LlmClient
from tia.cap.case import parse_sink
from tia.cap.cleanup import cleanup_new_rows, cleanup_tagged_rows, key_snapshot
from tia.cap.entry import (
    EntryCandidate,
    derive_payload_constraints,
    entry_candidates,
    infer_entry,
)
from tia.cap.forms import FormField, PageForm
from tia.cap.request_plan import plan_request
from tia.cap.schema import fetch_brief, render_brief
from tia.cap.write_sql import compile as compile_write
from tia.cap.write_sql import plan_write_sql
from tia.dom.state_probe import StateProbeRequest, constant_review, run_state_probe
from tia.inf.reports import write_case_report
from tia.inf.runtime import get_runtime
from tia.inf.settings import attempt_limit
from tia.inf.store import now_iso
from tia.orch.kernel import Kernel, LocalToolClient, StepRecord, ToolCallError, ToolClient
from tia.orch.learning import record_case
from tia.schemas.envelope import ToolError
from tia.schemas.plan import ConstraintPlan, ConstraintWrite, PayloadPlan, Step
from tia.schemas.verdict import TriggerVerdict
from tia.sinks.base import Observation, trigger_verdict
from tia.sinks.registry import sink_class_for

#: Exploration budget: enough attempts for complex entry pages, still bounded.
ENTRY_ATTEMPTS = attempt_limit("entry", 8)
#: How many payload shapes one slice may try before the slice is judged.
PAYLOAD_ATTEMPTS = attempt_limit("payload", 3)
#: Bounded discovery of database-only branch conditions.
CONSTRAINT_ROUNDS = attempt_limit("constraint_rounds", 3)
CONSTRAINT_WRITES = attempt_limit("constraint_writes", 3)

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


_MAX_READ_LINES = 4


def _select_lines(lines: list[dict[str, Any]], table: str, limit: int = _MAX_READ_LINES) -> list[int]:
    """Line numbers of SELECT statements that read the target table."""
    found: list[int] = []
    for item in lines:
        text = str(item.get("text", ""))
        match = _SELECT_RE.search(text)
        number = item.get("n")
        if match is None or match.group(1).lower() != table.lower():
            continue
        if isinstance(number, int) and number not in found:
            found.append(number)
            if len(found) >= limit:
                break
    return found


async def _capture_read_sql(
    kernel: Kernel,
    case_id: str,
    sink_file: str,
    lines: list[dict[str, Any]],
    table: str,
    base_url: str,
    tag: str,
) -> dict[str, Any]:
    """Run the read page once with the capture armed and keep the executed SQL."""
    note: dict[str, Any] = {"lines": [], "reads": []}
    candidates = _select_lines(lines, table)
    if not candidates:
        return note
    note["lines"] = candidates
    try:
        await kernel.call(
            "probe_arm",
            {
                "case_id": case_id,
                "targets": [{"file": sink_file, "line": line} for line in candidates],
            },
        )
    except ToolCallError as exc:
        note["error"] = exc.code.value
        return note
    try:
        run = await kernel.call("probe_run", {"case_id": case_id, "url": base_url})
    except ToolCallError as exc:
        note["error"] = exc.code.value
        return note
    finally:
        with contextlib.suppress(ToolCallError):
            await kernel.call("probe_disarm", {"case_id": case_id})
    seen: set[str] = set()
    for query in run.get("queries") or []:
        sql = str(query.get("sql") or "").strip()
        if not sql:
            continue
        key = " ".join(sql.lower().split())
        if key in seen:
            continue
        seen.add(key)
        note["reads"].append(
            {
                "sql": sql,
                "line": query.get("matched_at_line") or query.get("matched_at"),
                "rows": list(query.get("rows") or [])[:8],
            }
        )
    note["hit"] = bool(note["reads"])
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


def _column_value(column: str, *, payload: str, tag: str, column_type: str = "") -> str:
    """Value for a column: real payload in strings, a legal filler elsewhere."""
    declared = (column_type or "").lower()
    if any(kind in declared for kind in ("int", "decimal", "float", "double", "numeric")):
        return "1"
    if any(kind in declared for kind in ("date", "time")):
        return _today()
    return payload


def _payload_candidates(
    payload_base: str,
    tag: str,
    context_kind: str,
    limit: int,
    *,
    sink_class: Any = None,
    site: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    """Ordered payload candidates, seeded by the sink class for this kind."""
    if sink_class is None:
        sink_class = sink_class_for(str((site or {}).get("kind") or "Xss"))
    candidates: list[tuple[str, str]] = sink_class.seed(
        site or {}, context_kind, tag, payload_base=payload_base
    )
    return candidates[:limit]


def _entry_variants(candidates: list[EntryCandidate], limit: int) -> list[EntryCandidate]:
    """Add single-field variants: exclusive filters often accept only one key."""
    out: list[EntryCandidate] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for candidate in candidates:
        variants = [candidate]
        if len(candidate.values) > 1:
            for key, value in candidate.values.items():
                variants.append(
                    EntryCandidate(
                        candidate.method,
                        {key: value},
                        max(10, candidate.confidence - 5),
                        {key: "single-field"},
                    )
                )
        for variant in variants:
            marker = (variant.method, tuple(sorted(variant.values.items())))
            if marker in seen:
                continue
            seen.add(marker)
            out.append(variant)
    return out[:limit]



_LITERAL_EQ_RE = re.compile(
    r"(?:where|and|or)\s+`?(\w+)`?\s*=\s*'([^']{1,40})'", re.IGNORECASE
)
_ROW_CMP_RE = re.compile(
    r"\$?\w+\[\s*['\"](\w+)['\"]\s*\]\s*(?:===?|!==?)\s*['\"]([^'\"]{1,40})['\"]"
)
_NULL_CMP_RE = re.compile(r"\$?\w+\[\s*['\"](\w+)['\"]\s*\]\s*is\s+null", re.IGNORECASE)


def _constraint_candidates(
    source_text: str, table_meta: dict[str, Any], payload_column: str
) -> list[dict[str, Any]]:
    """Static hints for branch conditions that a database write could satisfy.

    Only values that literally appear next to a real column are proposed; the
    caller proves each one by writing it and re-reading the page, so a wrong
    guess costs one bounded attempt instead of corrupting the plan.
    """
    columns = {
        str(col.get("name")): str(col.get("type") or "")
        for col in table_meta.get("columns") or []
    }
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(column: str, value: str, predicate: str, why: str) -> None:
        if column not in columns or column == payload_column:
            return
        key = (column, value)
        if key in seen:
            return
        seen.add(key)
        found.append(
            {
                "column": column,
                "value": value,
                "predicate": predicate.strip(),
                "why": why,
            }
        )

    for match in _LITERAL_EQ_RE.finditer(source_text):
        add(
            match.group(1),
            match.group(2),
            match.group(0),
            "the SQL filter compares this column to a literal",
        )
    for match in _ROW_CMP_RE.finditer(source_text):
        add(
            match.group(1),
            match.group(2),
            match.group(0),
            "the branch compares this row field to a literal",
        )
    for match in _NULL_CMP_RE.finditer(source_text):
        add(
            match.group(1),
            "",
            match.group(0),
            "the branch requires a NULL value",
        )
    # Boolean-ish columns mentioned in a condition usually gate visibility.
    for name, col_type in columns.items():
        if name == payload_column:
            continue
        if name not in source_text:
            continue
        if re.search(r"\b(tinyint|bool|boolean|bit)\b", col_type, re.IGNORECASE):
            add(name, "1", name, "a boolean column guards the branch")
    return found[: max(1, CONSTRAINT_WRITES)]


async def _fetch_verify(
    kernel: Kernel,
    base_url: str,
    method: str,
    values: dict[str, str],
    tag: str,
    payload: str,
) -> dict[str, Any] | None:
    """Fetch the trigger page the same way the entry was solved, then verify."""
    try:
        if method.upper() == "GET":
            fetched = await kernel.call(
                "http_request", {"method": "GET", "url": base_url, "params": values}
            )
        else:
            fetched = await kernel.call(
                "http_request",
                {
                    "method": "POST",
                    "url": base_url,
                    "body": urlencode(values),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )
        args: dict[str, Any] = {"tag": tag, "payload": payload}
        body = str(fetched.get("body") or "")
        if body:
            args["html"] = body
            args["content_type"] = str(fetched.get("content_type") or "text/html")
        else:
            args["url"] = base_url
        result = await kernel.call("verify_tag", args)
        return result if isinstance(result, dict) else None
    except ToolCallError:
        return None


async def _node_windows(
    kernel: Kernel, slice_doc: dict[str, Any], sink_file: str, limit: int = 6
) -> list[dict[str, Any]]:
    """Read short windows around taint nodes that live in other files.

    A sink can be a shared template while the SQL that feeds it sits in the
    calling module (the NAVI chain records both).  Inference needs that view.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for node in slice_doc.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        file = str(node.get("file") or "")
        line = int(node.get("line") or 0)
        if not file or not line or file == sink_file or file in seen:
            continue
        seen.add(file)
        try:
            window = await kernel.call("source_read", {"file": file, "around": {"line": line, "n": 8}})
        except ToolCallError:
            continue
        out.append(window)
        if len(out) >= limit:
            break
    return out





async def _sql_probe_verify(
    kernel: Kernel,
    case_id: str,
    file: str,
    line: int,
    url: str,
    method: str,
    values: dict[str, str],
    tag: str,
    sink_class: Any,
    context: str,
) -> dict[str, Any]:
    """Read a stored value back and let the SQL probe judge the read page."""
    with contextlib.suppress(ToolCallError):
        await kernel.call(
            "probe_arm",
            {"case_id": case_id, "file": file, "line": line, "output": f"trigger-read-{tag}.json"},
        )
    arguments: dict[str, Any] = {"case_id": case_id, "url": url, "method": method.upper()}
    if method.upper() == "POST":
        arguments["body"] = urlencode(values)
        arguments["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        arguments["params"] = values
    try:
        run = await kernel.call("probe_run", arguments)
    finally:
        with contextlib.suppress(ToolCallError):
            await kernel.call("probe_disarm", {"case_id": case_id})
    queries = run.get("queries") or []
    statements = [str(item.get("sql") or "") for item in queries if isinstance(item, dict)]
    marker = any(tag in statement for statement in statements)
    facts = {
        "executed": bool(queries),
        "error": str(run.get("error") or ""),
        "statements": statements[:3],
    }
    outcome = sink_class.accept(
        Observation(
            channel="sql_probe",
            request={"url": url, "method": method, "values": values},
            payload=tag,
            marker_seen=marker,
            facts={"sql_probe": facts},
        ),
        context,
    )
    return {
        "found": marker,
        "best": {"executable": outcome.confirmed, "context_kind": "sql_probe"},
        "sql_probe": facts,
        "sql_probe_level": outcome.level,
    }

async def run_trigger(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
    flow: dict[str, Any] | None = None,
) -> TriggerResult:
    """Run the trigger agent and always revert the rows it wrote directly.

    P6 reverts on the normal path; this guard covers exceptions, timeouts and
    budget exhaustion, which would otherwise leave a payload row in the target.
    """
    case: dict[str, Any] = {}
    try:
        return await _run_trigger(
            raw_slice,
            base_url=base_url,
            payload_base=payload_base,
            budget=budget,
            client=client,
            slice_id=slice_id,
            flow=flow,
            case=case,
        )
    finally:
        case_id = str(case.get("case_id") or "")
        if case_id:
            await _revert_pending_writes(case_id)
        await _sweep_tagged_rows(case.get("cleanup"))


async def _revert_pending_writes(case_id: str) -> None:
    """Undo direct writes left pending by an interrupted trigger run."""
    from tia.cap.db import db_undo
    from tia.schemas.envelope import ToolError

    rt = get_runtime()
    try:
        if not rt.store.list_changes(case_id, pending_only=True):
            return
        await db_undo({"case_id": case_id})
    except ToolError:
        pass


async def _sweep_tagged_rows(state: dict[str, Any] | None) -> None:
    """Delete every row carrying this run's tag, whoever wrote it."""
    if not state or state.get("kernel") is None:
        return
    kernel = state["kernel"]
    case_id = str(state.get("case_id") or "")
    tag = str(state.get("tag") or "")
    snapshots = dict(state.get("snapshots") or {})
    if str(state.get("table") or "") in snapshots:
        await cleanup_new_rows(
            kernel, case_id=case_id, snapshots=snapshots, tag=tag
        )
        return
    await cleanup_tagged_rows(
        kernel,
        case_id=case_id,
        table=str(state.get("table") or ""),
        columns=[str(column) for column in state.get("columns") or []],
        tag=tag,
    )


async def _run_trigger(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
    flow: dict[str, Any] | None = None,
    case: dict[str, Any] | None = None,
) -> TriggerResult:
    rt = get_runtime()
    slice_doc = normalize_slice(raw_slice)
    sink_class = sink_class_for(str(slice_doc.get("kind") or ""))
    # The sink class decides how it is proved: a class that never persists a
    # payload is proved through the request itself, regardless of what writers a
    # flow happens to carry.  Writers only matter to classes that store a value.
    if not sink_class.writes_database():
        from tia.dom.request_prover import run_request_prover

        return await run_request_prover(
            raw_slice,
            base_url=base_url,
            payload_base=payload_base,
            budget=budget,
            client=client,
            slice_id=slice_id,
            flow=flow,
            case=case,
        )
    sink = slice_doc["sink"]
    sink_file, sink_line = sink["file"], sink["line"]
    params = [str(p) for p in (slice_doc.get("params") or [])]
    stages: list[StageRecord] = []
    notes: dict[str, Any] = {
        "base_url": base_url,
        "sink": f"{sink_file}:{sink_line}",
        "sink_file": sink_file,
        "sink_code": str(sink.get("code") or ""),
    }
    if flow:
        notes["flow_id"] = str(flow.get("flow_id") or "")
        notes["flow_class"] = str(flow.get("sink_class") or "")
        notes["flow_writers"] = list(flow.get("writer_slice_ids") or [])
    kernel = Kernel(
        profile="trigger", budget=budget, client=client or LocalToolClient(profile="trigger")
    )

    def done(result: TriggerResult) -> TriggerResult:
        record_case(rt.store, {"sinkFile": sink_file}, result.verdict, result.notes)
        return result

    # P0 Create case ------------------------------------------------------------
    opened = await kernel.call("case_open", {"slice": slice_doc, "agent": "trigger", "write_targets": []})
    case_id = str(opened["case_id"])
    kernel.case_id = case_id
    if case is not None:
        case["case_id"] = case_id
    kernel.slice_id = slice_id
    stages.append(StageRecord("P0", True, f"case_id={case_id}"))

    # P1 Locate read points and entry ---------------------------------------------------
    source = await kernel.call("source_read", {"file": sink_file, "around": {"line": sink_line, "n": 40}})
    source_text = "\n".join(str(line["text"]) for line in source["lines"])
    notes["source_sha256"] = source["sha256"]
    node_windows = await _node_windows(kernel, slice_doc, sink_file)
    inference_text = "\n".join(
        [source_text]
        + [
            "\n".join(str(line["text"]) for line in window["lines"])
            for window in node_windows
        ]
    )
    inferred = _infer_target(inference_text, params)
    table = inferred["table"]
    columns = inferred["insert_columns"]
    if not table and flow:
        table = str(flow.get("table") or flow.get("table_name") or "")
        columns = [str(column) for column in (flow.get("columns") or [])]
        if table:
            notes["inference_source"] = "flow"
    if not table:
        stages.append(StageRecord("P1", False, "Failed to infer target table from source code"))
        return done(TriggerResult(case_id=case_id, verdict="SQL_ERROR", residue=None,
                                  report=await kernel.report(), stages=stages, notes=notes,
                                  trace=kernel.trace))
    post_vars = sorted(set(_POST_VAR_RE.findall(source_text))) or params
    entry_plan = infer_entry(inference_text)
    read_lines = [line for line in source["lines"] if isinstance(line, dict)]
    for window in node_windows:
        read_lines.extend(line for line in window["lines"] if isinstance(line, dict))
    read_line = _read_line(read_lines, table)
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
        return done(TriggerResult(case_id=case_id, verdict="READ_EMPTY", residue=None,
                                  report=await kernel.report(), stages=stages, notes=notes,
                                  trace=kernel.trace))
    stages.append(StageRecord("P2", True, f"HTTP {status}, form fields {form_fields}"))

    # P3 Prepare data ----------------------------------------------------------
    schema = await kernel.call("db_schema", {"table": table})
    table_meta = schema["tables"][0]
    notes["table_meta"] = {
        "columns": [c["name"] for c in table_meta["columns"]],
        "primary_key": table_meta.get("primary_key", []),
    }
    stages.append(StageRecord("P3", True, f"Table {table} has {len(table_meta['columns'])} columns"))

    # P4 Craft payload candidates from the sink context and write them --------
    tag = _tag()
    sink_class = sink_class_for(str(slice_doc.get("kind") or "Xss"))
    context_hint = sink_class.context(sink, str(sink.get("code") or ""))
    channel = sink_class.observation_channel()
    payloads = _payload_candidates(
        payload_base,
        tag,
        context_hint,
        PAYLOAD_ATTEMPTS,
        sink_class=sink_class,
        site=slice_doc,
    )
    notes.update({"tag": tag, "context_hint": context_hint, "sink_class": sink_class.name})
    pk_columns = list(table_meta.get("primary_key") or [])
    value_columns = columns or [
        c["name"] for c in table_meta["columns"] if c["name"] not in pk_columns
    ]
    column_length = {c["name"]: c.get("length") for c in table_meta["columns"]}
    payload_column = value_columns[0] if value_columns else ""
    # Capture the statement the application actually runs before anything is
    # written: its SELECT list fixes which `$rows[i]` maps to which column, and
    # its rows tell the model which row the read path will render.
    read_evidence = await _capture_read_sql(
        kernel, case_id, sink_file, read_lines, table, base_url, tag
    )
    if read_evidence.get("reads"):
        notes["read_sql"] = [str(item["sql"]) for item in read_evidence["reads"]]
        notes["read_rows"] = [
            dict(row) for item in read_evidence["reads"] for row in item.get("rows") or []
        ][:8]
    if read_evidence.get("error"):
        notes["read_sql_error"] = read_evidence["error"]

    schema_text = ""
    # Give the model the NOT NULL/default/FK facts whether it updates or inserts.
    try:
        brief = await fetch_brief(kernel.call, table, payload_columns=value_columns)
    except (ToolCallError, ValueError) as exc:
        notes["schema_brief_error"] = str(exc)
    else:
        schema_text = render_brief(brief)
        notes["schema_brief"] = brief.to_dict()
    # The application writes rows as well (the verification POST submits the
    # form), so tag-based cleanup covers both our direct writes and the app's.
    if case is not None:
        # Record the keys before the payload write so cleanup can delete by key
        # range instead of scanning the whole table for the tag.
        snapshots = await key_snapshot(kernel, [table])
        case["cleanup"] = {
            "kernel": kernel,
            "case_id": case_id,
            "table": table,
            "columns": value_columns,
            "tag": tag,
            "snapshots": snapshots,
        }

    # The model writes the statement; local code only renders {{PAYLOAD}} and
    # checks structure. The captured read fixes the column and the row.
    write_plan: dict[str, Any] | None = None
    template = ""
    write_mode = "insert"
    try:
        write_plan = await plan_write_sql(
            LlmClient.from_env(),
            sink=f"{sink.get('file')}:{sink.get('line')}\n{sink.get('code')}",
            table=table,
            columns=value_columns,
            schema=schema_text,
            observed=list(read_evidence.get("reads") or []),
            rows=list(notes.get("read_rows") or []),
            payload=payloads[0][1] if payloads else f"{payload_base}{tag}",
            tag=tag,
        )
    except (ToolCallError, ToolError) as exc:
        notes["write_plan_error"] = f"{exc.code.value}: {exc.message}"
    if write_plan is not None:
        notes["write_plan"] = write_plan
        template = str(write_plan["template"])
        payload_column = str(write_plan["column"])
        notes["payload_column"] = payload_column
        notes["column_chosen_by"] = "llm_sql"
        head = str(write_plan["sql"]).split(None, 1)[0].lower()
        write_mode = "update" if head == "update" else "insert"
    notes["write_mode"] = write_mode

    change: dict[str, Any] | None = None
    db_error: str | None = None
    verify: dict[str, Any] | None = None
    verify_attempts: list[dict[str, Any]] = []
    payload_attempts: list[dict[str, Any]] = []
    chosen: dict[str, Any] | None = None
    entry_request: tuple[str, dict[str, str]] | None = None

    for shape, payload in payloads:
        if not template:
            payload_attempts.append(
                {
                    "shape": shape,
                    "payload": payload,
                    "written": False,
                    "error": notes.get("write_plan_error", "NO_WRITE_SQL"),
                }
            )
            continue
        rounds = 0
        while True:
            try:
                sql, _statement = compile_write(
                    template,
                    table=table,
                    columns=value_columns,
                    payload=payload,
                    row_id=write_plan.get("row_id") if write_plan else None,
                )
                written = await kernel.call("db_write", {"sql": sql})
            except (ToolCallError, ToolError) as exc:
                db_error = f"{exc.code.value}: {exc.message}"
                rounds += 1
                if rounds > 2:
                    payload_attempts.append(
                        {
                            "shape": shape,
                            "payload": payload,
                            "written": False,
                            "error": db_error,
                        }
                    )
                    break
                try:
                    write_plan = await plan_write_sql(
                        LlmClient.from_env(),
                        sink=f"{sink.get('file')}:{sink.get('line')}\n{sink.get('code')}",
                        table=table,
                        columns=value_columns,
                        schema=schema_text,
                        observed=list(read_evidence.get("reads") or []),
                        rows=list(notes.get("read_rows") or []),
                        payload=payload,
                        tag=tag,
                        error=db_error,
                    )
                except (ToolCallError, ToolError) as replan:
                    payload_attempts.append(
                        {
                            "shape": shape,
                            "payload": payload,
                            "written": False,
                            "error": f"{db_error}; replan: {replan.code.value}: {replan.message}",
                        }
                    )
                    break
                notes["write_plan"] = write_plan
                template = str(write_plan["template"])
                payload_column = str(write_plan["column"])
                notes["payload_column"] = payload_column
                continue
            change = written.get("change") if isinstance(written, dict) else None
            change_id = change.get("change_id") if change else None
            notes["change_id"] = change_id
            notes["write_sql"] = sql
            notes["insert_sql"] = sql
            payload_attempts.append({"shape": shape, "payload": payload, "written": True})
            break

        row: dict[str, Any] | None = None
        order = f" ORDER BY `{pk_columns[0]}` DESC" if pk_columns else ""
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
            limit=ENTRY_ATTEMPTS,
        )
        variants = _entry_variants(candidates, ENTRY_ATTEMPTS)
        planned = await plan_request(
            client=LlmClient.from_env(),
            goal="open this page so the row that carries the tag is selected and rendered",
            page_url=base_url,
            forms=[
                PageForm(
                    action=base_url,
                    method=entry_plan.method.lower() or "get",
                    fields=[
                        FormField(name=item.name, type="numeric" if item.numeric else "text")
                        for item in entry_plan.fields
                    ],
                )
            ],
            source_text=source_text,
            payload=tag,
            hint="the payload was just written; choose parameters that make the page query and render that row",
            fallback_fields=variants[0].values if variants else {},
            fallback_method=entry_plan.method.upper() or "GET",
        )
        if planned is not None and planned.values:
            plan_note = {
                "source": planned.source,
                "method": planned.method,
                "values": planned.values,
                "reason": planned.reason,
            }
            notes["read_request_plan"] = plan_note
            variants = [
                EntryCandidate(
                    method=planned.method,
                    values=planned.values,
                    confidence=90 if planned.source == "llm" else 60,
                    basis={"plan": planned.source},
                )
            ] + [c for c in variants if (c.method, c.values) != (planned.method, planned.values)]
        if variants and entry_request is None:
            entry_request = (variants[0].method, variants[0].values)
        if read_line is not None:
            notes["sink_read"] = await _probe_sink_read(
                kernel, case_id, sink_file, read_line, base_url, tag, entry_request
            )

        attempt_verify: dict[str, Any] | None = None
        for candidate in variants:
            attempt: dict[str, Any] = {
                "shape": shape,
                "payload": payload,
                "method": candidate.method,
                "values": candidate.values,
                "confidence": candidate.confidence,
                "basis": candidate.basis,
                "found": False,
            }
            try:
                if channel == "sql_probe":
                    if read_line is None:
                        attempt["error"] = "no read line to watch"
                        verify_attempts.append(attempt)
                        continue
                    attempt_verify = await _sql_probe_verify(
                        kernel,
                        case_id,
                        sink_file,
                        read_line,
                        base_url,
                        candidate.method,
                        dict(candidate.values),
                        tag,
                        sink_class,
                        context_hint,
                    )
                    attempt["status"] = 200
                else:
                    if candidate.method == "GET":
                        fetched = await kernel.call(
                            "http_request",
                            {"method": "GET", "url": base_url, "params": candidate.values},
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
                    attempt["status"] = fetched.get("status")
                    body = str(fetched.get("body") or "")
                    verify_args: dict[str, Any] = {"tag": tag, "payload": payload}
                    if body:
                        verify_args["html"] = body
                        verify_args["content_type"] = str(
                            fetched.get("content_type") or "text/html"
                        )
                    else:
                        verify_args["url"] = base_url
                    attempt_verify = await kernel.call("verify_tag", verify_args)
            except ToolCallError as exc:
                attempt["error"] = f"{exc.code.value}: {exc.message}"
                verify_attempts.append(attempt)
                continue
            attempt["found"] = bool(attempt_verify.get("found"))
            attempt["executable"] = bool((attempt_verify.get("best") or {}).get("executable"))
            attempt["occurrence_count"] = attempt_verify.get("occurrence_count")
            verify_attempts.append(attempt)
            if attempt["found"]:
                if (
                    verify is None
                    or attempt["executable"]
                    or not bool((verify.get("best") or {}).get("executable"))
                ):
                    verify = attempt_verify
                entry_request = (candidate.method, candidate.values)
                chosen = {"shape": shape, "payload": payload, "values": candidate.values,
                          "method": candidate.method}
                if attempt["executable"]:
                    break
        payload_attempts[-1]["found"] = bool(attempt_verify and attempt_verify.get("found"))
        payload_attempts[-1]["executable"] = bool(
            attempt_verify and (attempt_verify.get("best") or {}).get("executable")
        )
        if attempt_verify is not None and bool((attempt_verify.get("best") or {}).get("executable")):
            break
        # Not executable yet.  If the page did not show the value at all, keep
        # the row: a database-only branch condition may be hiding it, and the
        # constraint discovery below needs a row to rewrite.  If the page did
        # show it (context/encoding problem), drop the row and try the next
        # payload shape.
        if change_id:
            if attempt_verify is not None and not bool(attempt_verify.get("found")):
                break
            with contextlib.suppress(ToolCallError):
                await kernel.call("db_undo", {"change_id": change_id})
            change = None

    if chosen is None and verify is not None:
        chosen = {"shape": "unknown", "payload": payloads[0][1], "values": {}, "method": "GET"}
    # P3/P5 attribution: database-only branch conditions ----------------------
    # The payload is in place but the page still does not render it. Instead of
    # giving up, look for literal branch conditions in the source, satisfy each
    # one with a direct write, and re-read the page. Direct writes are discovery
    # only: they are recorded as ConstraintWrite steps and P6 rolls them back.
    constraints: list[dict[str, Any]] = []
    constraint_attempts: list[dict[str, Any]] = []
    best_now = (verify or {}).get("best") or {}
    if (
        change is not None
        and payload_column
        and not bool(best_now.get("executable"))
        and entry_request is not None
    ):
        trigger_method, trigger_values = entry_request
        for round_index in range(max(1, CONSTRAINT_ROUNDS)):
            progressed = False
            for hint in _constraint_candidates(source_text, table_meta, payload_column):
                if any(item["column"] == hint["column"] for item in constraints):
                    continue
                column = hint["column"]
                value_sql = (
                    "NULL" if hint["value"] == "" else _sql_literal(str(hint["value"]))
                )
                sql = (
                    f"UPDATE `{table}` SET `{column}`={value_sql} "
                    f"WHERE `{payload_column}` LIKE '%{tag}%'"
                )
                discovery_id: str | None = None
                try:
                    written_condition = await kernel.call("db_write", {"sql": sql})
                    change_condition = (
                        written_condition.get("change") if isinstance(written_condition, dict) else None
                    )
                    discovery_id = str((change_condition or {}).get("change_id") or "") or None
                except ToolCallError as exc:
                    constraint_attempts.append(
                        {
                            "round": round_index,
                            "column": column,
                            "value": hint["value"],
                            "written": False,
                            "error": f"{exc.code.value}: {exc.message}",
                        }
                    )
                    continue
                refreshed = await _fetch_verify(
                    kernel, base_url, trigger_method, trigger_values, tag, str((chosen or {}).get("payload") or "")
                )
                new_best = (refreshed or {}).get("best") or {}
                progressed_now = bool(new_best.get("executable"))
                constraint_attempts.append(
                    {
                        "round": round_index,
                        "column": column,
                        "value": hint["value"],
                        "predicate": hint["predicate"],
                        "written": True,
                        "found": bool((refreshed or {}).get("found")),
                        "executable": progressed_now,
                    }
                )
                if progressed_now:
                    constraint = ConstraintWrite(
                        constraint_id=f"dc-{len(constraints) + 1}",
                        at=f"{sink.get('file')}:{sink.get('line')}",
                        predicate=hint["predicate"],
                        why=hint["why"],
                        table=table,
                        column=column,
                        value=hint["value"],
                        sql=sql,
                        depends_on=["payload"] if constraints == [] else [],
                        replay="app_request",
                        confidence=70,
                        evidence_refs=[],
                    )
                    constraints.append(constraint.model_dump())
                    verify = refreshed
                    progressed = True
                    break
                if discovery_id:
                    with contextlib.suppress(ToolCallError):
                        await kernel.call("db_undo", {"change_id": discovery_id})
            if progressed or not constraints:
                continue
            if bool(((verify or {}).get("best") or {}).get("executable")):
                break

    if constraints:
        notes["constraints"] = constraints
    notes["constraint_attempts"] = constraint_attempts
    best_now = (verify or {}).get("best") or {}
    if constraints or (change is not None and str((chosen or {}).get("payload") or "")):
        payload_plan = PayloadPlan(
            table=table,
            column=payload_column,
            payload=str((chosen or {}).get("payload") or ""),
            tag=tag,
            context_kind=str(best_now.get("context_kind") or context_hint),
            out_filter="none" if bool(best_now.get("executable")) else "unknown",
            length_budget=(
                int(column_length[payload_column])
                if column_length.get(payload_column) is not None
                else None
            ),
            sink=f"{sink.get('file')}:{sink.get('line')}\n{sink.get('code')}",
            evidence_refs=[],
        )
        steps = [Step(kind="payload", ref="payload")]
        steps += [
            Step(kind="constraint", ref=str(item["constraint_id"]), phase="after_payload")
            for item in constraints
        ]
        trigger_method, trigger_values = entry_request or ("GET", {})
        notes["constraint_plan"] = ConstraintPlan(
            steps=steps,
            payload=payload_plan,
            constraints=[ConstraintWrite.model_validate(item) for item in constraints],
            final_trigger={
                "url": base_url,
                "method": trigger_method.upper(),
                "fields": trigger_values,
            },
        ).model_dump()

    notes["payload_attempts"] = payload_attempts
    notes["payload_candidates"] = [payload for _, payload in payloads]
    if chosen is not None:
        notes["payload_shape"] = chosen["shape"]
        notes["payload"] = chosen["payload"]
        if entry_request is not None:
            notes["read_entry_values"] = entry_request[1]

    stages.append(
        StageRecord(
            "P4",
            any(item.get("written") for item in payload_attempts),
            f"shapes={[shape for shape, _ in payloads]}"
            + (f" db_error={db_error}" if db_error else ""),
        )
    )

    # P5 Verify the reflected payload -----------------------------------------
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
        final_payload = str((chosen or {}).get("payload") or "")
        if channel != "sql_probe":
            notes["payload_constraints"] = derive_payload_constraints(
                verify,
                column=payload_column,
                column_length=column_length.get(payload_column),
                payload=final_payload,
            )
        if channel != "sql_probe" and bool(best.get("executable")) and chosen is not None:
            try:
                confirmed = await kernel.call(
                    "verify_tag",
                    {
                        "url": base_url,
                        "tag": tag,
                        "payload": final_payload,
                        "execute": True,
                        "execute_method": str(chosen.get("method") or "GET").upper(),
                        "execute_fields": {
                            str(key): str(value)
                            for key, value in dict(chosen.get("values") or {}).items()
                        },
                    },
                )
                notes["execution"] = confirmed.get("execution")
                verify["execution"] = confirmed.get("execution")
            except ToolCallError:
                notes["execution"] = None
    elif channel != "sql_probe" and db_error is None:
        try:
            verify = await kernel.call(
                "verify_tag", {"tag": tag, "payload": payloads[0][1], "url": base_url}
            )
        except ToolCallError as exc:
            notes["verify_error"] = f"{exc.code.value}: {exc.message}"

    sink_read = notes.get("sink_read") or {}
    stages.append(
        StageRecord(
            "P5",
            verify is not None and bool(verify.get("found")),
            f"found={bool(verify and verify.get('found'))} occurrences={notes.get('occurrence_count')}"
            f" payloads={len(payload_attempts)} attempts={len(verify_attempts)}"
            f" sink_read={sink_read.get('rows_with_tag')}/{sink_read.get('row_count')}",
        )
    )

    wrote_any = any(bool(item.get("written")) for item in payload_attempts)
    if db_error:
        verdict, explanation = TriggerVerdict.SQL_ERROR, f"Write phase failed: {db_error}"
    else:
        if channel == "sql_probe":
            outcome = sink_class.accept(
                Observation(
                    channel="sql_probe",
                    payload=final_payload if verify is not None else payload_base,
                    marker_seen=bool(verify and verify.get("found")),
                    facts={"sql_probe": (verify or {}).get("sql_probe") or {}},
                ),
                context_hint,
            )
        else:
            outcome = sink_class.accept(
                Observation(
                    channel="page",
                    payload=payload_base,
                    marker_seen=bool(verify and verify.get("found")),
                    facts={"verify": verify, "written": change is not None or wrote_any},
                ),
                context_hint,
            )
        verdict = TriggerVerdict(trigger_verdict(outcome))
        explanation = outcome.reason
    if constraints:
        notes["explanation"] = (
            f"{explanation}; {len(constraints)} database condition(s) were required and "
            "recorded as replay steps"
        )
    else:
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
    rt.store.merge_case_notes(case_id, notes)
    report = await kernel.report()
    rt.store.set_case_report(case_id, report)
    write_case_report(rt.store, case_id)
    stages.append(StageRecord("P6", True, "Report generated"))
    notes["account"] = os.environ.get("TIA_ACCOUNT") or "anonymous (no login)"
    notes["observed_at"] = now_iso()
    return done(
        TriggerResult(
            case_id=case_id,
            verdict=str(verdict),
            residue=residue,
            report=report,
            stages=stages,
            notes=notes,
            trace=kernel.trace,
        )
    )



async def _retry_insert_with_state(
    kernel: Kernel,
    case_id: str,
    table: str,
    value_columns: list[str],
    values: list[str],
    sql: str,
    exc: ToolCallError,
    notes: dict[str, Any],
    *,
    payload_column: str = "",
) -> tuple[Any, str] | None:
    """Ask state_probe which values make this INSERT legal, then retry once."""

    request = StateProbeRequest(
        case_id=case_id,
        table=table,
        payload_columns=[payload_column] if payload_column else [],
        failed_sql=sql[:2000],
        error_text=exc.message[:500],
        register_targets=getattr(kernel, "set_write_targets", None),
        review=constant_review(),
    )
    plan = await run_state_probe(kernel.call, request)
    notes["state_plan"] = plan.to_dict()
    try:
        from tia.inf.runtime import get_runtime

        get_runtime().store.save_state_plan(case_id, plan.to_dict())
    except Exception:  # noqa: BLE001 - persistence must not break the run
        pass
    if plan.status != "READY":
        return None
    merged = dict(zip(value_columns, values, strict=True))
    merged.update(plan.values)
    columns = list(merged)
    retry_sql = (
        f"INSERT INTO `{table}` ({', '.join(f'`{c}`' for c in columns)}) "
        f"VALUES ({', '.join(_state_literal(merged[c]) for c in columns)})"
    )
    written = await kernel.call("db_write", {"sql": retry_sql})
    notes["state_plan_retry"] = True
    return written, retry_sql


def _sql_literal(value: object) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _state_literal(value: object) -> str:
    text = str(value)
    if text == "NOW()":
        return text
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return text
    return _sql_literal(text)
