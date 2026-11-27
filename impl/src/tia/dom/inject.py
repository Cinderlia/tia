"""inject agent: proves "user can write content via HTTP entry" (I0–I7).

Division of labor with trigger: trigger writes directly to DB to prove sink reachability; inject only uses the app's own forms,
DB writes are performed by the app, finally using ``db_read`` / ``verify_tag`` for tri-state acceptance.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import os
import re
import secrets
import string
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from tia.ad.llm import LlmClient
from tia.cap.cleanup import (
    cleanup_new_rows,
    cleanup_tagged_rows,
    key_snapshot,
    max_key,
    parent_links,
    remove_orphan_parents,
)
from tia.cap.delivery import DeliveryAttempt, deliver
from tia.cap.domscan import Document, echo_snapshot, parse
from tia.cap.entry import (
    EntryPlan,
    entry_candidates,
    entry_field,
    resolve_values_with_guess,
)
from tia.cap.forms import FormField, PageForm, find_form, forms_from_document
from tia.cap.request_plan import plan_request
from tia.dom.trigger import StageRecord
from tia.inf.accounts import public_catalog
from tia.inf.reports import write_case_report
from tia.inf.runtime import get_runtime
from tia.inf.settings import attempt_limit
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient
from tia.orch.learning import preferred_payload_shape, record_case
from tia.sinks.base import Observation, inject_verdict
from tia.sinks.registry import sink_class_for

DEFAULT_PAYLOAD = "<script>alert(1)</script>"

# The rows this run wrote through the application, so cleanup can always find
# them: state is set before the first POST and cleared once residue is zero.
_ACTIVE_CLEANUP: ContextVar[dict[str, Any] | None] = ContextVar(
    "tia_inject_cleanup", default=None
)


async def _cleanup_tagged_rows(kernel: Kernel, state: dict[str, Any]) -> int:
    """Delete every row this run left behind, whoever wrote it.

    The tag covers rows the application created, the insert ids the probe
    reported cover parent rows that carry no tag, and the foreign keys of the
    target table cover the parents those insert ids could not name.
    """
    case_id = str(state.get("case_id") or "")
    tag = str(state.get("tag") or "")
    links = [dict(link) for link in state.get("parents") or []]
    tables = [
        str(state.get("table") or ""),
        *[str(table or "") for table in state.get("extra_tables") or []],
        *[str(link.get("table") or "") for link in links],
    ]
    related = [
        str(row.get("table") or "") for row in state.get("extra_rows") or []
    ]
    if case_id:
        targets = get_runtime().store.write_targets(case_id)
        known = {str(target.get("table") or "") for target in targets}
        added = [
            {"table": table, "mode": "delete"}
            for table in dict.fromkeys([*tables, *related])
            if table and table not in known
        ]
        register = getattr(kernel, "set_write_targets", None)
        if added and callable(register):
            # A cleanup may have to remove a row the application created in
            # another table; register those tables for the same case.
            register(targets + added)
    for row in state.get("extra_rows") or []:
        # A parent row created by the request carries no tag of its own; it is
        # identified by the insert id the probe reported for its statement.
        table = str(row.get("table") or "")
        try:
            schema = await kernel.call("db_schema", {"table": table})
        except ToolCallError:
            continue
        found = schema.get("tables") or []
        keys = (found[0].get("primary_key") if found else []) or []
        if not keys:
            continue
        try:
            await kernel.call(
                "db_write",
                {
                    "sql": (
                        f"DELETE FROM `{table}` WHERE `{keys[0]}` = "
                        f"{int(row.get('id') or 0)}"
                    ),
                    "case_id": case_id,
                    "allow_multi": True,
                },
            )
        except ToolCallError:
            continue
    snapshots = dict(state.get("snapshots") or {})
    table = str(state.get("table") or "")
    if table in snapshots:
        # The snapshot turns the tag lookup into an indexed key range: only the
        # rows created after the request are examined at all.
        residue = await cleanup_new_rows(
            kernel, case_id=case_id, snapshots=snapshots, tag=tag
        )
    else:
        columns = [str(column) for column in state.get("columns") or [] if str(column)]
        if not columns and state.get("column"):
            columns = [str(state["column"])]
        residue = await cleanup_tagged_rows(
            kernel,
            case_id=case_id,
            table=table,
            columns=columns,
            tag=tag,
        )
    snapshot = {
        str(table): int(value)
        for table, value in (state.get("parent_max") or {}).items()
    }
    await remove_orphan_parents(
        kernel, case_id=case_id, links=links, snapshot=snapshot
    )
    return residue

#: Verification attempts on the read page: bounded exploration, not one shot.
VERIFY_ATTEMPTS = attempt_limit("verify", 4)
WRITE_ATTEMPTS = attempt_limit("write", 2)
_TAG_RE = re.compile(r"<tia-([a-z0-9]{4})>")
_POST_VAR_RE = re.compile(r"\$_POST\[\s*[\'\"]([A-Za-z_][\w]*)[\'\"]\s*\]")


@dataclass
class InjectResult:
    case_id: str
    verdict: str
    stages: list[StageRecord] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    residue: int = 0
    report: str = ""
    trace: list[Any] = field(default_factory=list)


@dataclass
class _Form:
    action: str
    method: str
    fields: dict[str, str]
    files: list[str] = field(default_factory=list)


def _tag() -> str:
    """4-char lowercase alphanumeric: serves as evidence and passes common length limits."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(4))


def _walk(document: Document) -> list[Any]:
    return list(document.nodes)


def _forms(document: Document, page_url: str) -> list[_Form]:
    """Page forms via the shared parser, preserving the inject agent's dict view."""
    return [
        _Form(
            action=form.action,
            method=form.method,
            fields={field.name: field.value for field in form.fields},
            files=list(form.files),
        )
        for form in forms_from_document(document, page_url)
    ]


_INSERT_RE = re.compile(
    r"insert\s+(?:ignore\s+)?into\s+([`\"]?)([A-Za-z_][\w]*)\1\s*\(([^)]*)\)", re.I
)


_ASSIGN_RE = re.compile(r"^\s*\$(\w+)\s*=")
_POST_READ_RE = re.compile(r"\$_POST\[\s*[\'\"](\w+)[\'\"]\s*\]")
_BIND_RE = re.compile(r"bind(?:Param|Value)\(\s*[\'\"]:(\w+)[\'\"]\s*,\s*\$(\w+)")


def _column_params(text: str) -> dict[str, str]:
    """Map INSERT column -> POST parameter via assignments and bindParam calls.

    Assignments are matched per line so that direct reads and guard forms such as
    ``$user = isset($_POST['name']) ? $_POST['name'] : ''`` both resolve.
    """
    variables: dict[str, str] = {}
    for line in text.splitlines():
        assigned = _ASSIGN_RE.match(line)
        if assigned is None:
            continue
        reads = _POST_READ_RE.findall(line)
        if reads:
            variables[assigned.group(1)] = reads[0]
    mapping: dict[str, str] = {}
    for column, variable in _BIND_RE.findall(text):
        if variable in variables:
            mapping[column] = variables[variable]
    return mapping


def _insert_line(lines: list[dict[str, Any]]) -> int | None:
    """Absolute line number of the INSERT statement inside a source window."""
    for item in lines:
        if _INSERT_RE.search(str(item.get("text", ""))):
            number = item.get("n")
            if isinstance(number, int):
                return number
    return None


_INSERT_TABLE_RE = re.compile(
    r"INSERT\s+INTO\s+[`'\"]?([A-Za-z_][\w]*)", re.IGNORECASE
)


def _insert_tables(lines: list[dict[str, Any]], limit: int = 4) -> list[str]:
    """Tables the source window inserts into (a request may write several)."""
    found: list[str] = []
    for item in lines:
        for name in _INSERT_TABLE_RE.findall(str(item.get("text", ""))):
            if name not in found:
                found.append(name)
        if len(found) >= limit:
            break
    return found


def _insert_lines(lines: list[dict[str, Any]], limit: int = 4) -> list[int]:
    """Every INSERT statement line in the window (a request may write several tables)."""
    found: list[int] = []
    for item in lines:
        if _INSERT_RE.search(str(item.get("text", ""))):
            number = item.get("n")
            if isinstance(number, int) and number not in found:
                found.append(number)
        if len(found) >= limit:
            break
    return found


def _infer_target(source_text: str, sink_code: str, params: list[str]) -> dict[str, Any] | None:
    """Infer INSERT target table and columns from source; return None if unavailable."""
    insert = _INSERT_RE.search(source_text)
    if insert is None:
        return None
    table = insert.group(2)
    columns = [c.strip().strip("`\"") for c in insert.group(3).split(",") if c.strip()]
    bind = re.search(r'bind(?:Param|Value)\(\s*[\'"]:([A-Za-z_][\w]*)[\'"]', sink_code)
    column = bind.group(1) if bind else (params[0] if params else columns[-1] if columns else "")
    if column not in columns:
        # If colon name and column name do not match exactly, retry by parameter name
        candidate = params[0] if params and params[0] in columns else ""
        column = candidate or (columns[0] if columns else "")
    return {"table": table, "columns": columns, "column": column}


def _best_pair_hint(pair_hints: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Highest-confidence read/write hint that names a table."""
    for hint in pair_hints or []:
        if hint.get("table"):
            return hint
    return None


def _column_type(table: dict[str, Any], column: str) -> str:
    for item in table.get("columns") or []:
        if str(item.get("name")) == column:
            return str(item.get("type") or "")
    return ""


async def _count_tagged_rows(kernel: Any, table: str, tag: str, *, max_columns: int = 8) -> int:
    """Count rows of ``table`` whose text columns already carry the tag.

    The application, not the agent, decides which statement and which columns a
    form writes; this looks at the stored data instead of the statement.
    """

    schema = await kernel.call("db_schema", {"table": table})
    tables = schema.get("tables") or []
    if not tables:
        return 0
    columns = [
        str(item.get("name"))
        for item in tables[0].get("columns") or []
        if "char" in _column_type(tables[0], str(item.get("name")))
        or "text" in _column_type(tables[0], str(item.get("name")))
    ][:max_columns]
    if not columns:
        return 0
    where = " OR ".join(f"`{name}` LIKE '%{tag}%'" for name in columns)
    found = await kernel.call("db_read", {"sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE {where}"})
    rows = found.get("rows") or []
    try:
        return int((rows[0] or {}).get("n") or 0)
    except (TypeError, ValueError):
        return 0


async def _run_inject(
    raw_slice: dict[str, Any],
    base_url: str,
    payload_base: str = DEFAULT_PAYLOAD,
    budget: int = 40,
    client: ToolClient | None = None,
    cleanup: bool = True,
    pair_hints: list[dict[str, Any]] | None = None,
    verify_url: str | None = None,
    verify_entry: dict[str, Any] | None = None,
    verify_values: dict[str, str] | None = None,
    payload_constraints: dict[str, Any] | None = None,
    slice_id: str | None = None,
    learning: dict[str, Any] | None = None,
    read_target: dict[str, Any] | None = None,
    constraint_plan: dict[str, Any] | None = None,
    pair_candidates: dict[str, list[dict[str, Any]]] | None = None,
    flow: dict[str, Any] | None = None,
) -> InjectResult:
    kernel = Kernel(
        profile="inject", budget=budget, client=client or LocalToolClient(profile="inject")
    )
    kernel.slice_id = slice_id
    result = InjectResult(case_id="", verdict="ENV_ERROR")
    stages = result.stages
    notes = result.notes
    if flow:
        notes["flow_id"] = str(flow.get("flow_id") or "")
        notes["flow_class"] = str(flow.get("sink_class") or "")

    def stage(name: str, ok: bool, note: str) -> None:
        stages.append(StageRecord(stage=name, ok=ok, note=note))

    sink = str(raw_slice.get("sink") or raw_slice.get("sinkCode") or "")
    sink_file = str(raw_slice.get("sinkFile") or (sink.split(":", 1)[0] if ":" in sink else ""))
    line_match = re.search(r":(\d+)", sink)
    sink_line = int(line_match.group(1)) if line_match else int(raw_slice.get("sinkLine") or 0)
    notes["sink_file"] = sink_file
    read_file = str((read_target or {}).get("file") or "")
    read_line = int((read_target or {}).get("line") or 0)
    if read_file or read_line:
        notes["read_target"] = {"file": read_file, "line": read_line}
    params = [str(p) for p in raw_slice.get("params") or []]
    if not params:
        for source in raw_slice.get("sources") or []:
            if source.get("param"):
                params.append(str(source["param"]))
    tag = _tag()
    notes.update({"tag": tag, "sink": f"{sink_file}:{sink_line}"})

    async def call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        data = await kernel.call(tool, arguments)
        return data if isinstance(data, dict) else {}

    # ---- I0 Baseline: page does not contain new tag, and no residue in DB ----
    try:
        case = await call(
            "case_open",
            {
                "agent": "inject",
                "slice": {"sink": f"{sink_file}:{sink_line}  {sink}", "kind": raw_slice.get("kind", "SQL")},
                "write_targets": [],
            },
        )
    except ToolCallError as exc:
        stage("I0", False, f"case_open failed: {exc}")
        result.verdict = "ENV_ERROR"
        return result
    result.case_id = str(case.get("case_id", ""))
    kernel.case_id = result.case_id
    baseline = await call("verify_tag", {"url": base_url, "tag": tag})
    if baseline.get("found"):
        stage("I0", False, "BASELINE_DIRTY: tag already exists on page")
        result.verdict = "BASELINE_DIRTY"
        return await _finish(kernel, result, cleanup=False)
    stage("I0", True, f"baseline clean tag={tag}")

    # ---- I1 Write path symbolic: find INSERT target in source ----
    try:
        source = await call(
            "source_read",
            {"file": sink_file, "line_from": max(1, sink_line - 40), "line_to": sink_line + 10},
        )
    except ToolCallError as exc:
        stage("I1", False, f"source_read failed: {exc}")
        result.verdict = "PATH_UNREACHABLE"
        return await _finish(kernel, result)
    text = "\n".join(str(item.get("text", "")) for item in source.get("lines") or [])
    if not params:
        # The trigger slice carries no source parameters; recover POST fields from the write path itself.
        params = sorted(set(_POST_VAR_RE.findall(text)))
        notes["params_from_source"] = params
    target = _infer_target(text, str(raw_slice.get("sinkCode") or sink), params)
    hint = _best_pair_hint(pair_hints)
    inferred_table = str((target or {}).get("table") or "")
    if hint is not None:
        # The pairing prior names the storage the read path renders; the write
        # path only has to be a form the application accepts. Prefer the read
        # side's table/columns over whatever INSERT the source window shows first.
        hint_columns = [str(item) for item in hint.get("columns") or []]
        column = hint_columns[0] if hint_columns else str((target or {}).get("column") or "")
        target = {
            "table": str(hint["table"]),
            "columns": hint_columns or ([column] if column else []),
            "column": column,
            "source": "pair_hint",
        }
        notes["pair"] = {
            "pair_id": hint.get("pair_id"),
            "confidence": hint.get("confidence"),
            "side": hint.get("side"),
            "table": hint.get("table"),
            "columns": hint_columns,
        }
    if target is None:
        stage("I1", False, "INSERT target table not found")
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)
    notes["target"] = target
    insert_line: int | None = None
    if hint is None or inferred_table == str(target["table"]):
        insert_line = _insert_line([item for item in source.get("lines") or [] if isinstance(item, dict)])
        if insert_line is not None:
            target["line"] = insert_line
    kernel.set_write_targets([{"table": target["table"], "column": target["column"], "mode": "delete"}])
    stage(
        "I1",
        True,
        f"target={target['table']}.{target['column']} columns={target['columns']} line={insert_line}",
    )

    # ---- I2 Entry reconstruction: fetch page to find form ----
    try:
        page = await call("http_request", {"method": "GET", "url": base_url})
    except ToolCallError as exc:
        stage("I2", False, f"GET failed: {exc}")
        result.verdict = "ENV_ERROR"
        return await _finish(kernel, result)
    if int(page.get("status", 0)) >= 400:
        stage("I2", False, f"entry HTTP {page.get('status')}")
        result.verdict = "PATH_UNREACHABLE"
        return await _finish(kernel, result)
    document = parse(str(page.get("body") or ""))
    forms = [f for f in _forms(document, base_url) if f.method == "post"]
    if not forms:
        stage("I2", False, "No POST form on page")
        result.verdict = "NO_HTTP_ENTRY"
        return await _finish(kernel, result)
    column_params = _column_params(text)
    notes["column_params"] = column_params
    candidates = [
        parameter
        for column, parameter in column_params.items()
        if any(parameter in form.fields for form in forms)
    ] or [name for name in params if any(name in form.fields for form in forms)]
    if not candidates:
        stage("I2", False, f"form fields {sorted(set().union(*[set(f.fields) for f in forms]))} do not match params {params}")
        result.verdict = "ENTRY_AMBIGUOUS"
        return await _finish(kernel, result)
    notes["candidates"] = candidates
    stage("I2", True, f"forms={len(forms)} candidate fields={candidates}")

    # ---- I3 Length budget: pick the widest writable column that fits the payload ----
    schema = await call("db_schema", {"table": target["table"]})
    widths: dict[str, int | None] = {}
    column_limits: dict[str, str] = {}
    pk_columns: list[str] = []
    for table_item in schema.get("tables") or []:
        if table_item.get("name") == target["table"]:
            pk_columns = [str(item) for item in table_item.get("primary_key") or []]
            for column in table_item.get("columns") or []:
                widths[str(column.get("name"))] = column.get("length")
                column_limits[str(column.get("name"))] = (
                    f"{column.get('type') or 'text'}({column.get('length') or '?'})"
                )
    constraints = dict(payload_constraints or {})
    sink_class = sink_class_for(str(raw_slice.get("kind") or "Xss"))
    learned_shape = preferred_payload_shape(learning, constraints.get("context_kind"))
    if learned_shape:
        payload = sink_class.render(learned_shape, tag)
        notes["payload_shape"] = learned_shape
        stage("I3", True, f"learned payload shape {learned_shape} for this site")
    else:
        payload = f"{payload_base}{tag}"
    if constraints:
        notes["payload_constraints"] = constraints
        max_length = constraints.get("max_length")
        overhead = len(tag)
        if isinstance(max_length, int) and max_length > overhead and len(payload) > max_length:
            keep = max_length - overhead
            trimmed = payload_base[:keep]
            payload = f"{trimmed}{tag}"
            notes["payload_trimmed"] = {"max_length": max_length, "base_chars": len(trimmed)}
            stage("I3", True, f"payload trimmed to {len(payload)} chars for column limit {max_length}")
    fitting: list[tuple[int, str, str]] = []
    param_columns = {parameter: column for column, parameter in column_params.items()}
    for candidate in candidates:
        column = param_columns.get(candidate) or (
            candidate if candidate in target["columns"] else target["column"]
        )
        width = widths.get(column)
        if width is None or len(payload) <= int(width):
            fitting.append((int(width or 0), candidate, column))
    if not fitting:
        stage("I3", False, f"payload {len(payload)} exceeds every candidate column: {widths}")
        result.verdict = "LENGTH_EXCEEDED"
        return await _finish(kernel, result)
    _, field_name, chosen_column = max(fitting)
    form = next(f for f in forms if field_name in f.fields)
    target["column"] = chosen_column
    notes["entry"] = {"url": form.action, "method": form.method, "field": field_name, "fields": form.fields}
    notes["payload"] = payload
    links = parent_links(str(target.get("table") or ""))
    parent_max = {
        str(link["table"]): await max_key(kernel, str(link["table"]), str(link["parent_column"]))
        for link in links
    }
    write_tables = [str(target.get("table") or "")]
    write_tables += [str(link.get("table") or "") for link in links]
    write_tables += _insert_tables(
        [item for item in source.get("lines") or [] if isinstance(item, dict)]
    )
    snapshots = await key_snapshot(kernel, write_tables)
    state: dict[str, Any] = {
        "kernel": kernel,
        "case_id": result.case_id,
        "table": str(target.get("table") or ""),
        "column": chosen_column,
        "tag": tag,
        "pending": False,
        "parents": links,
        "parent_max": parent_max,
        "snapshots": snapshots,
    }
    _ACTIVE_CLEANUP.set(state)
    notes["_cleanup_needed"] = True
    stage("I3", True, f"payload {len(payload)} chars, column {chosen_column} width={widths.get(chosen_column)}")
    stage("I4", True, f"intersect: field={field_name}, column={chosen_column}, payload {len(payload)} chars")

    # ---- I4/I5 delivery: use the application's own form ----
    # The model plans the request; local code only fills a page every field
    # blank and validates the plan. Execution (probe/verify) decides if it worked.
    fallback = {name: (value or "tia") for name, value in form.fields.items()}
    fallback[field_name] = payload
    plan_forms = [
        PageForm(
            action=item.action,
            method=item.method,
            fields=[
                FormField(name=name, type="text", value=value)
                for name, value in item.fields.items()
            ],
            files=list(item.files),
        )
        for item in forms
    ]
    def _diagnose(html: str, status: Any, probe_hit: bool) -> str:
        parts = [f"HTTP {status}"]
        if not probe_hit:
            parts.append(
                "no SQL matched the armed target lines, so the request did not reach the sink"
            )
        if html:
            lowered = html.lower()
            for keyword in (
                "error",
                "fatal",
                "warning",
                "invalid",
                "required",
                "not found",
                "can not use both",
            ):
                position = lowered.find(keyword)
                if position >= 0:
                    snippet = " ".join(html[max(0, position - 60): position + 140].split())
                    parts.append(f"page text near {keyword!r}: {snippet}")
                    break
            if tag not in html:
                parts.append("the case tag does not appear in the response")
        return "; ".join(parts)

    observation = ""
    submitted: dict[str, Any] = {}
    armed = False
    arm_targets: list[dict[str, Any]] = []
    # A single request can insert into several tables (a parent row plus the row
    # that stores the payload), so arm every INSERT in the window, not just the
    # first one, plus the read site when it lives in another file.
    window = [item for item in source.get("lines") or [] if isinstance(item, dict)]
    for number in _insert_lines(window):
        arm_targets.append({"file": sink_file, "line": number})
    if read_file and read_line and (read_file, read_line) not in {
        (sink_file, number) for number in _insert_lines(window)
    }:
        arm_targets.append({"file": read_file, "line": read_line})
    async def _send(
        method: str, values: dict[str, str], files: dict[str, str], account: str = ""
    ) -> dict[str, Any]:
        body = urlencode(values)
        if armed:
            page = await call(
                "probe_run",
                {
                    "case_id": result.case_id,
                    "url": form.action,
                    "method": method,
                    "body": body,
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "capture_html": True,
                    "files": files,
                    "account_label": account,
                },
            )
            http = page.get("http") or {}
            queries = page.get("queries") or []
            hit = any(int(query.get("affected_rows") or 0) > 0 for query in queries)
            return {
                "status": http.get("status"),
                "body": str(http.get("html") or ""),
                "content_type": str(http.get("content_type") or "text/html"),
                "probe_hit": hit,
                "raw": page,
            }
        page = await call(
            "http_request",
            {
                "method": method,
                "url": form.action,
                "body": body,
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "files": files,
                "account_label": account,
            },
        )
        return {
            "status": page.get("status"),
            "body": str(page.get("body") or ""),
            "content_type": str(page.get("content_type") or "text/html"),
            "probe_hit": False,
            "raw": page,
        }

    async def _accept(attempt: DeliveryAttempt, page: dict[str, Any]) -> bool:
        attempt.extra["raw"] = page.get("raw") or {}
        status = int(attempt.status or 0)
        return status < 400 and (not armed or attempt.probe_hit)

    if arm_targets:
        try:
            await call(
                "probe_arm",
                {
                    "case_id": result.case_id,
                    "targets": arm_targets,
                    "output": f"inject-{tag}.json",
                },
            )
            armed = True
        except ToolCallError as exc:
            notes["probe_error"] = str(exc.envelope.error.message if exc.envelope.error else exc)
    delivery = await deliver(
        client=LlmClient.from_env(),
        goal=(
            "submit this form so the application stores the payload as a record of "
            f"{target['table']} (creating a new row is expected); the application's "
            "own write path decides the columns, the payload only has to end up in "
            "the column the read path renders"
        ),
        page_url=base_url,
        forms=plan_forms,
        html=str(notes.get("page_html") or ""),
        source_text=text,
        tag=tag,
        payload=payload,
        hint=(
            f"send the payload through parameter {field_name}; a new record is the "
            "normal outcome, do not try to reproduce a specific SQL statement"
        ),
        constraints=", ".join(f"{name}: {kind}" for name, kind in column_limits.items()),
        fallback_fields=fallback,
        observation="\n".join(kernel.tool_errors[-3:]),
        max_rounds=WRITE_ATTEMPTS,
        send=_send,
        accept=_accept,
        accounts=public_catalog(get_runtime().settings.accounts_path),
    )
    notes["write_attempts"] = [item.to_dict() for item in delivery.attempts]
    if delivery.plan is not None:
        notes["request_plan"] = delivery.plan.to_dict()
        if delivery.plan.warnings:
            notes["request_plan_warnings"] = delivery.plan.warnings
        if delivery.plan.payload:
            payload = delivery.plan.payload
            notes["payload"] = payload
        if delivery.plan.column and delivery.plan.column in widths:
            width = widths.get(delivery.plan.column)
            if width is None or len(payload) <= int(width):
                chosen_column = delivery.plan.column
                target["column"] = chosen_column
                notes["column_chosen_by"] = "llm"
            else:
                notes["column_rejected"] = (
                    f"{delivery.plan.column} holds {width} chars, payload needs {len(payload)}"
                )
        notes["entry"] = {
            "url": delivery.plan.url or form.action,
            "method": delivery.plan.method.lower(),
            "field": delivery.plan.payload_field or field_name,
            "fields": dict(form.fields),
            "planned_by": delivery.plan.source,
        }
    probed = armed and delivery.last is not None and bool(delivery.last.probe_hit)
    stored = 0
    if delivery.last is not None and int(delivery.last.status or 0) < 400 and not probed:
        # The application may write a different statement than the modelled one
        # (or a new row); look for the tag in the stored data instead.
        try:
            stored = await _count_tagged_rows(kernel, str(target["table"]), tag)
        except ToolCallError:
            stored = 0
    accepted = (
        delivery.last is not None
        and int(delivery.last.status or 0) < 400
        and (not armed or probed or stored > 0)
    )
    notes["write_signal"] = (
        "probe" if probed else ("db_read" if stored > 0 else ("status" if not armed else "none"))
    )
    submitted = dict((delivery.last.extra.get("raw") if delivery.last else {}) or {})
    if delivery.last is not None and not submitted:
        submitted = {"http": {"status": delivery.last.status, "html": delivery.last.html}}
    if not accepted:
        if armed:
            with contextlib.suppress(ToolCallError):
                await call("probe_disarm", {"case_id": result.case_id})
        stage("I5", False, "POST never reached the sink")
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)
    if armed:
        with contextlib.suppress(ToolCallError):
            await call("probe_disarm", {"case_id": result.case_id})
    state["pending"] = True
    state["column"] = str(target.get("column") or chosen_column)
    state["columns"] = [str(c) for c in target.get("columns") or [] if str(c)]
    extra_tables: list[str] = []
    extra_rows: list[dict[str, Any]] = []
    for query in submitted.get("queries") or []:
        write = query.get("write") or {}
        table = str(write.get("table") or "")
        if not table or table == str(target["table"]):
            continue
        if table not in extra_tables:
            extra_tables.append(table)
        insert_id = query.get("last_insert_id")
        if insert_id:
            extra_rows.append({"table": table, "id": insert_id})
    state["extra_tables"] = extra_tables
    state["extra_rows"] = extra_rows
    status = submitted.get("http", {}).get("status") if armed else submitted.get("status")
    stage("I5", True, f"POST {form.action} → {status} probe={armed}")
    if armed and (submitted.get("queries") or []):
        query = (submitted.get("queries") or [{}])[0]
        notes["probe"] = {
            "mode": submitted.get("mode"),
            "targets": submitted.get("targets"),
            "by_target": submitted.get("by_target"),
            "sql": query.get("sql"),
            "bindings": query.get("bindings"),
            "affected_rows": query.get("affected_rows"),
            "last_insert_id": query.get("last_insert_id"),
            "matched_at": query.get("matched_at"),
        }
    if int(status or 0) >= 400:
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)

    # ---- I5.5 database constraints: replay the branch conditions trigger found ----
    constraint_steps = notes.setdefault("constraint_steps", [])
    for constraint in (constraint_plan or {}).get("constraints") or []:
        constraint_id = str(constraint.get("constraint_id") or "")
        c_table = str(constraint.get("table") or "")
        c_column = str(constraint.get("column") or "")
        c_value = str(constraint.get("value") or "")
        pair_opts = (pair_candidates or {}).get(constraint_id) or []
        chosen = pair_opts[0] if pair_opts else None
        step: dict[str, Any] = {
            "constraint_id": constraint_id,
            "table": c_table,
            "column": c_column,
            "value": c_value,
            "predicate": constraint.get("predicate"),
        }
        if chosen is None:
            step["error"] = "no injection slice can rewrite this condition"
            constraint_steps.append(step)
            stage("I5.5", False, f"CONSTRAINT_UNSATISFIED {c_table}.{c_column}")
            result.verdict = "CONSTRAINT_UNSATISFIED"
            return await _finish(kernel, result)
        other = get_runtime().store.get_slice(str(chosen.get("write_slice_id") or ""))
        if other is None:
            step["error"] = "the paired write slice disappeared"
            constraint_steps.append(step)
            stage("I5.5", False, "CONSTRAINT_REPLAY_FAILED missing slice")
            result.verdict = "CONSTRAINT_REPLAY_FAILED"
            return await _finish(kernel, result)
        other_raw = dict(other["slice"])
        c_file = str(other_raw.get("sinkFile") or "")
        c_line = int(other_raw.get("sinkLine") or 0)
        step["write_slice_id"] = str(chosen.get("write_slice_id"))
        step["page_url"] = str(chosen.get("page_url") or base_url)
        try:
            constraint_window = await call(
                "source_read", {"file": c_file, "around": {"line": c_line, "n": 40}}
            )
            c_text = "\n".join(item["text"] for item in constraint_window.get("lines") or [])
        except ToolCallError as exc:
            step["error"] = f"source_read failed: {exc}"
            constraint_steps.append(step)
            stage("I5.5", False, f"CONSTRAINT_REPLAY_FAILED {c_table}.{c_column}")
            result.verdict = "CONSTRAINT_REPLAY_FAILED"
            return await _finish(kernel, result)
        col_params = _column_params(c_text)
        step["parameter"] = col_params.get(c_column) or c_column
        try:
            constraint_page = await call("http_request", {"method": "GET", "url": str(step["page_url"])})
            c_forms = forms_from_document(
                parse(str(constraint_page.get("body") or "")), str(step["page_url"])
            )
        except ToolCallError as exc:
            c_forms = []
            step["page_error"] = str(exc)
        c_form = find_form(c_forms, str(step["parameter"]), method="post")
        if c_form is None and c_forms:
            c_form = c_forms[0]
        if c_form is None:
            step["error"] = "no form on the paired write page"
            constraint_steps.append(step)
            stage("I5.5", False, f"CONSTRAINT_REPLAY_FAILED {c_table}.{c_column}")
            result.verdict = "CONSTRAINT_REPLAY_FAILED"
            return await _finish(kernel, result)
        replay_values = {
            item.name: str(item.value or "tia")
            for item in c_form.fields
            if item.type not in {"submit", "button", "checkbox", "radio"}
        }
        replay_values[str(step["parameter"])] = c_value
        step["values"] = dict(replay_values)
        armed_now = False
        try:
            await call(
                "probe_arm",
                {
                    "case_id": result.case_id,
                    "targets": [{"file": c_file, "line": c_line}],
                    "output": f"constraint-{tag}-{constraint_id}.json",
                },
            )
            armed_now = True
        except ToolCallError:
            armed_now = False
        try:
            replay = await call(
                "probe_run" if armed_now else "http_request",
                {
                    "case_id": result.case_id,
                    "url": c_form.action,
                    "method": "POST",
                    "body": urlencode(replay_values),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "capture_html": True,
                },
            )
        except ToolCallError as exc:
            replay = {}
            step["error"] = f"replay failed: {exc}"
        finally:
            if armed_now:
                with contextlib.suppress(ToolCallError):
                    await call("probe_disarm", {"case_id": result.case_id})
        replay_queries = replay.get("queries") or []
        step["affected"] = sum(int(q.get("affected_rows") or 0) for q in replay_queries)
        step["probe_hit"] = step["affected"] > 0
        payload_column = str(target.get("column") or "")
        value_ok = False
        if payload_column:
            with contextlib.suppress(ToolCallError):
                check = await call(
                    "db_read",
                    {
                        "sql": (
                            f"SELECT `{c_column}` AS v FROM `{c_table}` "
                            f"WHERE `{payload_column}` LIKE '%{tag}%' LIMIT 1"
                        )
                    },
                )
                rows_check = check.get("rows") or []
                if rows_check:
                    step["observed"] = rows_check[0].get("v")
                    value_ok = str(rows_check[0].get("v")) == c_value
        step["confirmed"] = value_ok
        constraint_steps.append(step)
        if not (step.get("probe_hit") or value_ok):
            stage("I5.5", False, f"CONSTRAINT_REPLAY_FAILED {c_table}.{c_column}")
            result.verdict = "CONSTRAINT_REPLAY_FAILED"
            return await _finish(kernel, result)
        stage("I5.5", True, f"{c_table}.{c_column} = {c_value}")

    # ---- I6 tri-state acceptance: in DB / on page / executable ----
    table = target["table"]
    column = target["column"]
    probe = await call(
        "db_read",
        {
            "sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE `{column}` LIKE '%{tag}%'",
        },
    )
    rows = probe.get("rows") or []
    in_db = bool(rows and int(rows[0].get("n") or 0) > 0)
    notes["tag_in_db"] = in_db
    stage("I6", in_db, f"tag_in_db={in_db}")

    # The read-side sink class decides the acceptance channel.  A SQL injection
    # read page proves itself through the database probe, not through markup.
    flow_class = str((flow or {}).get("sink_class") or "")
    read_class = sink_class_for(flow_class or str(raw_slice.get("kind") or "Xss"))
    read_channel = read_class.observation_channel()
    sql_outcome = None
    verify: dict[str, Any] | None = None
    if read_channel == "sql_probe" and verify_url:
        sql_entry = verify_entry or {}
        sql_method = str(sql_entry.get("method") or "POST").upper()
        sql_fields = [
            str(item.get("name"))
            for item in sql_entry.get("fields") or []
            if isinstance(item, dict) and item.get("name")
        ]
        seeds: list[dict[str, str]] = []
        if verify_values:
            seed: dict[str, str] = {}
            for name, value in verify_values.items():
                token = str(value or "")
                seed[str(name)] = tag if (len(token) == 4 and token.isalnum()) else token
            if seed:
                seeds.append(seed)
        for name in sql_fields:
            single = {name: tag}
            if single not in seeds:
                seeds.append(single)
        if sql_fields:
            combined = {name: tag for name in sql_fields}
            if combined not in seeds:
                seeds.append(combined)
        sql_attempts: list[dict[str, Any]] = []
        read_armed = False
        if read_file and read_line:
            with contextlib.suppress(ToolCallError):
                await call(
                    "probe_arm",
                    {
                        "case_id": result.case_id,
                        "targets": [{"file": read_file, "line": read_line}],
                        "output": f"inject-sqlread-{tag}.json",
                    },
                )
                read_armed = True
        try:
            for values in seeds[:VERIFY_ATTEMPTS]:
                arguments: dict[str, Any] = {
                    "case_id": result.case_id,
                    "url": verify_url,
                    "method": sql_method,
                }
                if sql_method == "POST":
                    arguments["body"] = urlencode(values)
                    arguments["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
                else:
                    arguments["params"] = values
                try:
                    run = await call("probe_run", arguments)
                except ToolCallError as exc:
                    sql_attempts.append({"values": values, "error": exc.code.value})
                    continue
                queries = run.get("queries") or []
                statements = [
                    str(item.get("sql") or "") for item in queries if isinstance(item, dict)
                ]
                marker_seen = any(tag in statement for statement in statements)
                sql_observation = Observation(
                    channel="sql_probe",
                    request={"url": verify_url, "method": sql_method, "values": values},
                    payload=tag,
                    marker_seen=marker_seen,
                    facts={
                        "sql_probe": {
                            "executed": bool(queries),
                            "error": str(run.get("error") or ""),
                            "statements": statements[:3],
                        }
                    },
                )
                outcome = read_class.accept(sql_observation, "sql_probe")
                sql_outcome = outcome
                sql_attempts.append(
                    {
                        "values": values,
                        "marker_seen": marker_seen,
                        "executed": bool(queries),
                        "level": outcome.level,
                        "statements": statements[:2],
                    }
                )
                if outcome.confirmed:
                    break
        finally:
            if read_armed:
                with contextlib.suppress(ToolCallError):
                    await call("probe_disarm", {"case_id": result.case_id})
        notes["verify_attempts"] = sql_attempts
        notes["verify_on"] = "sql_probe"
        if sql_outcome is not None:
            notes["sql_probe_verdict"] = sql_outcome.level
        sql_confirmed = bool(sql_outcome is not None and sql_outcome.confirmed)
        verify = {
            "found": sql_confirmed,
            "best": {"executable": sql_confirmed, "context_kind": "sql_probe"},
            "channel": "sql_probe",
        }
        stage("I6", sql_confirmed, f"sql_probe attempts={len(sql_attempts)}")

    # Second-order XSS: the write entry and the read page differ. Fetch the read
    # page with its own entry parameters before classifying the tag context.
    verify_content_type = "text/html"
    submitted_http = submitted.get("http") or {}
    same_page_html = str(submitted_http.get("html") or "")
    same_page_is_sink = not verify_url or verify_url == form.action
    if read_channel != "sql_probe" and same_page_is_sink and same_page_html and tag in same_page_html:
        # The write page already rendered the tag: one arm, one request covered both
        # the write target and the read target.
        verify = await call(
            "verify_tag",
            {
                "tag": tag,
                "payload": payload,
                "html": same_page_html,
                "content_type": str(submitted_http.get("content_type") or "text/html"),
            },
        )
        notes["verify_on"] = "probe_page"
        notes["verify_attempts"] = [{"values": dict(delivery.plan.values) if delivery.plan else {}, "source": "probe_page",
                                     "found": bool(verify.get("found"))}]
    elif read_channel != "sql_probe" and verify_url and verify_url != form.action and verify_entry:
        entry_method = str(verify_entry.get("method") or "POST").upper()
        entry_spec = [entry_field(item) for item in verify_entry.get("fields") or []]
        read_forms: list[PageForm] = []
        read_html = ""
        try:
            read_page = await call("http_request", {"method": "GET", "url": verify_url})
            read_html = str(read_page.get("body") or "")
            read_forms = forms_from_document(parse(read_html), verify_url)
            notes["read_forms"] = [
                {"action": form.action, "method": form.method, "fields": sorted(field.name for field in form.fields)}
                for form in read_forms
            ]
        except ToolCallError as exc:
            notes["read_page_error"] = str(
                exc.envelope.error.message if exc.envelope.error else exc
            )
        written_row: dict[str, Any] | None = None
        try:
            row_hit = await call(
                "db_read",
                {
                    "sql": (
                        f"SELECT * FROM `{table}` WHERE `{column}` LIKE '%{tag}%' LIMIT 1"
                    )
                },
            )
            rows_found = row_hit.get("rows") or []
            written_row = rows_found[0] if rows_found else None
        except ToolCallError:
            written_row = None
        entry_fields, entry_basis = await resolve_values_with_guess(
            entry_spec,
            tag=tag,
            row=written_row,
            pk_columns=pk_columns,
            context=text,
            client=LlmClient.from_env(),
        )
        notes["read_entry_basis"] = entry_basis
        plan = EntryPlan(method=entry_method, fields=entry_spec, has_filter=True, mutating=False)
        entry_candidates_list = await entry_candidates(
            plan,
            tag=tag,
            row=written_row,
            pk_columns=pk_columns,
            context=text,
            client=LlmClient.from_env(),
            limit=VERIFY_ATTEMPTS,
        )
        # Local-first: the trigger already proved which read parameters reach the
        # sink. Seed those values, then try single-field and full-form variants
        # before asking the model for anything.
        local_values: list[dict[str, str]] = []
        if verify_values:
            seed_by_name = {spec.name: spec for spec in entry_spec}
            seeded: dict[str, str] = {}
            for name, value in verify_values.items():
                spec = seed_by_name.get(str(name))
                if spec is not None and spec.usage == "contains":
                    seeded[str(name)] = tag
                elif value not in (None, ""):
                    seeded[str(name)] = str(value)
            if seeded:
                local_values.append(seeded)
        for spec in entry_spec:
            single = {spec.name: tag}
            if single not in local_values:
                local_values.append(single)
        combined = {spec.name: tag for spec in entry_spec}
        if combined not in local_values:
            local_values.append(combined)
        for candidate_entry in entry_candidates_list:
            candidate_values = dict(candidate_entry.values)
            if candidate_values and candidate_values not in local_values:
                local_values.append(candidate_values)
        attempt_values = local_values or [entry_fields]
        notes["verify_attempt_candidates"] = [
            {"method": candidate.method, "confidence": candidate.confidence, "values": candidate.values}
            for candidate in entry_candidates_list
        ]
        verify = None
        attempts: list[dict[str, Any]] = []
        read_armed = False
        if read_file and read_line:
            with contextlib.suppress(ToolCallError):
                await call(
                    "probe_arm",
                    {
                        "case_id": result.case_id,
                        "targets": [{"file": read_file, "line": read_line}],
                        "output": f"inject-read-{tag}.json",
                    },
                )
                read_armed = True
        queue: list[dict[str, str]] = [dict(seed) for seed in attempt_values]
        used_plans = 0
        observation = ""
        index = 0
        while index < len(queue) and len(attempts) < VERIFY_ATTEMPTS + 1:
            values = queue[index]
            index += 1
            attempt_html: str | None = None
            try:
                if read_armed:
                    probe_page = await call(
                        "probe_run",
                        {
                            "case_id": result.case_id,
                            "url": verify_url,
                            "method": entry_method,
                            "params": values if entry_method == "GET" else {},
                            "body": urlencode(values) if entry_method == "POST" else None,
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                            "capture_html": True,
                        },
                    )
                    page = probe_page.get("http") or {}
                    attempt_html = str(page.get("html") or "")
                    verify_content_type = str(page.get("content_type") or "text/html")
                    status = page.get("status")
                    notes.setdefault("read_probe", []).append(probe_page.get("by_target"))
                elif entry_method == "GET":
                    page = await call(
                        "http_request", {"method": "GET", "url": verify_url, "params": values}
                    )
                    attempt_html = str(page.get("body") or "")
                    verify_content_type = str(page.get("content_type") or "text/html")
                    status = page.get("status")
                else:
                    page = await call(
                        "http_request",
                        {
                            "method": "POST",
                            "url": verify_url,
                            "body": urlencode(values),
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        },
                    )
                    attempt_html = str(page.get("body") or "")
                    verify_content_type = str(page.get("content_type") or "text/html")
                    status = page.get("status")
            except ToolCallError as exc:
                attempts.append({"values": values, "error": str(exc)})
                observation = str(exc)
                if used_plans < 1:
                    used_plans += 1
                    again = await plan_request(
                        client=LlmClient.from_env(),
                        goal=(
                            "open this page so the row that carries the tag is selected and rendered"
                        ),
                        page_url=verify_url,
                        forms=read_forms
                        or [
                            PageForm(
                                action=verify_url,
                                method=entry_method.lower(),
                                fields=[
                                    FormField(
                                        name=item.name,
                                        type="numeric" if item.numeric else "text",
                                    )
                                    for item in entry_spec
                                ],
                            )
                        ],
                        html=read_html,
                        source_text=str(notes.get("read_sink_code") or text),
                        payload=tag,
                        tag=tag,
                        constraints=", ".join(
                            f"{name}: {kind}" for name, kind in column_limits.items()
                        ),
                        observation=observation,
                        hint="the previous attempt did not render the row; change the request",
                        fallback_fields=queue[0] if queue else {},
                        fallback_method=entry_method,
                    )
                    if again is not None and again.source == "rejected":
                        notes["read_request_plan_rejection"] = again.rejection
                        observation = f"local validator rejected the plan: {again.rejection}"
                    elif again is not None and again.source == "llm" and again.values:
                        notes["read_request_plan"] = again.to_dict()
                        queue.append(dict(again.values))
                continue
            this_verify = await call(
                "verify_tag", {"tag": tag, "payload": payload, "html": attempt_html,
                               "content_type": verify_content_type}
            )
            attempts.append(
                {
                    "values": values,
                    "status": status,
                    "found": bool(this_verify.get("found")),
                    "shape": notes.get("payload_shape"),
                    "executable": bool((this_verify.get("best") or {}).get("executable")),
                    "context_kind": (this_verify.get("best") or {}).get("context_kind"),
                }
            )
            if verify is None or (this_verify.get("found") and not bool(verify.get("found"))):
                verify = this_verify
            if tag and tag in attempt_html:
                snapshot = echo_snapshot(attempt_html, tag)
                if snapshot:
                    notes.setdefault("read_snapshots", []).append(
                        {"values": dict(values), "snapshot": snapshot}
                    )
            if this_verify.get("found"):
                break
            lowered = attempt_html.lower()
            snippet = ""
            for keyword in ("error", "fatal", "warning", "invalid", "required", "not found"):
                position = lowered.find(keyword)
                if position >= 0:
                    snippet = " ".join(
                        attempt_html[max(0, position - 60): position + 140].split()
                    )
                    break
            observation = f"HTTP {status}; the case tag is absent from the response"
            if snippet:
                observation += f"; page text: {snippet}"
            if used_plans < 1 and index >= len(queue):
                used_plans += 1
                again = await plan_request(
                    client=LlmClient.from_env(),
                    goal="open this page so the row that carries the tag is selected and rendered",
                    page_url=verify_url,
                    forms=read_forms
                    or [
                        PageForm(
                            action=verify_url,
                            method=entry_method.lower(),
                            fields=[
                                FormField(
                                    name=item.name,
                                    type="numeric" if item.numeric else "text",
                                )
                                for item in entry_spec
                            ],
                        )
                    ],
                    html=read_html,
                    source_text=str(notes.get("read_sink_code") or text),
                    payload=tag,
                    tag=tag,
                    constraints=", ".join(
                        f"{name}: {kind}" for name, kind in column_limits.items()
                    ),
                    observation=observation,
                    hint="the row was written but this request did not show it",
                    fallback_fields=values,
                    fallback_method=entry_method,
                )
                if again is not None and again.source == "rejected":
                    notes["read_request_plan_rejection"] = again.rejection
                    observation = f"local validator rejected the plan: {again.rejection}"
                elif again is not None and again.source == "llm" and again.values:
                    notes["read_request_plan"] = again.to_dict()
                    queue.append(dict(again.values))
        if read_armed:
            with contextlib.suppress(ToolCallError):
                await call("probe_disarm", {"case_id": result.case_id})
        notes["verify_attempts"] = attempts
        stage("I6", verify is not None, f"read page {verify_url} attempts={len(attempts)}")
        if verify is None:
            verify = await call("verify_tag", {"tag": tag, "payload": payload, "url": verify_url or form.action})
        notes["verify_on"] = "read_page"
    elif read_channel != "sql_probe":
        try:
            verify = await call("verify_tag", {"tag": tag, "payload": payload, "url": form.action})
            notes["verify_on"] = "url"
        except ToolCallError as exc:
            notes["verify_error"] = str(exc)
            verify = None
    found = bool(verify.get("found") if verify else False)
    best = (verify or {}).get("best") or {}
    executable = bool(best.get("executable"))
    notes.update({"tag_in_page": found, "executable": executable, "context_kind": best.get("context_kind")})
    stage("I6", found, f"tag_in_page={found} executable={executable} kind={best.get('context_kind')}")

    if executable and verify is not None and read_channel != "sql_probe":
        try:
            if notes.get("verify_on") == "probe_page":
                page_values = dict(delivery.plan.values) if delivery.plan else {}
                method, target_url, fields = "POST", form.action, page_values
            else:
                attempts = notes.get("verify_attempts") or []
                last = attempts[-1] if attempts else {}
                method = str((verify_entry or {}).get("method") or "POST").upper()
                target_url = verify_url or form.action
                fields = dict(last.get("values") or {})
            confirmed = await call(
                "verify_tag",
                {
                    "url": target_url,
                    "tag": tag,
                    "payload": payload,
                    "execute": True,
                    "execute_method": method,
                    "execute_fields": fields,
                },
            )
            execution = confirmed.get("execution")
            if isinstance(verify, dict):
                verify["execution"] = execution
            notes["execution"] = execution
        except ToolCallError:
            notes["execution"] = None

    if sql_outcome is not None:
        outcome = sql_outcome
    else:
        outcome = sink_class.accept(
            Observation(
                channel="inject",
                marker_seen=found,
                facts={
                    "tag_in_db": in_db,
                    "tag_in_page": found,
                    "executable": executable,
                    "execution": notes.get("execution"),
                },
            ),
            context=str(constraints.get("context_kind") or ""),
        )
    verdict = inject_verdict(outcome)
    notes["explanation"] = outcome.reason

    # ---- I7 cleanup: delete self-generated data, keep change record for rollback ----
    state["column"] = str(target.get("column") or column)
    if cleanup and state.get("pending"):
        result.residue = await _cleanup_tagged_rows(kernel, state)
        state["pending"] = result.residue != 0
        notes["cleanup"] = {"residue": result.residue, "tag": tag}
        stage("I7", result.residue == 0, f"cleanup tag={tag} residue={result.residue}")
    else:
        stage("I7", True, "no data to clean")

    result.verdict = verdict
    return await _finish(kernel, result)


async def run_inject(
    raw_slice: dict[str, Any],
    base_url: str,
    payload_base: str = DEFAULT_PAYLOAD,
    budget: int = 40,
    client: ToolClient | None = None,
    cleanup: bool = True,
    pair_hints: list[dict[str, Any]] | None = None,
    verify_url: str | None = None,
    verify_entry: dict[str, Any] | None = None,
    verify_values: dict[str, str] | None = None,
    payload_constraints: dict[str, Any] | None = None,
    slice_id: str | None = None,
    learning: dict[str, Any] | None = None,
    read_target: dict[str, Any] | None = None,
    constraint_plan: dict[str, Any] | None = None,
    pair_candidates: dict[str, list[dict[str, Any]]] | None = None,
    flow: dict[str, Any] | None = None,
) -> InjectResult:
    """Run the inject agent and always remove the rows it wrote through the app.

    Every early return already cleans up; this wrapper is the guard for paths
    that raise instead of returning (a killed request, a non-tool error).
    """
    token = _ACTIVE_CLEANUP.set(None)
    try:
        return await _run_inject(
            raw_slice,
            base_url,
            payload_base=payload_base,
            budget=budget,
            client=client,
            cleanup=cleanup,
            pair_hints=pair_hints,
            verify_url=verify_url,
            verify_entry=verify_entry,
            verify_values=verify_values,
            payload_constraints=payload_constraints,
            slice_id=slice_id,
            learning=learning,
            read_target=read_target,
            constraint_plan=constraint_plan,
            pair_candidates=pair_candidates,
            flow=flow,
        )
    finally:
        state = _ACTIVE_CLEANUP.get()
        if cleanup and state and state.get("pending"):
            with contextlib.suppress(Exception):
                await _cleanup_tagged_rows(state["kernel"], state)
        _ACTIVE_CLEANUP.reset(token)


async def _finish(kernel: Kernel, result: InjectResult, cleanup: bool = True) -> InjectResult:
    state = _ACTIVE_CLEANUP.get()
    if cleanup and state and state.get("pending") and state.get("kernel") is kernel:
        result.residue = await _cleanup_tagged_rows(kernel, state)
        state["pending"] = result.residue != 0
        result.notes["cleanup"] = {"residue": result.residue, "tag": state.get("tag")}
        result.stages.append(
            StageRecord("I7", result.residue == 0, f"cleanup tag={state.get('tag')} residue={result.residue}")
        )
    if result.case_id:
        record_case(
            get_runtime().store,
            {"sinkFile": str(result.notes.get("sink_file") or "")},
            str(result.verdict),
            result.notes,
        )
    if result.case_id:
        get_runtime().store.set_case_verdict(result.case_id, str(result.verdict), ceiling="EXECUTABLE")
    report = ""
    try:
        data = await kernel.call(
            "case_report",
            {"case_id": result.case_id, "format": "markdown"},
        )
        report = str(data.get("markdown", "")) if isinstance(data, dict) else ""
    except ToolCallError:
        report = ""
    result.notes["account"] = os.environ.get("TIA_ACCOUNT") or "anonymous (no login)"
    if result.case_id:
        get_runtime().store.merge_case_notes(result.case_id, result.notes)
    result.report = report
    if result.case_id and report:
        get_runtime().store.set_case_report(result.case_id, report)
        write_case_report(get_runtime().store, result.case_id)
    result.trace = kernel.trace
    return result


def _today() -> str:
    return _dt.date.today().isoformat()
