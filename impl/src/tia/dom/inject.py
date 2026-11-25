"""inject agent: proves "user can write content via HTTP entry" (I0–I7).

Division of labor with trigger: trigger writes directly to DB to prove sink reachability; inject only uses the app's own forms,
DB writes are performed by the app, finally using ``db_read`` / ``verify_tag`` for tri-state acceptance.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import re
import secrets
import string
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin

from tia.cap.domscan import Document, parse
from tia.dom.trigger import StageRecord
from tia.inf.runtime import get_runtime
from tia.orch.judge import judge_inject
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient

DEFAULT_PAYLOAD = "<script>alert(1)</script>"
_TAG_RE = re.compile(r"<tia-([a-z0-9]{4})>")


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


def _tag() -> str:
    """4-char lowercase alphanumeric: serves as evidence and passes common length limits."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(4))


def _walk(document: Document) -> list[Any]:
    return list(document.nodes)


def _forms(document: Document, page_url: str) -> list[_Form]:
    forms: list[_Form] = []
    for node in document.nodes:
        if node.tag != "form":
            continue
        action = node.attrs.get("action", "")
        method = (node.attrs.get("method") or "get").lower()
        fields: dict[str, str] = {}
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.tag in {"input", "textarea", "select"}:
                name = child.attrs.get("name")
                if name:
                    kind = (child.attrs.get("type") or "").lower()
                    if kind not in {"submit", "button", "reset", "file", "image"}:
                        fields[name] = child.attrs.get("value", "")
            stack.extend(child.children)
        forms.append(_Form(action=urljoin(page_url, action or page_url), method=method, fields=fields))
    return forms


_INSERT_RE = re.compile(
    r"insert\s+(?:ignore\s+)?into\s+([`\"]?)([A-Za-z_][\w]*)\1\s*\(([^)]*)\)", re.I
)


def _insert_line(lines: list[dict[str, Any]]) -> int | None:
    """Absolute line number of the INSERT statement inside a source window."""
    for item in lines:
        if _INSERT_RE.search(str(item.get("text", ""))):
            number = item.get("n")
            if isinstance(number, int):
                return number
    return None


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


async def run_inject(
    raw_slice: dict[str, Any],
    base_url: str,
    payload_base: str = DEFAULT_PAYLOAD,
    budget: int = 40,
    client: ToolClient | None = None,
    cleanup: bool = True,
) -> InjectResult:
    kernel = Kernel(
        profile="inject", budget=budget, client=client or LocalToolClient(profile="inject")
    )
    result = InjectResult(case_id="", verdict="ENV_ERROR")
    stages = result.stages
    notes = result.notes

    def stage(name: str, ok: bool, note: str) -> None:
        stages.append(StageRecord(stage=name, ok=ok, note=note))

    sink = str(raw_slice.get("sink") or raw_slice.get("sinkCode") or "")
    sink_file = str(raw_slice.get("sinkFile") or (sink.split(":", 1)[0] if ":" in sink else ""))
    line_match = re.search(r":(\d+)", sink)
    sink_line = int(line_match.group(1)) if line_match else int(raw_slice.get("sinkLine") or 0)
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
    target = _infer_target(text, str(raw_slice.get("sinkCode") or sink), params)
    if target is None:
        stage("I1", False, "INSERT target table not found")
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)
    notes["target"] = target
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
    field_name = next(
        (name for name in params if any(name in form.fields for form in forms)),
        "",
    )
    if not forms:
        stage("I2", False, "No POST form on page")
        result.verdict = "NO_HTTP_ENTRY"
        return await _finish(kernel, result)
    if not field_name:
        stage("I2", False, f"form fields {sorted(set().union(*[set(f.fields) for f in forms]))} do not match params {params}")
        result.verdict = "ENTRY_AMBIGUOUS"
        return await _finish(kernel, result)
    form = next(f for f in forms if field_name in f.fields)
    notes["entry"] = {"url": form.action, "method": form.method, "field": field_name, "fields": form.fields}
    stage("I2", True, f"form {form.action} field={field_name}")

    # ---- I3 Length budget: column width determines if payload fits ----
    schema = await call("db_schema", {"table": target["table"]})
    length = None
    for table_item in schema.get("tables") or []:
        if table_item.get("name") == target["table"]:
            for column in table_item.get("columns") or []:
                if column.get("name") == target["column"]:
                    length = column.get("length")
    payload = f"{payload_base}<tia-{tag}>"
    if length is not None and len(payload) > int(length):
        stage("I3", False, f"payload {len(payload)} > column width {length}")
        result.verdict = "LENGTH_EXCEEDED"
        return await _finish(kernel, result)
    notes["payload"] = payload
    stage("I3", True, f"payload {len(payload)} chars, column width {length}")
    stage("I4", True, f"intersect: field={field_name}, payload {len(payload)} chars")

    # ---- I4/I5 delivery: use the application's own form ----
    values = dict(form.fields)
    values[field_name] = payload
    for param in params:
        if param in form.fields and param != field_name:
            values[param] = values[param] or f"tia-{tag}"
    body = urlencode(values)
    armed = False
    if insert_line is not None:
        try:
            await call("probe_arm", {"case_id": result.case_id, "file": sink_file, "line": insert_line})
            armed = True
        except ToolCallError as exc:
            notes["probe_error"] = str(exc.envelope.error.message if exc.envelope.error else exc)
    try:
        if armed:
            submitted = await call(
                "probe_run",
                {
                    "case_id": result.case_id,
                    "url": form.action,
                    "method": "POST",
                    "body": body,
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )
        else:
            submitted = await call(
                "http_request",
                {
                    "method": "POST",
                    "url": form.action,
                    "body": body,
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            )
    except ToolCallError as exc:
        stage("I5", False, f"POST failed: {exc}")
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)
    finally:
        if armed:
            with contextlib.suppress(ToolCallError):
                await call("probe_disarm", {"case_id": result.case_id})
    status = submitted.get("http", {}).get("status") if armed else submitted.get("status")
    stage("I5", True, f"POST {form.action} → {status} probe={armed}")
    if armed and (submitted.get("queries") or []):
        query = (submitted.get("queries") or [{}])[0]
        notes["probe"] = {
            "mode": submitted.get("mode"),
            "sql": query.get("sql"),
            "bindings": query.get("bindings"),
            "affected_rows": query.get("affected_rows"),
            "last_insert_id": query.get("last_insert_id"),
            "matched_at": query.get("matched_at"),
        }
    if int(status or 0) >= 400:
        result.verdict = "WRITE_NOT_REACHED"
        return await _finish(kernel, result)

    # ---- I6 tri-state acceptance: in DB / on page / executable ----
    table = target["table"]
    column = target["column"]
    probe = await call(
        "db_read",
        {
            "sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE `{column}` LIKE '%<tia-{tag}>%'",
        },
    )
    rows = probe.get("rows") or []
    in_db = bool(rows and int(rows[0].get("n") or 0) > 0)
    notes["tag_in_db"] = in_db
    stage("I6", in_db, f"tag_in_db={in_db}")

    verify = await call("verify_tag", {"url": form.action, "tag": tag, "payload": payload})
    found = bool(verify.get("found"))
    best = verify.get("best") or {}
    executable = bool(best.get("executable"))
    notes.update({"tag_in_page": found, "executable": executable, "context_kind": best.get("context_kind")})
    stage("I6", found, f"tag_in_page={found} executable={executable} kind={best.get('context_kind')}")

    verdict, explanation = judge_inject(in_db, found, executable)
    notes["explanation"] = explanation

    # ---- I7 cleanup: delete self-generated data, keep change record for rollback ----
    if cleanup and in_db:
        try:
            deleted = await call(
                "db_write",
                {
                    "case_id": result.case_id,
                    "sql": f"DELETE FROM `{table}` WHERE `{column}` LIKE '%<tia-{tag}>%'",
                    "expect_affected": 1,
                },
            )
            change = (deleted.get("change") or {}).get("change_id")
            again = await call(
                "db_read",
                {
                    "sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE `{column}` LIKE '%<tia-{tag}>%'",
                },
            )
            rows_again = again.get("rows") or []
            result.residue = int(rows_again[0].get("n") or 0) if rows_again else 0
            notes["cleanup"] = {"change_id": change, "residue": result.residue}
            stage("I7", result.residue == 0, f"cleanup change={change} residue={result.residue}")
        except ToolCallError as exc:
            stage("I7", False, f"cleanup failed: {exc.envelope.error.message if exc.envelope.error else exc}")
    else:
        stage("I7", True, "no data to clean")

    result.verdict = verdict
    return await _finish(kernel, result)


async def _finish(kernel: Kernel, result: InjectResult, cleanup: bool = True) -> InjectResult:
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
    result.report = report
    result.trace = kernel.trace
    if result.case_id:
        with contextlib.suppress(ToolCallError):
            await kernel.call(
                "case_note",
                {"case_id": result.case_id, "key": "verdict", "value": result.verdict},
            )
    return result


def _today() -> str:
    return _dt.date.today().isoformat()
