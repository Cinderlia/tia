"""Read conditions -> ordered, legally replayable steps.

The read path decides which rows it shows with a SQL predicate. When that
predicate needs a column value a low-privileged user cannot produce, the flow is
not reachable until some other action sets it. This module finds the predicate,
pairs it with the write slice that can set the column, and replays that action
with a legal request (scraping the page token the action needs).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from tia.cap.conditions import Condition, conditions_in, statement_conditions
from tia.cap.sqlparse import parse_write
from tia.cap.statement import sql_literals, statement_origin
from tia.schemas.envelope import ToolError

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]

_PARAM = re.compile(r"\$_(?:GET|POST|REQUEST)\[['\"](\w+)['\"]\]")
_SET_COLUMN = re.compile(r"\b(?:set|values)\b[^;]{0,300}", re.IGNORECASE)
_TOKEN = re.compile(r"formid=([A-Za-z0-9]+)")
_FORM_TOKEN = re.compile(
    r'name=["\']formid["\'][^>]*?value=["\']([^"\']+)', re.IGNORECASE
)
_FORM_TOKEN_REVERSED = re.compile(
    r'value=["\']([^"\']+)["\'][^>]*?name=["\']formid["\']', re.IGNORECASE
)


def _admin_account(accounts: list[dict[str, Any]], path: str) -> str:
    """Prefer an operator-declared administrator when the action lives under /admin/."""

    if "admin" not in path.lower():
        return ""
    for entry in accounts:
        roles = " ".join(str(role).lower() for role in entry.get("roles") or [])
        description = str(entry.get("description") or "").lower()
        if "admin" in roles or "admin" in description:
            return str(entry.get("label") or "")
    return ""


def _request_params(text: str) -> list[str]:
    return [match.group(1) for match in _PARAM.finditer(text)]


def _write_columns(text: str) -> list[str]:
    """Columns a written statement assigns, without requiring the SQL to be parseable."""

    try:
        write = parse_write(text)
    except ToolError:
        write = None
    if write is not None:
        return [str(column) for column in write.columns]
    match = re.search(
        r"\bupdate\s+`?(\w+)`?\s+set\s+(.*?)(?:\bwhere\b|$)", text, re.IGNORECASE | re.DOTALL
    )
    if match is None:
        return []
    columns: list[str] = []
    for assignment in re.split(r",(?![^()]*\))", match.group(2)):
        found = re.match(r"\s*`?(\w+)`?\s*=", assignment)
        if found:
            columns.append(found.group(1))
    return columns


def _set_expression(text: str, column: str) -> str:
    for block in _SET_COLUMN.finditer(text):
        match = re.search(
            rf"`?{re.escape(column)}`?\s*=\s*(.+?)(?:\bwhere\b|,|$)",
            block.group(0),
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            return match.group(1)
    return ""


def _write_table(text: str) -> str:
    match = re.search(r"\b(?:update|insert\s+into)\s+`?(\w+)`?", text, re.IGNORECASE)
    return match.group(1) if match else ""


_PLAN_SYSTEM = """You plan HTTP requests against a running PHP web application.

A read path shows a row only when a database column holds a fixed value, and an
existing application action (an admin approval, a flag switch, a state change)
produces that value. You are given the executed read SQL, the predicate, the
source of the action that writes the column, the application root URL, and the
lines elsewhere in the code that reference this action.

Reply with ONE JSON object:
{"candidates": [{"url": "absolute URL", "method": "GET"|"POST"}, ...],
 "account": "label from the switchable users, or \"\"",
 "reason": "one sentence"}

Rules:
- Every URL must share the origin AND start with app_url.
- The action file path is relative to the application root. The action is
  included by a page, usually with a query parameter that selects it; read the
  reference lines to find that page and parameter name.
- List at most 4 candidates, most likely first.
- Do not put parameters the caller must supply (row IDs, the payload) into the
  URL; the caller fills every request variable the action reads.
- Pick the least privileged account that is allowed to act.
- Never answer with SQL; the application must perform the write.
"""


async def plan_action(
    planner: Any,
    *,
    read_sql: str,
    condition: Condition,
    writer_file: str,
    writer_code: str,
    base_url: str,
    accounts: list[dict[str, Any]] | None,
    route_evidence: list[dict[str, Any]] | None = None,
    app_url: str = "",
    action_stem: str = "",
    trace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Let the model choose candidate action URLs; the caller validates them."""

    from urllib.parse import urlsplit

    users = [
        {
            "label": str(entry.get("label") or ""),
            "roles": list(entry.get("roles") or []),
            "description": str(entry.get("description") or ""),
        }
        for entry in accounts or []
    ]
    user = json.dumps(
        {
            "page_url": base_url,
            "app_url": app_url or base_url,
            "read_sql": read_sql,
            "condition": {
                "table": condition.table,
                "column": condition.column,
                "value": condition.value,
                "predicate": condition.predicate,
            },
            "action_file": writer_file,
            "action_stem": action_stem,
            "action_source": writer_code[-4000:],
            "route_evidence": route_evidence or [],
            "switchable_users": users,
            "executed_trace": trace or {},
        },
        ensure_ascii=False,
    )
    reply = await planner.complete_json(_PLAN_SYSTEM, user)
    raw_candidates = reply.get("candidates") or []
    if not raw_candidates and reply.get("url"):
        raw_candidates = [{"url": reply.get("url"), "method": reply.get("method")}]
    base = urlsplit(base_url)
    prefix = base.path if base.path.endswith("/") else base.path.rsplit("/", 1)[0] + "/"
    urls: list[str] = []
    method = "GET"
    for item in raw_candidates[:4]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        try:
            target = urlsplit(url)
        except ValueError:
            continue
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            continue
        if not target.path.startswith(prefix):
            continue
        if url in urls:
            continue
        urls.append(url)
        if len(urls) == 1:
            candidate_method = str(item.get("method") or "GET").upper()
            method = candidate_method if candidate_method in {"GET", "POST"} else "GET"
    account = str(reply.get("account") or "").strip()
    labels = {str(entry.get("label") or "") for entry in accounts or []}
    if account and account not in labels:
        account = ""
    return {"urls": urls, "method": method, "account": account, "reason": reply.get("reason")}


async def build_steps(
    call: Call,
    flow: dict[str, Any],
    writers: list[tuple[str, dict[str, Any]]],
    base_url: str,
    url_for: Callable[[dict[str, Any]], str] | None,
    accounts: list[dict[str, Any]] | None = None,
    *,
    read_raw: dict[str, Any] | None = None,
    read_sql: str = "",
    read_trace: dict[str, Any] | None = None,
    planner: Any | None = None,
) -> dict[str, Any]:
    """One constraint step per read predicate whose column a write slice sets."""

    table = str(flow.get("table_name") or flow.get("table") or "")
    conditions: list[Condition] = []
    read_text = ""
    if read_sql.strip():
        # The probe reports the statement the engine ran; its predicate is the
        # condition a write step has to satisfy, so parse that and nothing else.
        conditions = [
            item for item in statement_conditions(read_sql, "executed_sql") if item.column
        ]
    elif read_raw:
        read_file = str(read_raw.get("sinkFile") or "")
        read_line = int(read_raw.get("sinkLine") or 0)
        if read_file:
            try:
                window = await call(
                    "source_read",
                    {"file": read_file, "around": {"line": read_line, "n": 80}},
                )
                read_text = "\n".join(
                    str(item.get("text") or "") for item in window.get("lines") or []
                )
                conditions = [
                    item
                    for item in statement_conditions(read_text, f"{read_file}:{read_line}")
                    if item.value not in {"0", "1"} or item.column
                ]
            except Exception:  # noqa: BLE001
                conditions = []
    if not conditions and table:
        try:
            grep = await call(
                "source_grep",
                {"pattern": table, "max": 10},
            )
        except Exception:  # noqa: BLE001 - no source, no constraints
            return {}
        if os.environ.get("TIA_PLAN_DEBUG"):
            print(f"[plan] grep hits={grep.get('hits')}", flush=True)
        for hit in (grep.get("hits") or [])[:6]:
            file_name = str(hit.get("file") or "")
            line = int(hit.get("line") or 0)
            try:
                window = await call(
                    "source_read", {"file": file_name, "around": {"line": line, "n": 40}}
                )
            except Exception:  # noqa: BLE001
                continue
            text = "\n".join(str(item.get("text") or "") for item in window.get("lines") or [])
            conditions.extend(conditions_in(text, f"{file_name}:{line}", table))
            sql_fragments = sql_literals(text)
            if os.environ.get("TIA_PLAN_DEBUG"):
                print(
                    f"[plan] hit={file_name}:{line} frag={sql_fragments[:160]!r}",
                    flush=True,
                )
            if sql_fragments:
                conditions.extend(statement_conditions(sql_fragments, f"{file_name}:{line}"))
    if os.environ.get("TIA_PLAN_DEBUG"):
        print(f"[plan] conditions={[(c.table, c.column, c.value) for c in conditions]}", flush=True)
    seen: set[tuple[str, str]] = set()
    steps: list[dict[str, Any]] = []
    for condition in conditions:
        key = (condition.column, condition.value)
        if key in seen:
            continue
        seen.add(key)
        for write_slice_id, raw in writers:
            file_name = str(raw.get("sinkFile") or "")
            line = int(raw.get("sinkLine") or 0)
            try:
                window = await call("source_read", {"file": file_name, "around": {"line": line, "n": 40}})
            except Exception:  # noqa: BLE001
                continue
            lines = [
                (int(item.get("n") or item.get("line") or 0), str(item.get("text") or ""))
                for item in window.get("lines") or []
            ]
            text = "\n".join(item[1] for item in lines)
            origin_text, _origin_line = statement_origin(lines, line)
            columns = _write_columns(origin_text)
            writer_table = _write_table(origin_text)
            if os.environ.get("TIA_PLAN_DEBUG"):
                print(
                    f"[plan] cond={condition.table}.{condition.column} writer={writer_table}"
                    f" cols={columns} file={file_name}:{line}",
                    flush=True,
                )
            if condition.column not in columns:
                continue
            if writer_table and writer_table != condition.table:
                continue
            expr = _set_expression(origin_text, condition.column)
            value_params = [
                name
                for name in _request_params(expr)
                if name.lower() not in {"formid", "action", "page"}
            ]
            key_params = [
                name
                for name in _request_params(origin_text)
                if name not in value_params and name.lower() not in {"formid", "action", "page"}
            ]
            replay_url = base_url
            if url_for is not None and file_name:
                replay_url = url_for(raw).rstrip("/") + "/" + Path(file_name).name
            account = _admin_account(accounts or [], file_name)
            method = "GET"
            replay_urls = [replay_url]
            if planner is not None:
                stem = Path(file_name).stem
                evidence: list[dict[str, Any]] = []
                try:
                    hits = await call("source_grep", {"pattern": stem, "max": 8})
                except Exception:  # noqa: BLE001 - no hits, no evidence
                    hits = {}
                for hit in (hits.get("hits") or [])[:8]:
                    evidence.append(
                        {
                            "file": hit.get("file"),
                            "line": hit.get("line"),
                            "text": str(hit.get("text") or "")[:200],
                        }
                    )
                app_url = base_url if base_url.endswith("/") else base_url.rsplit("/", 1)[0] + "/"
                planned = await plan_action(
                    planner,
                    read_sql=read_sql,
                    condition=condition,
                    writer_file=file_name,
                    writer_code=text,
                    base_url=base_url,
                    accounts=accounts,
                    route_evidence=evidence,
                    app_url=app_url,
                    action_stem=stem,
                    trace=read_trace,
                )
                if planned.get("urls"):
                    replay_urls = list(planned["urls"])
                    method = str(planned.get("method") or "GET")
                    account = str(planned.get("account") or "") or account
            steps.append(
                {
                    "constraint_id": f"dc-{len(steps) + 1}",
                    "table": condition.table,
                    "payload_table": table,
                    "column": condition.column,
                    "value": condition.value,
                    "predicate": condition.predicate,
                    "at": condition.at,
                    "write_slice_id": write_slice_id,
                    "write_file": file_name,
                    "write_line": line,
                    "replay_url": replay_urls[0] if replay_urls else "",
                    "replay_urls": replay_urls,
                    "method": method,
                    "value_params": value_params,
                    "key_params": key_params,
                    "account": account,
                }
            )
            break
    if not steps:
        return {}
    return {
        "steps": [{"kind": "constraint", "ref": step["constraint_id"]} for step in steps]
        + [{"kind": "payload", "ref": "payload"}],
        "constraints": [
            {key: value for key, value in step.items()} for step in steps
        ],
    }


def _token(page: str) -> str:
    match = _TOKEN.search(page or "")
    return match.group(1) if match else ""


def _form_token(page: str) -> str:
    """Read a CSRF token from a form field, in either attribute order."""

    for pattern in (_FORM_TOKEN, _FORM_TOKEN_REVERSED):
        match = pattern.search(page or "")
        if match:
            return match.group(1)
    return _token(page)


async def replay(
    call: Call,
    *,
    case_id: str,
    step: dict[str, Any],
    payload_column: str,
    tag: str,
) -> dict[str, Any]:
    """Replay one constraint through the action that sets the column."""

    table = str(step.get("table") or "")
    payload_table = str(step.get("payload_table") or table)
    column = str(step.get("column") or "")
    value = str(step.get("value") or "")
    urls = [str(item) for item in (step.get("replay_urls") or []) if str(item)]
    single = str(step.get("replay_url") or "")
    if not urls and single:
        urls = [single]
    out: dict[str, Any] = {"constraint_id": step.get("constraint_id"), "urls": urls}
    if not (table and column and urls and payload_column):
        out["error"] = "the step has no table, column, url or payload column"
        return out
    try:
        row = await call(
            "db_read",
            {
                "sql": f"SELECT * FROM `{payload_table}` WHERE `{payload_column}` LIKE '%{tag}%' LIMIT 1"
            },
        )
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"db_read failed: {exc}"
        return out
    rows = row.get("rows") or []
    if not rows:
        out["error"] = "no stored row carries the tag"
        return out
    stored = rows[0]
    key_name, key_value = next(
        (
            (name, val)
            for name, val in stored.items()
            if name.lower().endswith("_id") or name.lower() == "id"
        ),
        ("", ""),
    )
    check_key = key_name
    try:
        schema = await call("db_schema", {"table": table})
        tables = schema.get("tables") or []
        primary = list((tables[0] if tables else {}).get("primary_key") or [])
        if primary:
            check_key = str(primary[0])
    except Exception:  # noqa: BLE001 - fall back to the payload table key
        pass
    account = str(step.get("account") or "")
    method = str(step.get("method") or "GET").upper()
    base_params: dict[str, Any] = {}
    for name in step.get("value_params") or []:
        base_params[str(name)] = value
    for name in step.get("key_params") or []:
        base_params[str(name)] = key_value
    armed = False
    try:
        await call(
            "probe_arm",
            {
                "case_id": case_id,
                "targets": [{"file": step.get("write_file"), "line": step.get("write_line")}],
                "output": f"step-{step.get('constraint_id')}-{tag}.json",
            },
        )
        armed = True
    except Exception:  # noqa: BLE001 - replay still runs without probe evidence
        armed = False
    attempts: list[dict[str, Any]] = []
    confirmed = False
    for url in urls:
        params = dict(base_params)
        # The action page usually carries a CSRF token; fetch it first like a
        # browser would, then replay the action with the token attached.
        try:
            landing = await call(
                "http_request",
                {
                    "url": url,
                    "method": "GET",
                    "account_label": account,
                },
            )
            initial_token = _form_token(str(landing.get("body") or ""))
        except Exception:  # noqa: BLE001 - the action may not need a token
            initial_token = ""
        if initial_token:
            params["formid"] = initial_token
        for _attempt in range(2):
            request: dict[str, Any] = {
                "case_id": case_id,
                "url": url,
                "method": method,
                "capture_html": True,
                "account_label": account,
            }
            if method == "POST":
                request["values"] = params
            else:
                request["params"] = params
            try:
                page = await call("probe_run" if armed else "http_request", request)
            except Exception as exc:  # noqa: BLE001 - a branch that did not run is a fact
                attempts.append({"url": url, "params": dict(params), "error": str(exc)})
                break
            http = page.get("http") or {}
            attempts.append(
                {
                    "url": url,
                    "params": dict(params),
                    "status": http.get("status"),
                    "queries": len(page.get("queries") or []),
                }
            )
            try:
                check = await call(
                    "db_read",
                    {
                        "sql": (
                            f"SELECT `{column}` AS v FROM `{table}` "
                            f"WHERE `{check_key}` = '{key_value}' LIMIT 1"
                        )
                    },
                )
            except Exception:  # noqa: BLE001
                check = {}
            rows_check = check.get("rows") or []
            if rows_check and str(rows_check[0].get("v")) == value:
                confirmed = True
                out["observed"] = rows_check[0].get("v")
                out["url"] = url
                break
            token = _token(str(http.get("html") or ""))
            if not token:
                break
            params["formid"] = token
        if confirmed:
            break
    if armed:
        with contextlib.suppress(Exception):
            await call("probe_disarm", {"case_id": case_id})
    out["attempts"] = attempts
    out["confirmed"] = confirmed
    return out
