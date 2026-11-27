"""Probe tools: arm, run and disarm the observation probe of the target runtime.

The probe itself lives in the target PHP runtime (the ``sqlquery`` extension).
This module is the only place that knows the extension's file contract: a
configuration file that selects a file and line, the captured result of the last
request, and a flat debug log that states how many queries matched.

Composition lives here, not in another tool (H7): ``probe_run`` issues the HTTP
request and reads the captured result in one step.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.ad.http import HttpClient
from tia.ad.sqlprobe import ProbeConfigError, SqlProbeAdapter
from tia.cap.http import _file_fields
from tia.cap.policy import require_case
from tia.cap.registry import ToolOutput
from tia.cap.session import looks_like_login, renew_session, resolve_session
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import ErrorCode, ToolError

MAX_WAIT_MS = 2000


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc


def _target_file(raw: str) -> str:
    """Resolve the target file and keep it inside the application root."""

    rt = get_runtime()
    root = Path(rt.settings.app_root).resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise _bad(f"Target file does not exist: {raw}") from exc
    if not resolved.is_relative_to(root):
        raise ToolError(
            ErrorCode.POLICY_DENIED,
            f"Target file is outside the application root: {resolved}",
            hint=f"Application root: {root}",
        )
    return str(resolved)



_SQL_ERROR_HINTS = (
    "sql syntax",
    "sqlstate[",
    "you have an error in your sql",
    "mysqli_sql_exception",
    "pdoexception",
    "uncaught mysqli",
    "uncaught pdoexception",
    "unknown column",
    "fatal error:",
    "syntax error at or near",
)


def _sql_error(body: str) -> str:
    """Best-effort SQL error text from the response, for the agent's diagnosis."""
    lowered = body.lower()
    for hint in _SQL_ERROR_HINTS:
        index = lowered.find(hint)
        if index >= 0:
            snippet = " ".join(body[max(0, index - 80) : index + 240].split())
            return snippet[:400]
    return ""

def _matched_at(query: dict[str, Any]) -> str:
    if query.get("matched_at_prepare"):
        return "prepare"
    if query.get("matched_at_origin"):
        return "origin"
    if query.get("matched_at_fetch"):
        return "fetch"
    return "stack"


def _normalize_query(query: dict[str, Any]) -> dict[str, Any]:
    raw_fields = query.get("fields") or []
    fields = [field for field in raw_fields if isinstance(field, dict)]
    names = [str(field.get("name") or "") for field in fields]
    rows: list[dict[str, Any]] = []
    for row in query.get("rows") or []:
        values = list(row) if isinstance(row, list) else [row]
        rows.append({name: values[index] if index < len(values) else None
                     for index, name in enumerate(names)})
    raw_write = query.get("write")
    write: dict[str, Any] = raw_write if isinstance(raw_write, dict) else {}
    parameters = write.get("parameters") if isinstance(write.get("parameters"), list) else []
    execute_ms = query.get("execute_time_ms") or 0
    observed: dict[str, Any] = {
        "call_index": query.get("call_index", 0),
        "sql": query.get("sql", ""),
        "kind": query.get("kind", ""),
        "bindings": parameters,
        "fields": fields,
        "rows": rows,
        "row_count": int(query.get("row_count") or 0),
        "affected_rows": int(query.get("affected_rows") or 0),
        "last_insert_id": int(query.get("last_insert_id") or 0),
        "matched_at": _matched_at(query),
        "execute_time_ms": int(round(float(execute_ms))),
        "fetch_time_ms": int(round(float(query.get("fetch_time_ms") or 0))),
        "total_time_ms": int(
            round(float(execute_ms) + float(query.get("fetch_time_ms") or 0))
        ),
        "error": str(
            query.get("error")
            or query.get("error_message")
            or (write.get("error") if write else "")
            or ""
        ),
        "observed_at": now_iso(),
    }
    target_index = query.get("target_index")
    if isinstance(target_index, int) and target_index >= 0:
        observed["target_index"] = target_index
        observed["target_file"] = str(query.get("target_file") or "")
        observed["target_line"] = int(query.get("target_line") or 0)
    if write:
        observed["write"] = write
    return observed


class ProbeTargetInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    line: int = Field(ge=1)


def _by_target(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group captures by the target that matched them."""

    groups: dict[int, dict[str, Any]] = {}
    for query in queries:
        raw = query.get("target_index")
        key = int(raw) if isinstance(raw, int) else -1
        group = groups.setdefault(key, {
            "target_index": key,
            "target_file": str(query.get("target_file") or ""),
            "target_line": int(query.get("target_line") or 0),
            "queries": 0,
            "rows": 0,
        })
        group["queries"] += 1
        group["rows"] += int(query.get("row_count") or 0)
    return [groups[key] for key in sorted(groups)]


class ProbeArmInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    targets: list[ProbeTargetInput] = Field(default_factory=list)
    output: str | None = None
    match: str = "line"


async def probe_arm(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ProbeArmInput, arguments)
    rt = get_runtime()
    require_case(rt.store, params.case_id)
    requested: list[ProbeTargetInput] = list(params.targets)
    if params.file is not None or params.line is not None:
        if params.file is None or params.line is None:
            raise _bad("file and line must be given together")
        requested.append(ProbeTargetInput(file=params.file, line=params.line))
    if not requested:
        raise _bad("give at least one target", "Pass targets: [{file, line}, ...]")
    seen: set[tuple[str, int]] = set()
    targets: list[tuple[str, int]] = []
    for item in requested:
        resolved = _target_file(item.file)
        key = (resolved, item.line)
        if key in seen:
            continue
        seen.add(key)
        targets.append(key)
    adapter = SqlProbeAdapter()
    output = params.output or f"{params.case_id}-{targets[0][1]}.json"
    previous = adapter.read_config()
    try:
        config = adapter.arm(targets, output)
    except ProbeConfigError as exc:
        raise _bad(str(exc), "Use a plain .json file name without path separators") from exc
    warnings: list[str] = []
    if previous is not None and previous != config:
        warnings.append("PROBE_SLOT_REUSED")
    probe_id = f"probe-{params.case_id}-{targets[0][1]}"
    target_list = [
        {"file": file_name, "line": line, "match": params.match}
        for file_name, line in targets
    ]
    rt.store.add_probe(
        params.case_id,
        probe_id=probe_id,
        mode="read",
        target={"targets": target_list},
        status="armed",
        body=config,
    )
    return ToolOutput(
        data={
            "probe_id": probe_id,
            "targets": target_list,
            "target": target_list[0],
            "output": config["output"],
            "config_path": str(adapter.config_path),
            "armed_at": now_iso(),
        },
        warnings=warnings,
    )


class ProbeRunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    url: str
    method: str = "GET"
    params: dict[str, Any] = Field(default_factory=dict)
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    output: str | None = None
    wait_ms: int = Field(default=0, ge=0, le=MAX_WAIT_MS)
    capture_html: bool = False
    files: dict[str, str] = Field(default_factory=dict)
    session_id: str | None = None
    account_label: str = ""


async def probe_run(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ProbeRunInput, arguments)
    rt = get_runtime()
    require_case(rt.store, params.case_id)
    if not params.url.startswith(("http://", "https://")):
        raise _bad("url must be an absolute http(s) address")
    adapter = SqlProbeAdapter()
    config = adapter.read_config()
    if config is None:
        raise ToolError(
            ErrorCode.CONFLICT,
            "No probe is armed",
            hint="Call probe_arm before probe_run",
        )
    output = params.output or str(config.get("output") or "")
    if not output:
        raise ToolError(ErrorCode.CONFLICT, "The armed probe has no output file")

    headers = dict(params.headers)
    if params.method.upper() != "GET" and params.body and not any(
        key.lower() == "content-type" for key in headers
    ):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    session_id, cookies, warnings = await resolve_session(
        params.session_id, params.url, params.account_label
    )
    started = time.perf_counter()
    result = HttpClient().fetch(
        params.method,
        params.url,
        params=params.params or None,
        body=params.body,
        headers=headers,
        cookies=cookies,
        max_bytes=rt.settings.profile.max_http_bytes,
        files=_file_fields(params.files),
    )
    if session_id and looks_like_login(
        result.status, result.headers.get("location", ""), result.body
    ):
        session_id, cookies = await renew_session(session_id)
        warnings.append("SESSION_RENEWED")
        result = HttpClient().fetch(
            params.method,
            params.url,
            params=params.params or None,
            body=params.body,
            headers=headers,
            cookies=cookies,
            max_bytes=rt.settings.profile.max_http_bytes,
        )
    if params.wait_ms:
        time.sleep(params.wait_ms / 1000)
    http_ms = round((time.perf_counter() - started) * 1000.0, 1)
    capture_started = time.perf_counter()
    snapshot = adapter.snapshot(output)
    capture_ms = round((time.perf_counter() - capture_started) * 1000.0, 1)
    if snapshot.output is None:
        raise ToolError(
            ErrorCode.NOT_FOUND,
            "The probe produced no output for this request",
            hint=(
                "The configured line did not execute, or the runtime is not loaded with "
                "the probe; check the debug log of the same request"
            ),
        )
    queries = [_normalize_query(query) for query in snapshot.output.get("queries") or []
               if isinstance(query, dict)]
    raw_targets = config.get("targets") or []
    config_targets = [
        {"file": str(item.get("file") or ""), "line": int(item.get("line") or 0)}
        for item in raw_targets
        if isinstance(item, dict)
    ]
    if not config_targets:
        config_targets = [{"file": str(config.get("file") or ""),
                           "line": int(config.get("line") or 0)}]
    first_line = config_targets[0]["line"] if config_targets else 0

    mode = "write" if any(query.get("affected_rows") or query.get("write") for query in queries) else "read"
    if not queries:
        warnings.append("PROBE_NO_MATCH")
    elif len(config_targets) > 1:
        matched = {int(query["target_index"]) for query in queries
                   if isinstance(query.get("target_index"), int)}
        missing = [index for index in range(len(config_targets)) if index not in matched]
        if missing:
            warnings.append("PROBE_TARGET_UNMATCHED")
    if snapshot.debug.get("matched_queries") == "0":
        warnings.append("PROBE_NO_MATCH")
    return ToolOutput(
        data={
            "probe_id": f"probe-{params.case_id}-{first_line}",
            "session_id": session_id,
            "mode": mode,
            "targets": config_targets,
            "target": config_targets[0] if config_targets else {"file": "", "line": 0},
            "hit": bool(queries),
            "by_target": _by_target(queries),
            "queries": queries,
            "http": {
                "status": result.status,
                "content_type": result.content_type,
                "redirect_chain": result.redirect_chain,
                "bytes": result.body_bytes,
                "elapsed_ms": round(float(getattr(result, "elapsed_ms", 0.0)), 2),
                **({"html": result.body} if params.capture_html else {}),
            },
            "timing": {
                "http_ms": http_ms,
                "capture_read_ms": capture_ms,
                "total_ms": round(http_ms + capture_ms, 1),
            },
            "error": _sql_error(result.body),
            "debug": snapshot.debug,
            "observed_at": now_iso(),
        },
        warnings=sorted(set(warnings)),
    )


class ProbeDisarmInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str | None = None
    remove_output: bool = True


async def probe_disarm(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ProbeDisarmInput, arguments)
    adapter = SqlProbeAdapter()
    config = adapter.read_config() or {}
    disarmed = adapter.disarm()
    removed_output = False
    output = config.get("output")
    if params.remove_output and isinstance(output, str):
        removed_output = adapter.remove_output(output)
    return ToolOutput(
        data={
            "disarmed": disarmed,
            "removed_output": removed_output,
            "output": output if isinstance(output, str) else "",
        }
    )
