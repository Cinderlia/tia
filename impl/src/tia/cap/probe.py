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
from tia.cap.policy import require_case
from tia.cap.registry import ToolOutput
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
        "observed_at": now_iso(),
    }
    if write:
        observed["write"] = write
    return observed


class ProbeArmInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    file: str
    line: int = Field(ge=1)
    output: str | None = None
    match: str = "line"


async def probe_arm(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ProbeArmInput, arguments)
    rt = get_runtime()
    require_case(rt.store, params.case_id)
    target = _target_file(params.file)
    adapter = SqlProbeAdapter()
    output = params.output or f"{params.case_id}-{params.line}.json"
    previous = adapter.read_config()
    try:
        config = adapter.arm(target, params.line, output)
    except ProbeConfigError as exc:
        raise _bad(str(exc), "Use a plain .json file name without path separators") from exc
    warnings: list[str] = []
    if previous is not None and previous != config:
        warnings.append("PROBE_SLOT_REUSED")
    probe_id = f"probe-{params.case_id}-{params.line}"
    target_obj = {"file": target, "line": params.line, "match": params.match}
    rt.store.add_probe(
        params.case_id,
        probe_id=probe_id,
        mode="read",
        target=target_obj,
        status="armed",
        body=config,
    )
    return ToolOutput(
        data={
            "probe_id": probe_id,
            "target": target_obj,
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

    result = HttpClient().fetch(
        params.method,
        params.url,
        params=params.params or None,
        body=params.body,
        headers=params.headers,
        max_bytes=rt.settings.profile.max_http_bytes,
    )
    if params.wait_ms:
        time.sleep(params.wait_ms / 1000)

    snapshot = adapter.snapshot(output)
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
    mode = "write" if any(query.get("affected_rows") or query.get("write") for query in queries) else "read"
    warnings: list[str] = []
    if not queries:
        warnings.append("PROBE_NO_MATCH")
    if snapshot.debug.get("matched_queries") == "0":
        warnings.append("PROBE_NO_MATCH")
    return ToolOutput(
        data={
            "probe_id": f"probe-{params.case_id}-{config.get('line', 0)}",
            "mode": mode,
            "target": {
                "file": config.get("file", ""),
                "line": int(config.get("line", 0)),
                "match": "line",
            },
            "hit": bool(queries),
            "queries": queries,
            "http": {
                "status": result.status,
                "content_type": result.content_type,
                "redirect_chain": result.redirect_chain,
                "bytes": result.body_bytes,
            },
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
