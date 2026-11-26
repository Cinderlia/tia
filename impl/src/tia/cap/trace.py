"""Directed opcode trace tools: run one request under a directed tracer, and
diff two recorded traces.

A full opcode trace of a real request is far too large for an agent (tens of
thousands to millions of lines), so every trace is directed by file, line range,
function and depth on the tracer side, then adjacent duplicates are collapsed
and the result is bounded before it leaves this module.

The tracer lives in the target PHP runtime (``impl/probe-php/opcode-tracer``).
This module writes its config, issues the request and reads the produced file
(H7: the composition lives in the handler, not in another tool).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.ad.http import HttpClient, HttpResult
from tia.ad.opcode_trace import (
    OpcodeTraceAdapter,
    TraceConfigError,
    TraceRequest,
)
from tia.cap.policy import require_case
from tia.cap.registry import ToolOutput
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import ErrorCode, ToolError

MAX_ENTRIES = 300
MAX_TRACE_LINES = 200_000
_LINE_RE = re.compile(r"^(?P<file>.*?):(?P<line>\d+) \| op=(?P<op>[A-Za-z0-9_]+)(?P<rest>.*)$")
_PC_RE = re.compile(r" \| pc=(-?\d+)")
_DEPTH_RE = re.compile(r" \| depth=(\d+)")
_FUNC_RE = re.compile(r" \| func=([^|]*)")


class TraceRunInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    url: str
    file: str
    line_from: int = 0
    line_to: int = 0
    function: str = ""
    max_depth: int = 0
    max_lines: int = Field(default=20000, ge=1, le=MAX_TRACE_LINES)
    method: str = "GET"
    params: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    output: str | None = None
    max_entries: int = Field(default=MAX_ENTRIES, ge=1, le=MAX_ENTRIES)
    dedupe: bool = True


class TraceDiffInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    trace_a: str
    trace_b: str
    max_regions: int = Field(default=20, ge=1, le=100)


@dataclass(frozen=True)
class TraceEntry:
    file: str
    line: int
    op: str
    pc: int | None
    depth: int | None
    func: str | None
    raw: str

    @property
    def signature(self) -> str:
        return f"{self.file}:{self.line}|{self.op}|{self.func or '-'}|d{self.depth or 0}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "op": self.op,
            "pc": self.pc,
            "depth": self.depth,
            "func": self.func,
            "raw": self.raw,
        }


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc


def _target_file(raw: str) -> str:
    """Resolve the traced file and keep it inside the application root."""

    rt = get_runtime()
    root = Path(rt.settings.app_root).resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise _bad(f"Traced file does not exist: {raw}") from exc
    if not resolved.is_relative_to(root):
        raise ToolError(
            ErrorCode.POLICY_DENIED,
            f"Traced file is outside the application root: {resolved}",
            hint=f"Application root: {root}",
        )
    return str(resolved)


def parse_trace(text: str) -> tuple[list[TraceEntry], list[str]]:
    """Parse trace lines; return entries plus the tracer's marker lines."""

    entries: list[TraceEntry] = []
    markers: list[str] = []
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            if raw:
                markers.append(raw)
            continue
        match = _LINE_RE.match(raw)
        if match is None:
            continue
        rest = match.group("rest")
        pc = _PC_RE.search(rest)
        depth = _DEPTH_RE.search(rest)
        func = _FUNC_RE.search(rest)
        entries.append(
            TraceEntry(
                file=match.group("file"),
                line=int(match.group("line")),
                op=match.group("op"),
                pc=int(pc.group(1)) if pc else None,
                depth=int(depth.group(1)) if depth else None,
                func=func.group(1).strip() if func and func.group(1).strip() else None,
                raw=raw,
            )
        )
    return entries, markers


def dedupe_adjacent(entries: list[TraceEntry]) -> list[TraceEntry]:
    """Collapse consecutive entries that describe the same execution point."""

    result: list[TraceEntry] = []
    previous: str | None = None
    for entry in entries:
        signature = entry.signature
        if signature == previous:
            continue
        result.append(entry)
        previous = signature
    return result


def summarize(entries: list[TraceEntry], markers: list[str]) -> dict[str, Any]:
    ops: dict[str, int] = {}
    files: dict[str, int] = {}
    functions: dict[str, int] = {}
    for entry in entries:
        ops[entry.op] = ops.get(entry.op, 0) + 1
        files[entry.file] = files.get(entry.file, 0) + 1
        if entry.func:
            functions[entry.func] = functions.get(entry.func, 0) + 1
    top_ops = sorted(ops.items(), key=lambda item: (-item[1], item[0]))[:10]
    top_functions = sorted(functions.items(), key=lambda item: (-item[1], item[0]))[:10]
    return {
        "entry_count": len(entries),
        "files": files,
        "opcodes": dict(top_ops),
        "functions": dict(top_functions),
        "first": entries[0].to_dict() if entries else None,
        "last": entries[-1].to_dict() if entries else None,
        "markers": markers,
    }


def _trace_dir(case_id: str) -> Path:
    rt = get_runtime()
    return Path(rt.store.path).parent / "traces" / "opcode" / case_id


def _fetch(
    url: str,
    method: str,
    params: dict[str, str],
    body: str | None,
    headers: dict[str, str],
) -> HttpResult:
    rt = get_runtime()
    client = HttpClient()
    return client.fetch(
        method,
        url,
        params=params or None,
        body=body,
        headers=headers or None,
        follow_redirects=False,
        max_bytes=rt.settings.profile.max_http_bytes,
    )


def _method_name(raw: str) -> str:
    method = raw.strip().upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise _bad(f"Unsupported method: {raw}")
    return method


async def trace_run(arguments: dict[str, Any]) -> ToolOutput:
    """Run one request under a directed opcode trace, then bound the result."""

    params = _validate(TraceRunInput, arguments)
    rt = get_runtime()
    require_case(rt.store, params.case_id)
    url = params.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise _bad("url must be an absolute http(s) URL")
    method = _method_name(params.method)
    target = _target_file(params.file)
    if params.line_from and params.line_to and params.line_from > params.line_to:
        raise _bad("line_from must not be greater than line_to")

    adapter = OpcodeTraceAdapter()
    try:
        canonical = adapter.normalize_name(
            params.output or f"trace-{int(time.time() * 1000)}-{params.case_id[-6:]}.log"
        )
    except TraceConfigError as exc:
        raise _bad(str(exc)) from exc
    request = TraceRequest(
        file=target,
        output=canonical,
        line_from=params.line_from,
        line_to=params.line_to,
        function=params.function,
        max_depth=params.max_depth,
        max_lines=params.max_lines,
    )
    try:
        config = adapter.arm(request)
    except TraceConfigError as exc:
        raise ToolError(ErrorCode.ENV_ERROR, str(exc), hint="Check /tmp write access") from exc
    request_params = dict(params.params)
    request_body = params.body
    request_headers = dict(params.headers)
    if method != "GET" and request_body is None and request_params:
        request_body = urlencode(request_params)
        request_params = {}
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    started = time.monotonic()
    try:
        http = _fetch(url, method, request_params, request_body, request_headers)
        text = adapter.read_output(canonical)
    finally:
        adapter.disarm()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if text is None:
        raise ToolError(
            ErrorCode.NOT_FOUND,
            "The tracer produced no output for this request",
            hint=(
                "Check that opcode_tracer is loaded in the target PHP runtime, that the "
                "traced file matches a request-handling script, and that the request "
                "reached that file"
            ),
        )

    entries, markers = parse_trace(text)
    if params.dedupe:
        entries = dedupe_adjacent(entries)
    truncated = bool(markers) or http.truncated
    summary = summarize(entries, markers)
    observed_at = now_iso()
    trace_id = "tr-" + hashlib.sha1(
        f"{params.case_id}|{canonical}|{observed_at}".encode()
    ).hexdigest()[:12]
    directory = _trace_dir(params.case_id)
    directory.mkdir(parents=True, exist_ok=True)
    raw_path = directory / f"{trace_id}.jsonl"
    body_lines = [json.dumps(entry.to_dict(), ensure_ascii=False) for entry in entries]
    raw_path.write_text("\n".join(body_lines) + ("\n" if body_lines else ""), encoding="utf-8")
    rt.store.add_trace(
        trace_id=trace_id,
        case_id=params.case_id,
        file=target,
        line_from=params.line_from,
        line_to=params.line_to,
        function=params.function,
        method=method,
        url=url,
        output=canonical,
        raw_path=str(raw_path),
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        total_lines=len(entries),
        unique_lines=len(entries),
        truncated=truncated,
        summary=summary,
        observed_at=observed_at,
    )
    warnings: list[str] = []
    if truncated:
        warnings.append("TRACE_TRUNCATED")
    if http.status >= 400:
        warnings.append(f"HTTP_STATUS_{http.status}")
    data = {
        "trace_id": trace_id,
        "file": target,
        "line_from": params.line_from,
        "line_to": params.line_to,
        "function": params.function,
        "method": method,
        "url": url,
        "status": http.status,
        "content_type": http.content_type,
        "total_lines": len(entries),
        "truncated": truncated,
        "summary": summary,
        "entries": [entry.to_dict() for entry in entries[: params.max_entries]],
        "config": config,
        "cost_ms": elapsed_ms,
        "observed_at": observed_at,
    }
    return ToolOutput(data=data, warnings=warnings)


def _load_trace_entries(trace_id: str) -> tuple[dict[str, Any], list[TraceEntry]]:
    rt = get_runtime()
    row = rt.store.get_trace(trace_id)
    if row is None:
        raise ToolError(ErrorCode.NOT_FOUND, f"Unknown trace: {trace_id}")
    path = Path(row["raw_path"])
    if not row["raw_path"] or not path.is_file():
        raise ToolError(
            ErrorCode.NOT_FOUND,
            f"Trace payload is gone: {trace_id}",
            hint="Re-run trace_run for this case",
        )
    entries: list[TraceEntry] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(
            TraceEntry(
                file=str(item.get("file", "")),
                line=int(item.get("line", 0)),
                op=str(item.get("op", "")),
                pc=item.get("pc"),
                depth=item.get("depth"),
                func=item.get("func"),
                raw=str(item.get("raw", "")),
            )
        )
    return row, entries


def diff_entries(
    before: list[TraceEntry],
    after: list[TraceEntry],
    max_regions: int = 20,
) -> dict[str, Any]:
    """Diff two traces by execution point (file, line, opcode, function, depth)."""

    a = [entry.signature for entry in before]
    b = [entry.signature for entry in after]
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    regions: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        regions.append(
            {
                "kind": tag,
                "a_start": i1,
                "a_count": i2 - i1,
                "b_start": j1,
                "b_count": j2 - j1,
                "a_sample": [entry.to_dict() for entry in before[i1 : min(i2, i1 + 3)]],
                "b_sample": [entry.to_dict() for entry in after[j1 : min(j2, j1 + 3)]],
            }
        )
    counts = {
        "only_before": sum(1 for entry in a if entry not in b),
        "only_after": sum(1 for entry in b if entry not in a),
        "before_total": len(a),
        "after_total": len(b),
    }
    return {
        "regions": regions[:max_regions],
        "region_count": len(regions),
        "counts": counts,
    }


async def trace_diff(arguments: dict[str, Any]) -> ToolOutput:
    """Compare two recorded traces and report the first diverging regions."""

    params = _validate(TraceDiffInput, arguments)
    rt = get_runtime()
    require_case(rt.store, params.case_id)
    row_a, before = _load_trace_entries(params.trace_a)
    row_b, after = _load_trace_entries(params.trace_b)
    for row in (row_a, row_b):
        if row["case_id"] != params.case_id:
            raise ToolError(
                ErrorCode.CONFLICT,
                f"Trace {row['id']} belongs to another case",
            )
    diff = diff_entries(before, after, params.max_regions)
    warnings: list[str] = []
    if diff["region_count"] > params.max_regions:
        warnings.append("TRACE_DIFF_TRUNCATED")
    data = {
        "trace_a": params.trace_a,
        "trace_b": params.trace_b,
        "file_a": row_a["file"],
        "file_b": row_b["file"],
        "observed_a": row_a["observed_at"],
        "observed_b": row_b["observed_at"],
        **diff,
    }
    return ToolOutput(data=data, warnings=warnings)
