"""Tool registry: the single source of truth is the design document "Tool Interface Documentation".

Two responsibilities:
1. Declare metadata and schema for 36 tools (``TOOLS``);
2. Filter by profile and unify handler returns/exceptions into an envelope (``dispatch``).

Handlers only write ``tia.cap.*`` / ``tia.ad.*``, loaded lazily via dot-separated paths,
avoiding reverse dependencies from the registry to capability implementations (and import cycles).
"""

from __future__ import annotations

import importlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from tia.schemas.envelope import Envelope, ErrorBody, ErrorCode, JsonValue, ToolError

PROFILES = ("main", "trigger", "inject")

#: 22 tools not registered in the main profile (G1: unregistered means unavailable).
MAIN_EXCLUDED: frozenset[str] = frozenset(
    {
        "probe_arm",
        "probe_run",
        "probe_disarm",
        "write_probe",
        "http_request",
        "http_replay",
        "form_fill",
        "verify_tag",
        "context_classify",
        "canary_calibrate",
        "budget_solve",
        "db_write",
        "db_undo",
        "trace_run",
        "trace_diff",
        "guard_harvest",
        "session_bind",
        "rate_guard",
        "includer_trace",
        "taint_trace",
        "case_open",
        "case_note",
    }
)

#: Handler return: data + evidence references + warnings. The envelope is uniformly wrapped by the registry.
Handler = Callable[[dict[str, Any]], Awaitable["ToolOutput"]]


@dataclass(slots=True)
class ToolOutput:
    data: JsonValue
    evidence_refs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    category: str
    mutating: bool = False
    #: JSON Schema (delivered as-is via MCP tools/list). Detailed constraints are tightened with each tool implementation.
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object"})
    #: Formatted like ``tia.cap.verify:verify_tag``; None indicates not yet implemented.
    handler_path: str | None = None


_SCHEMA = {"type": "object", "additionalProperties": True}


def _t(
    name: str,
    description: str,
    category: str,
    *,
    mutating: bool = False,
    handler_path: str | None = None,
    input_schema: dict[str, Any] | None = None,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        category=category,
        mutating=mutating,
        handler_path=handler_path,
        input_schema=input_schema or _SCHEMA,
    )


_VERIFY_TAG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Online page URL (choose one of url or html)"},
        "html": {"type": "string", "description": "Offline HTML (choose one of url or html)"},
        "tag": {"type": "string", "description": "4-character tag"},
    },
    "required": ["tag"],
    "additionalProperties": False,
}


_FORM_PARSE_SCHEMA = {
    "type": "object",
    "properties": {
        "html": {"type": "string", "description": "Page HTML (static parsing, no requests sent)"},
        "base_url": {"type": "string", "description": "Used to resolve relative actions into absolute addresses"},
        "max_forms": {"type": "integer", "minimum": 1, "maximum": 100},
    },
    "required": ["html"],
    "additionalProperties": False,
}

_CONTEXT_CLASSIFY_SCHEMA = {
    "type": "object",
    "properties": {
        "html": {"type": "string"},
        "tag": {"type": "string"},
        "payload": {"type": "string", "description": "Optional: actual injected content, used for closure/capacity determination"},
        "content_type": {"type": "string"},
        "max_occurrences": {"type": "integer", "minimum": 1, "maximum": 50},
    },
    "required": ["html", "tag"],
    "additionalProperties": False,
}

_BUDGET_SOLVE_SCHEMA = {
    "type": "object",
    "properties": {
        "column_length": {"type": "integer", "minimum": 1},
        "maxlength": {"type": "integer", "minimum": 1},
        "validation_limit": {"type": "integer", "minimum": 1},
        "prefix": {"type": "string"},
        "suffix": {"type": "string"},
        "skeleton": {"type": "string"},
        "tag_len": {"type": "integer", "minimum": 0},
        "encoding": {"type": "string", "enum": ["none", "url", "html"]},
    },
    "additionalProperties": False,
}

_TRACE_RUN_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "url": {"type": "string", "description": "Absolute http(s) URL to request"},
        "file": {"type": "string", "description": "Traced source file (path or suffix)"},
        "line_from": {"type": "integer", "minimum": 0},
        "line_to": {"type": "integer", "minimum": 0},
        "function": {"type": "string", "description": "Keep frames whose function contains it"},
        "targets": {
            "type": "array",
            "maxItems": 16,
            "description": "Trace several files or line ranges in one request",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line_from": {"type": "integer", "minimum": 0},
                    "line_to": {"type": "integer", "minimum": 0},
                    "function": {"type": "string"},
                },
                "required": ["file"],
                "additionalProperties": False,
            },
        },
        "max_depth": {"type": "integer", "minimum": 0},
        "max_lines": {"type": "integer", "minimum": 1, "maximum": 200000},
        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]},
        "params": {"type": "object", "additionalProperties": {"type": "string"}},
        "body": {"type": "string"},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "output": {"type": "string"},
        "max_entries": {"type": "integer", "minimum": 1, "maximum": 300},
        "dedupe": {"type": "boolean"},
    },
    "required": ["case_id", "url"],
    "additionalProperties": False,
}

_TRACE_DIFF_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "trace_a": {"type": "string", "description": "Trace id returned by trace_run"},
        "trace_b": {"type": "string", "description": "Trace id returned by trace_run"},
        "max_regions": {"type": "integer", "minimum": 1, "maximum": 100},
    },
    "required": ["case_id", "trace_a", "trace_b"],
    "additionalProperties": False,
}

_FLOW_LOOKUP_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"type": "string"},
        "base_url": {"type": "string"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
    },
    "additionalProperties": False,
}

_ARTIFACT_SAVE_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "name": {"type": "string", "description": "Filename, whitelist alphanumeric._-"},
        "content": {"type": "string"},
        "content_type": {"type": "string"},
    },
    "required": ["case_id", "name", "content"],
    "additionalProperties": False,
}

_PROBE_ARM_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "file": {"type": "string", "description": "Target PHP file, relative to the application root or absolute"},
        "line": {"type": "integer", "minimum": 1, "description": "Line that issues, sources or reads the query"},
        "targets": {
            "type": "array",
            "maxItems": 16,
            "description": "Several (file, line) targets captured in the same request",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                },
                "required": ["file", "line"],
                "additionalProperties": False,
            },
        },
        "output": {"type": "string", "description": "Plain .json file name; defaults to <case_id>-<line>.json"},
        "match": {
            "type": "string",
            "enum": ["line", "origin", "fetch", "prepare"],
            "description": "Recorded as the caller's expectation; the probe itself reports how it matched",
        },
    },
    "required": ["case_id"],
    "additionalProperties": False,
}

_PROBE_RUN_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "url": {"type": "string"},
        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "HEAD"]},
        "params": {"type": "object"},
        "body": {"type": "string", "description": "Raw request body, e.g. a form-encoded POST"},
        "headers": {"type": "object"},
        "output": {"type": "string", "description": "Read this capture instead of the armed one"},
        "wait_ms": {"type": "integer", "minimum": 0, "maximum": 2000},
    },
    "required": ["case_id", "url"],
    "additionalProperties": False,
}

_PROBE_DISARM_SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "remove_output": {"type": "boolean"},
    },
    "additionalProperties": False,
}

#: 36 tools, order consistent with "Tool Interface Documentation".
_SLICE_NEXT_SCHEMA = {
    "type": "object",
    "properties": {
        "run_id": {"type": "string", "description": "Only lease slices seeded for this run"},
        "ttl_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
        "peek": {
            "type": "boolean",
            "description": "Return ranked slice digests without leasing (planner view)",
        },
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        "slice_id": {"type": "string", "description": "Lease exactly this slice (planner choice)"},
    },
    "additionalProperties": False,
}
_SLICE_ARCHIVE_SCHEMA = {
    "type": "object",
    "properties": {
        "slice_id": {"type": "string"},
        "verdict": {"type": "string"},
        "case_id": {"type": "string"},
        "notes": {"type": "string"},
    },
    "required": ["slice_id", "verdict"],
    "additionalProperties": False,
}
_SLICE_SKIP_SCHEMA = {
    "type": "object",
    "properties": {
        "slice_id": {"type": "string"},
        "reason": {"type": "string"},
        "status": {"type": "string", "enum": ["skipped", "blocked"]},
    },
    "required": ["slice_id", "reason"],
    "additionalProperties": False,
}

TOOLS: tuple[ToolSpec, ...] = (
    # 1. Source code and entry points (7)
    _t("source_read", "Read source code snippet (with context line numbers)", "source", handler_path="tia.cap.source:source_read"),
    _t("source_grep", "Grep source code by regex, returning hit locations and one line of context", "source", handler_path="tia.cap.source:source_grep"),
    _t("taint_trace", "Trace assignment chain from sink back to request variables (bounded)", "source"),
    _t("form_parse", "Parse form fields and HTML5 constraints from page or source code", "source",
       input_schema=_FORM_PARSE_SCHEMA, handler_path="tia.cap.offline:form_parse"),
    _t("endpoint_search", "Search for reachable HTTP entry points by sink file", "source"),
    _t("includer_trace", "Trace include/require chains", "source"),
    _t("filter_analyze", "Analyze filtering and encoding on input/output sides", "source"),
    # 2. Data and Probes (8)
    _t("db_schema", "Read database table schema", "data", handler_path="tia.cap.db:db_schema"),
    _t("db_read", "Read-only SQL query, returning rows and column metadata", "data", handler_path="tia.cap.db:db_read"),
    _t("db_write", "Write to database (must return change_id and undo_sql)", "data", mutating=True, handler_path="tia.cap.db:db_write"),
    _t("db_undo", "Rollback own writes, must have residue==0", "data", mutating=True, handler_path="tia.cap.db:db_undo"),
    _t(
        "probe_arm",
        "Attach collection probes at read/write points",
        "probe",
        mutating=True,
        handler_path="tia.cap.probe:probe_arm",
        input_schema=_PROBE_ARM_SCHEMA,
    ),
    _t(
        "probe_run",
        "Run probe request and retrieve hit SQL and bound parameters",
        "probe",
        mutating=True,
        handler_path="tia.cap.probe:probe_run",
        input_schema=_PROBE_RUN_SCHEMA,
    ),
    _t(
        "probe_disarm",
        "Remove probes",
        "probe",
        mutating=True,
        handler_path="tia.cap.probe:probe_disarm",
        input_schema=_PROBE_DISARM_SCHEMA,
    ),
    _t("write_probe", "Perform before/after diff on target table", "probe", mutating=True),
    # 3. Delivery and Acceptance (7)
    _t("http_request", "Issue single HTTP request (explicit Cookie, no redirect following)", "http", handler_path="tia.cap.http:http_request"),
    _t("form_fill", "Fill form template and generate request chain", "http", mutating=True, handler_path="tia.cap.http:form_fill"),
    _t("http_replay", "Replay request chain under specified session", "http", mutating=True),
    _t("verify_tag",
       "Locate tag in page/HTML, returning occurrence locations, context, and executability limit",
       "verify",
       handler_path="tia.cap.verify:verify_tag",
       input_schema=_VERIFY_TAG_SCHEMA),
    _t("context_classify", "Classify hit context into one of 8 categories", "verify",
       input_schema=_CONTEXT_CLASSIFY_SCHEMA, handler_path="tia.cap.offline:context_classify"),
    _t("canary_calibrate", "Measure write/read transform F=O(W(x)) with canary", "verify", mutating=True),
    _t("budget_solve", "Solve writable length budget and candidate skeletons", "verify",
       input_schema=_BUDGET_SOLVE_SCHEMA, handler_path="tia.cap.offline:budget_solve"),
    # 4. Trace (3)
    _t("trace_run", "Targeted trace with filter (full trace forbidden)", "trace",
       mutating=True, input_schema=_TRACE_RUN_SCHEMA, handler_path="tia.cap.trace:trace_run"),
    _t("trace_diff", "Compare branch differences between two traces", "trace",
       input_schema=_TRACE_DIFF_SCHEMA, handler_path="tia.cap.trace:trace_diff"),
    _t("guard_harvest", "Harvest rejection point candidates from entry files", "trace"),
    # 5. Control and Human Interaction (8)
    _t("case_open", "Create case", "control", mutating=True, handler_path="tia.cap.case:case_open"),
    _t("case_note", "Append evidence note to case", "control", mutating=True, handler_path="tia.cap.case:case_note"),
    _t("case_report", "Generate Markdown report for case", "control", handler_path="tia.cap.case:case_report"),
    _t("session_bind", "Bind valid login session to case", "control", mutating=True),
    _t("human_ask", "Ask human (login, authorization, binary choice)", "control"),
    _t("artifact_save", "Save artifact to project directory", "control",
       input_schema=_ARTIFACT_SAVE_SCHEMA, handler_path="tia.cap.offline:artifact_save"),
    _t("flow_lookup", "Query form templates and known guards in flow library", "control",
       input_schema=_FLOW_LOOKUP_SCHEMA, handler_path="tia.cap.offline:flow_lookup"),
    _t("rate_guard", "Rate limit backoff", "control", mutating=True),
    # 6. Slice (3)
    _t("slice_next", "Lease the next pending slice from the queue", "slice",
       input_schema=_SLICE_NEXT_SCHEMA, handler_path="tia.cap.slice:slice_next"),
    _t("slice_archive", "Archive a finished slice with its verdict", "slice", mutating=True,
       input_schema=_SLICE_ARCHIVE_SCHEMA, handler_path="tia.cap.slice:slice_archive"),
    _t("slice_skip", "Skip a slice and record the reason", "slice", mutating=True,
       input_schema=_SLICE_SKIP_SCHEMA, handler_path="tia.cap.slice:slice_skip"),
)

_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOLS}
if len(_BY_NAME) != 36:  # pragma: no cover - design invariant
    raise RuntimeError(f"Tool count should be 36, actual {len(_BY_NAME)}")


def tools_for_profile(profile: str) -> tuple[ToolSpec, ...]:
    """Return tools distributable by profile; reject unknown profiles directly."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    if profile == "main":
        return tuple(spec for spec in TOOLS if spec.name not in MAIN_EXCLUDED)
    return TOOLS


def tool_names(profile: str) -> tuple[str, ...]:
    return tuple(spec.name for spec in tools_for_profile(profile))


_handler_cache: dict[str, Handler] = {}


def _load_handler(path: str) -> Handler:
    cached = _handler_cache.get(path)
    if cached is not None:
        return cached
    module_name, _, attr = path.partition(":")
    module = importlib.import_module(module_name)
    handler: object = getattr(module, attr)
    if not callable(handler):
        raise RuntimeError(f"handler not callable: {path}")
    loaded = handler
    _handler_cache[path] = loaded
    return loaded


def _failure(
    profile: str, name: str, error: ErrorBody, cost_ms: int
) -> Envelope:
    return Envelope.failure(tool=name, profile=profile, error=error, cost_ms=cost_ms)


async def dispatch(
    profile: str,
    name: str,
    arguments: dict[str, Any] | None,
) -> Envelope:
    """Execute a tool call; any failure converges to an envelope (H9)."""
    started = time.perf_counter()
    spec = _BY_NAME.get(name)
    if spec is None or spec.name not in {s.name for s in tools_for_profile(profile)}:
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.NOT_FOUND,
                message=f"tool {name!r} is not available in profile {profile!r}",
                hint="Check tool name, or confirm if the tool is registered in the current profile",
            ),
            _elapsed_ms(started),
        )
    if spec.handler_path is None:
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.UNSUPPORTED,
                message=f"tool {name!r} not yet implemented",
                retryable=False,
                hint="See implementation order in tia-design-kit/TASKS.md",
            ),
            _elapsed_ms(started),
        )

    handler = _load_handler(spec.handler_path)
    try:
        output = await handler(arguments or {})
    except ToolError as exc:
        return _failure(profile, name, exc.to_body(), _elapsed_ms(started))
    except Exception as exc:  # noqa: BLE001 - boundary: protocol requires no raise
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.ENV_ERROR,
                message=f"{type(exc).__name__}: {exc}",
                retryable=True,
                hint="This is an unexpected exception, check server stderr logs",
            ),
            _elapsed_ms(started),
        )

    return Envelope.success(
        tool=name,
        profile=profile,
        data=output.data,
        evidence_refs=output.evidence_refs,
        warnings=output.warnings,
        cost_ms=_elapsed_ms(started),
    )


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
