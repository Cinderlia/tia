"""Tools requiring no external environment: pure function parsing + local storage queries.

Security conventions (see docs/security.md):
- Treat all input as **data**: no shell concatenation, no ``eval``, no dynamic import;
- Parsing has upper bounds (length/entry count); return BAD_ARGS on excess, no infinite expansion;
- Write paths restricted to ``impl/var/artifacts/<case_id>/`` only, with filename whitelist.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.cap.domscan import Document, parse
from tia.cap.registry import ToolOutput
from tia.cap.verify import analyze
from tia.inf.runtime import get_runtime
from tia.schemas.envelope import ErrorCode, ToolError

MAX_HTML_CHARS = 1_000_000
MAX_TRACE_ITEMS = 2_000
MAX_ARTIFACT_BYTES = 1_048_576
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameters: {exc.errors()[0]['msg']}") from exc


# ---------------------------------------------------------------------------
# form_parse: Statically parse forms in HTML (no requests, no JS execution)
# ---------------------------------------------------------------------------
class FormParseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    html: str = Field(min_length=1, max_length=MAX_HTML_CHARS)
    base_url: str | None = None
    max_forms: int = Field(default=20, ge=1, le=100)


_FIELD_TAGS = {"input", "textarea", "select", "button"}
_SKIP_TYPES = {"submit", "button", "reset", "image"}
_CSRF_HINTS = ("csrf", "token", "authenticity", "xsrf", "_wpnonce", "nonce")


def _walk_children(node: Any) -> list[Any]:
    stack = list(node.children)
    result: list[Any] = []
    while stack:
        child = stack.pop()
        result.append(child)
        stack.extend(child.children)
    result.sort(key=lambda item: item.start)
    return result


def _constraint(attrs: dict[str, str], base_url: str | None) -> dict[str, Any]:
    field: dict[str, Any] = {
        "name": attrs.get("name", ""),
        "type": (attrs.get("type") or "text").lower(),
    }
    for key in ("value", "placeholder", "pattern", "id", "autocomplete"):
        if key in attrs:
            field[key] = attrs[key]
    for key in ("maxlength", "minlength", "size"):
        if key in attrs and attrs[key].strip().isdigit():
            field[key] = int(attrs[key])
    for key in ("required", "readonly", "disabled", "multiple"):
        if key in attrs:
            field[key] = True
    if field["name"].lower() in {"username", "user", "login", "email"}:
        field["looks_like_identity"] = True
    if base_url and attrs.get("src"):
        field["src"] = _join(base_url, attrs["src"])
    return field


def _join(base_url: str, url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    base = base_url.rstrip("/") + "/"
    if url.startswith("/"):
        from urllib.parse import urlsplit

        parts = urlsplit(base_url)
        return f"{parts.scheme}://{parts.netloc}{url}"
    return base + url


def _forms(document: Document, base_url: str | None, max_forms: int) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for index, node in enumerate(document.nodes):
        if node.tag != "form" or len(forms) >= max_forms:
            continue
        action = node.attrs.get("action", "")
        method = (node.attrs.get("method") or "get").lower()
        fields: list[dict[str, Any]] = []
        csrf: list[str] = []
        for child in _walk_children(node):
            if child.tag not in _FIELD_TAGS:
                continue
            attrs = dict(child.attrs)
            if child.tag == "input" and (attrs.get("type") or "").lower() in _SKIP_TYPES:
                continue
            if child.tag == "button":
                continue
            field = _constraint(attrs, base_url)
            if not field["name"]:
                continue
            lowered = field["name"].lower()
            if any(hint in lowered for hint in _CSRF_HINTS):
                csrf.append(field["name"])
            fields.append(field)
        forms.append(
            {
                "index": index,
                "action": _join(base_url, action) if (base_url and action) else action,
                "method": method,
                "enctype": node.attrs.get("enctype", "application/x-www-form-urlencoded"),
                "fields": fields,
                "csrf_candidates": csrf,
                "field_names": [item["name"] for item in fields],
            }
        )
    return forms


async def form_parse(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(FormParseInput, arguments)
    document = parse(params.html)
    forms = _forms(document, params.base_url, params.max_forms)
    truncated = len(forms) >= params.max_forms
    warnings = ["TRUNCATED_FORMS"] if truncated else []
    return ToolOutput(
        data={
            "forms": forms,
            "form_count": len(forms),
            "base_url": params.base_url,
            "note": "Static parsing only; use http_request to fetch rendered DOM first",
        },
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# context_classify: Given HTML and tag, determine context of hit point (offline, pure function)
# ---------------------------------------------------------------------------
class ContextClassifyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    html: str = Field(min_length=1, max_length=MAX_HTML_CHARS)
    tag: str = Field(min_length=1, max_length=64)
    payload: str | None = Field(default=None, max_length=4096)
    content_type: str = "text/html"
    max_occurrences: int = Field(default=10, ge=1, le=50)


async def context_classify(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ContextClassifyInput, arguments)
    result = analyze(
        html=params.html,
        tag=params.tag,
        payload=params.payload,
        content_type=params.content_type,
        headers={},
        status=None,
        max_occurrences=params.max_occurrences,
    )
    return ToolOutput(
        data={
            "found": result.found,
            "contexts": [item.model_dump(mode="json") for item in result.occurrences],
            "best": result.best.model_dump(mode="json") if result.best else None,
            "verdict_ceiling": result.verdict_ceiling,
            "rule_version": result.rule_version,
        },
        warnings=result.warnings,
    )


# ---------------------------------------------------------------------------
# budget_solve: Length budget, pure arithmetic
# ---------------------------------------------------------------------------
class BudgetSolveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    column_length: int | None = Field(default=None, ge=1, le=1_000_000)
    maxlength: int | None = Field(default=None, ge=1, le=1_000_000)
    validation_limit: int | None = Field(default=None, ge=1, le=1_000_000)
    prefix: str = Field(default="", max_length=64)
    suffix: str = Field(default="", max_length=64)
    skeleton: str = Field(default="", max_length=256)
    tag_len: int = Field(default=4, ge=0, le=64)
    encoding: Literal["none", "url", "html"] = "none"


async def budget_solve(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(BudgetSolveInput, arguments)
    limits = {
        "column_length": params.column_length,
        "maxlength": params.maxlength,
        "validation_limit": params.validation_limit,
    }
    present = {key: value for key, value in limits.items() if value is not None}
    if not present:
        raise _bad("Provide at least one length limit: column_length / maxlength / validation_limit")
    limiting, limit = min(present.items(), key=lambda item: item[1])
    overhead = len(params.prefix) + len(params.suffix) + len(params.skeleton) + params.tag_len
    budget = int(limit) - overhead
    fits = budget >= 0
    data: dict[str, Any] = {
        "limit": limit,
        "limiting_factor": limiting,
        "overhead": overhead,
        "max_payload_len": max(budget, 0),
        "fits": fits,
        "all_limits": limits,
        "encoding": params.encoding,
    }
    warnings: list[str] = []
    if not fits:
        warnings.append("LENGTH_EXCEEDED")
        data["hint"] = "Reduce prefix/skeleton, or move tag to suffix"
    if params.encoding != "none":
        data["note"] = "Length expands after encoding; recalculate with actual encoding before submission"
    return ToolOutput(data=data, warnings=warnings)


# ---------------------------------------------------------------------------
# trace_diff: Compare two traces (pure function)
# ---------------------------------------------------------------------------
class TraceDiffInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    before: list[dict[str, Any]] = Field(max_length=MAX_TRACE_ITEMS)
    after: list[dict[str, Any]] = Field(max_length=MAX_TRACE_ITEMS)
    key: str = Field(default="at", min_length=1, max_length=32)
    max_items: int = Field(default=50, ge=1, le=200)


def _key_of(item: dict[str, Any], key: str) -> str:
    return str(item.get(key, ""))


def _changed_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    keys = set(before) | set(after)
    return sorted(key for key in keys if before.get(key) != after.get(key))


async def trace_diff(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(TraceDiffInput, arguments)
    before_map: dict[str, dict[str, Any]] = {}
    for item in params.before:
        before_map[_key_of(item, params.key)] = item
    after_map: dict[str, dict[str, Any]] = {}
    for item in params.after:
        after_map[_key_of(item, params.key)] = item
    added = [item for key, item in after_map.items() if key not in before_map]
    removed = [item for key, item in before_map.items() if key not in after_map]
    changed = [
        {
            "key": key,
            "fields": _changed_fields(before_map[key], after_map[key]),
            "before": before_map[key],
            "after": after_map[key],
        }
        for key in before_map
        if key in after_map and before_map[key] != after_map[key]
    ]
    truncated = any(len(items) > params.max_items for items in (added, removed, changed))
    warnings = ["TRUNCATED"] if truncated else []
    return ToolOutput(
        data={
            "added": added[: params.max_items],
            "removed": removed[: params.max_items],
            "changed": changed[: params.max_items],
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        },
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# flow_lookup: Query local flow library (sqlite, no network)
# ---------------------------------------------------------------------------
class FlowLookupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str | None = None
    base_url: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


async def flow_lookup(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(FlowLookupInput, arguments)
    store = get_runtime().store
    flows = store.list_flows(kind=params.kind, base_url=params.base_url, limit=params.limit)
    return ToolOutput(
        data={
            "flows": flows,
            "count": len(flows),
            "note": "Flow library written only by harness hooks; model reads summaries only",
        },
        warnings=["FLOWS_EMPTY"] if not flows else [],
    )


# ---------------------------------------------------------------------------
# artifact_save: Write artifacts to project directory (path restricted, size restricted)
# ---------------------------------------------------------------------------
class ArtifactSaveInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=64)
    content: str = Field(max_length=MAX_ARTIFACT_BYTES)
    content_type: str = Field(default="text/plain", max_length=128)


async def artifact_save(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(ArtifactSaveInput, arguments)
    if not _SAFE_NAME.match(params.name):
        raise _bad("name allows only alphanumerics and . _ -, and cannot start with .", "e.g. report.md")
    rt = get_runtime()
    if rt.store.get_case(params.case_id) is None:
        raise ToolError(ErrorCode.NOT_FOUND, f"case not found: {params.case_id}")
    raw = params.content.encode("utf-8")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise _bad(f"content exceeds {MAX_ARTIFACT_BYTES} bytes")
    root = (rt.settings.store_path.parent / "artifacts" / params.case_id).resolve()
    target = (root / params.name).resolve()
    if not target.is_relative_to(root):
        raise ToolError(ErrorCode.POLICY_DENIED, "artifact path out of bounds")
    root.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    return ToolOutput(
        data={
            "case_id": params.case_id,
            "name": params.name,
            "path": str(target),
            "bytes": len(raw),
            "sha256": digest,
            "content_type": params.content_type,
        }
    )
