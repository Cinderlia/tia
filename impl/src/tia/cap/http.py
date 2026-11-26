"""Delivery and acceptance: http_request / form_fill.

``form_fill`` is a pure function (no network calls); it only composes the request based on the field order in FlowRecord;
Fields with missing values go into ``missing``; no default values are guessed for the caller.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.ad.http import HttpClient
from tia.cap.registry import ToolOutput
from tia.cap.session import looks_like_login, renew_session, resolve_session
from tia.inf.runtime import get_runtime
from tia.schemas.envelope import ErrorCode, ToolError
from tia.schemas.objects import FlowRecord

MIME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc


class HttpRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str = "GET"
    url: str
    params: dict[str, Any] = Field(default_factory=dict)
    body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    session_id: str | None = None
    account_label: str = ""
    follow_redirects: bool = False
    max_redirects: int = Field(default=5, ge=0, le=10)
    capture: dict[str, Any] | None = None
    #: Multipart file fields: field name -> filename. Content is a small marker.
    files: dict[str, str] = Field(default_factory=dict)


async def _fetch(
    params: HttpRequestInput,
    rt: Any,
    cookies: dict[str, str],
    *,
    around: int,
) -> Any:
    capture = params.capture or {}
    marker = capture.get("marker")
    return HttpClient().fetch(
        params.method.upper(),
        params.url,
        params=params.params or None,
        body=params.body,
        headers=params.headers,
        cookies=cookies,
        follow_redirects=params.follow_redirects,
        max_redirects=params.max_redirects,
        max_bytes=rt.settings.profile.max_http_bytes,
        marker=str(marker) if marker else None,
        around=around,
        files=_file_fields(params.files),
    )


async def http_request(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(HttpRequestInput, arguments)
    rt = get_runtime()
    if not params.url.startswith(("http://", "https://")):
        raise _bad("url must be an absolute http(s) address", "Use http://127.0.0.1/... inside the container")
    method = params.method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "HEAD"}:
        raise _bad(f"Unsupported method: {method}")

    session_id, cookies, warnings = await resolve_session(
        params.session_id, params.url, params.account_label
    )

    capture = params.capture or {}
    result = await _fetch(params, rt, cookies, around=int(capture.get("around", 800)))
    if session_id and looks_like_login(
        result.status, result.headers.get("location", ""), result.body
    ):
        session_id, cookies = await renew_session(session_id)
        warnings.append("SESSION_RENEWED")
        result = await _fetch(params, rt, cookies, around=int(capture.get("around", 800)))
    if result.truncated:
        warnings.append("TRUNCATED")
    data = {
        "status": result.status,
        "final_url": result.final_url,
        "content_type": result.content_type,
        "headers": result.headers,
        "redirect_chain": result.redirect_chain,
        "body_bytes": result.body_bytes,
        "body": result.body,
        "truncated": result.truncated,
        "session_id": session_id,
        "session_after": {"valid": bool(session_id), "renewed": "SESSION_RENEWED" in warnings},
        "observed_at": _now(),
    }
    return ToolOutput(data=data, warnings=warnings)


def _now() -> str:
    from tia.inf.store import now_iso

    return now_iso()


class FormFillInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flow: FlowRecord
    values: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None


async def form_fill(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(FormFillInput, arguments)
    requests: list[dict[str, Any]] = []
    missing: list[str] = []
    for index, step in enumerate(params.flow.steps, start=1):
        merged = dict(step.params)
        merged.update(params.values)
        order = list(step.params_order) or list(merged)
        for name in order:
            if name not in merged:
                missing.append(name)
        request: dict[str, Any] = {
            "step": index,
            "method": step.method,
            "url": step.url,
            "params_order": order,
            "params": {name: merged[name] for name in order if name in merged},
            "headers": {},
        }
        if step.referer:
            request["headers"]["Referer"] = step.referer
        if step.csrf_source:
            request["csrf"] = {"field": step.csrf_source.get("field", ""), "refetched": False}
        requests.append(request)
    return ToolOutput(data={"requests": requests, "missing": sorted(set(missing))})


def _file_fields(files: dict[str, str]) -> dict[str, tuple[str, bytes]] | None:
    """Multipart parts for the upload fields a form advertises.

    The bytes only need to be a valid upload; the interesting value travels in
    the ordinary fields (filename or description depending on the app).
    """
    if not files:
        return None
    parts: dict[str, tuple[str, bytes]] = {}
    for name, filename in files.items():
        if not MIME_OK.match(filename):
            raise _bad(f"Invalid upload filename: {filename!r}")
        parts[name] = (filename, b"tia-upload")
    return parts
