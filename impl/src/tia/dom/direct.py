"""Direct (first-order) agent.

First-order slices name both the input parameter and the sink on one request
path, so the pipeline is the trigger agent's skeleton minus the database: prove
the entry, deliver a payload through the application's own form, and let
``verify_tag`` decide. Delivery, candidate ranking, payload shapes, length
budgeting and the verdict vocabulary are the same pieces the inject and trigger
agents use — this module only sequences them.

Family selection is by slice origin (the navi ``direct/`` tree), never by
inspecting slice features.
"""

from __future__ import annotations

import os
import secrets
import string
from typing import Any
from urllib.parse import urlencode

from tia.ad.llm import LlmClient
from tia.cap.delivery import DeliveryAttempt, deliver
from tia.cap.domscan import parse
from tia.cap.entry import (
    EntryPlan,
    derive_payload_constraints,
    infer_entry,
)
from tia.cap.forms import (
    PageForm,
    find_form,
    forms_from_document,
    forms_from_formparse,
    merge_forms,
)
from tia.dom.trigger import _POST_VAR_RE, StageRecord, TriggerResult, normalize_slice
from tia.inf.reports import write_case_report
from tia.inf.runtime import get_runtime
from tia.inf.settings import attempt_limit
from tia.orch.judge import judge_direct
from tia.orch.kernel import Kernel, LocalToolClient, ToolCallError, ToolClient
from tia.orch.learning import hints_for, record_case


def _attempts() -> int:
    return attempt_limit("direct", 8)


def _tag() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(4))


async def run_direct(
    raw_slice: dict[str, Any],
    *,
    base_url: str,
    payload_base: str = "<script>alert(1)</script>",
    budget: int = 40,
    client: ToolClient | None = None,
    slice_id: str | None = None,
) -> TriggerResult:
    """D0–D6: case, entry, candidates, delivery, verification, report."""
    del payload_base  # shapes come from the observed context, not a template
    raw = normalize_slice(raw_slice)
    kernel = Kernel(
        "inject",  # same capability surface as the trigger/inject agents
        case_id=None,
        budget=budget,
        client=client or LocalToolClient("inject"),
    )
    source_param = _source_param(raw)
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
        return await _finish(kernel, case_id, "NOT_EXECUTED", stages, notes)

    # D1 Source context: the parameter, its method and the sink shape.
    window = await kernel.call("source_read", {"file": file, "around": {"line": line, "n": 40}})
    text = "\n".join(str(item.get("text", "")) for item in window.get("lines", []))
    plan = infer_entry(text)
    post_params = sorted(set(_POST_VAR_RE.findall(text)))
    if source_param and source_param not in post_params:
        post_params.append(source_param)
    notes.update(
        {
            "sink_file": file,
            "sink": f"{file}:{line}",
            "sink_code": sink_code,
            "source_window_sha256": window.get("sha256"),
            "entry_plan": {"method": plan.method, "has_filter": plan.has_filter},
            "params": post_params,
        }
    )
    stages.append(StageRecord("D1", True, f"file={file}:{line} method={plan.method} params={post_params}"))

    # D2 Entry page, parsed by the same ``form_parse`` tool the inject agent uses.
    page = await kernel.call("http_request", {"method": "GET", "url": base_url})
    status = int(page.get("status", 0))
    if status >= 400:
        notes["page_status"] = status
        stages.append(StageRecord("D2", False, f"page status {status}"))
        return await _finish(kernel, case_id, "READ_NOT_REFLECTED", stages, notes)
    body = str(page.get("body", ""))
    parsed = await kernel.call(
        "form_parse", {"html": body, "base_url": base_url, "max_forms": 20}
    )
    doc_forms = forms_from_document(parse(body), base_url)
    forms = merge_forms(doc_forms, forms_from_formparse(parsed.get("forms") or [], base_url))
    param = _pick_param(plan, post_params, forms)
    method = "post" if plan.method.upper() == "POST" else None
    form = find_form(forms, param, method=method) or find_form(forms, param)
    if form is None:
        stages.append(StageRecord("D2", False, "no form on the entry page"))
        return await _finish(kernel, case_id, "NOT_EXECUTED", stages, notes)
    notes["entry"] = {
        "url": form.action,
        "method": form.method,
        "param": param,
        "fields": form.names,
        "csrf_candidates": list(parsed.get("forms") and (parsed["forms"][0].get("csrf_candidates") or [])),
    }
    stages.append(StageRecord("D2", True, f"action={form.action} method={form.method} param={param}"))

    # D3 Length budget through the same ``budget_solve`` tool used elsewhere.
    field = _field_for(form, param)
    maxlength = field.maxlength if field is not None else None
    limits = await kernel.call(
        "budget_solve",
        {"maxlength": maxlength} if maxlength else {"validation_limit": 4096},
    )
    allowed = int(limits.get("max_payload_len") or 0)
    notes["budget"] = {
        "maxlength": maxlength,
        "allowed": allowed,
        "limiting_factor": limits.get("limiting_factor"),
    }
    stages.append(StageRecord("D3", True, f"maxlength={maxlength} allowed={allowed}"))

    # D4 The model plans the request from the page itself; delivery sends it and
    # turns a failed response into the observation for the next round. No local
    # payload shape list and no local field whitelist: both are the model's job.
    tag = _tag()
    hints = hints_for(get_runtime().store, raw)
    notes["learning"] = hints
    constraints = f"max payload length {allowed} characters" if allowed else ""

    async def _send(method: str, values: dict[str, str], files: dict[str, str]) -> dict[str, Any]:
        request: dict[str, Any] = {"method": method, "url": form.action}
        if method == "POST":
            request["body"] = urlencode(values)
            request["headers"] = {"Content-Type": form.enctype}
        else:
            request["params"] = values
        if files:
            request["files"] = files
        result = await kernel.call("http_request", request)
        return {
            "status": result.get("status"),
            "body": str(result.get("body") or ""),
            "content_type": str(result.get("content_type") or "text/html"),
            "probe_hit": False,
        }

    async def _accept(attempt: DeliveryAttempt, page: dict[str, Any]) -> bool:
        verify = await kernel.call(
            "verify_tag",
            {
                "html": attempt.html,
                "content_type": attempt.content_type or "text/html",
                "tag": tag,
                "payload": attempt.payload,
            },
        )
        attempt.extra = {"verify": verify, "shape": _shape_of(attempt.payload, tag)}
        return bool(verify.get("found") and (verify.get("best") or {}).get("executable"))

    delivery = await deliver(
        client=LlmClient.from_env(),
        goal=(
            "submit the form so this page echoes the tag into the sink named above; "
            "the payload must be HTML/JavaScript for a reflected XSS sink (not SQL), "
            "contain the tag verbatim and land in an executable context"
        ),
        page_url=form.action,
        forms=[form],
        html=body,
        source_text=text,
        tag=tag,
        sink=f"{file}:{line}\n{sink_code}",
        payload=tag,
        hint=_HINT,
        constraints=constraints,
        fallback_fields={item.name: item.value for item in form.fields},
        fallback_method=form.method.upper(),
        observation="\n".join(kernel.tool_errors[-3:]),
        max_rounds=_attempts(),
        send=_send,
        accept=_accept,
    )
    notes["delivery"] = {
        "plan": delivery.plan.to_dict() if delivery.plan is not None else None,
        "attempts": [item.to_dict() for item in delivery.attempts],
    }
    attempts = [
        {
            "shape": item.extra.get("shape"),
            "payload": item.payload,
            "delivered": not item.error,
            "status": item.status,
            "found": bool((item.extra.get("verify") or {}).get("found")),
            "executable": bool(((item.extra.get("verify") or {}).get("best") or {}).get("executable")),
            "context_kind": ((item.extra.get("verify") or {}).get("best") or {}).get("context_kind"),
            "verify": item.extra.get("verify"),
            "warnings": item.warnings,
            "error": item.error,
        }
        for item in delivery.attempts
    ]
    notes["attempts"] = attempts
    stages.append(StageRecord("D4", True, f"attempts={len(attempts)}"))

    verdict, explanation = judge_direct(attempts)
    notes["explanation"] = explanation
    stages.append(StageRecord("D5", verdict == "EXECUTED", explanation))
    best = next((item for item in attempts if item.get("executable")), None) or next(
        (item for item in attempts if item.get("found")), None
    )
    if best is not None:
        notes["payload"] = best.get("payload")
        notes["payload_constraints"] = {
            **derive_payload_constraints(
                best.get("verify") or {},
                column=param,
                column_length=maxlength,
                payload=str(best.get("payload") or ""),
            ),
            "field": param,
            "maxlength": maxlength,
        }
    return await _finish(kernel, case_id, verdict, stages, notes)


_HINT = (
    "use the form fields the page shows and any extra field the source expects; "
    "put an HTML/JavaScript (XSS) payload containing the tag in the parameter that "
    "reaches the sink; never a SQL statement"
)


def _shape_of(payload: str, tag: str) -> str:
    lowered = payload.lower()
    if "onerror" in lowered:
        return "img_onerror"
    if "<script" in lowered:
        return "script_tag"
    if "on" in lowered and "=" in lowered:
        return "attr_event"
    if payload == tag:
        return "tag"
    return "custom"


async def _deliver_and_verify(
    kernel: Kernel,
    form: PageForm,
    param: str,
    payload: str,
    candidate: Any,
    tag: str,
    shape: str = "tag",
) -> dict[str, Any]:
    """Fill the form, submit it, and classify the response with ``verify_tag``."""
    values = {item.name: item.value for item in form.fields}
    for key, value in (getattr(candidate, "values", None) or {}).items():
        if key in values:
            values[key] = str(value)
    if param:
        values[param] = payload
    try:
        if form.method == "post":
            response = await kernel.call(
                "http_request",
                {
                    "method": "POST",
                    "url": form.action,
                    "body": urlencode(values),
                    "headers": {"Content-Type": form.enctype},
                },
            )
        else:
            response = await kernel.call(
                "http_request",
                {"method": "GET", "url": form.action, "params": values},
            )
    except ToolCallError as exc:
        body = exc.envelope.error
        return {
            "shape": shape,
            "payload": payload,
            "candidate": getattr(candidate, "basis", None),
            "delivered": False,
            "error": body.code if body else "TOOL_ERROR",
        }
    html = str(response.get("body", ""))
    verify = await kernel.call(
        "verify_tag",
        {
            "html": html,
            "tag": tag,
            "payload": payload,
            "content_type": str(response.get("content_type") or "text/html"),
        },
    )
    best = verify.get("best") if isinstance(verify.get("best"), dict) else {}
    execution = None
    if bool(best.get("executable")):
        try:
            confirmed = await kernel.call(
                "verify_tag",
                {
                    "url": form.action,
                    "tag": tag,
                    "payload": payload,
                    "execute": True,
                    "execute_method": form.method.upper(),
                    "execute_fields": values,
                },
            )
            execution = confirmed.get("execution")
        except ToolCallError:
            execution = None
    return {
        "shape": shape,
        "payload": payload,
        "candidate": getattr(candidate, "basis", None),
        "delivered": True,
        "status": response.get("status"),
        "found": bool(verify.get("found")),
        "occurrences": verify.get("occurrence_count", 0),
        "executable": bool(best.get("executable")),
        "context_kind": best.get("context_kind"),
        "reason": best.get("executable_reason"),
        "node_path": best.get("node_path"),
        "execution": execution,
        "verify": verify,
    }


def _source_param(raw: dict[str, Any]) -> str:
    sources = raw.get("sources")
    if isinstance(sources, list) and sources and isinstance(sources[0], dict):
        return str(sources[0].get("param") or "")
    return ""


def _pick_param(plan: EntryPlan, params: list[str], forms: list[PageForm]) -> str:
    names = {name for form in forms for name in form.names}
    for param in params:
        if param in names:
            return param
    for field in plan.fields:
        if field.name in names:
            return field.name
    return params[0] if params else (plan.fields[0].name if plan.fields else "")


def _field_for(form: PageForm, param: str) -> Any:
    return next((item for item in form.fields if item.name == param), None)


async def _finish(
    kernel: Kernel,
    case_id: str,
    verdict: str,
    stages: list[StageRecord],
    notes: dict[str, Any],
) -> TriggerResult:
    store = get_runtime().store
    store.set_case_verdict(case_id, verdict, ceiling="EXECUTABLE")
    record_case(store, {"sinkFile": str(notes.get("sink_file") or "")}, verdict, notes)
    notes["account"] = os.environ.get("TIA_ACCOUNT") or "anonymous (no login)"
    store.merge_case_notes(case_id, notes)
    report = await kernel.report()
    store.set_case_report(case_id, report)
    write_case_report(store, case_id)
    stages.append(StageRecord("D6", True, "report generated"))
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
