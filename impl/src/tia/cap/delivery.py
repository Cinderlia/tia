"""Shared request delivery: plan with the model, send, learn from the response.

Every agent that talks to the application (trigger, inject, direct) needs the
same loop: ask the model for one concrete request that reaches a code path, send
it, and when the page or the probe says it did not work, turn the failure into an
observation and replan within a bounded number of rounds. Keeping this in one
place avoids three slightly different heuristics that drift apart.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from tia.ad.llm import LlmClient
from tia.cap.domscan import echo_snapshot
from tia.cap.forms import PageForm
from tia.cap.request_plan import PlannedRequest, plan_request
from tia.cap.trace import diff_entries
from tia.cap.trace_view import diff_view

_PAGE_ERROR = re.compile(
    r"(fatal error|parse error|warning|error|invalid|required|missing|"
    r"not found|can not|can't|cannot|must be|denied|forbidden)[^<\n]{0,160}",
    re.IGNORECASE,
)

Send = Callable[
    [str, dict[str, str], dict[str, str], str], Awaitable[dict[str, Any]]
]
_LOGIN_FORM = re.compile(r"<input[^>]+type=[\"']?password", re.IGNORECASE)
Accept = Callable[["DeliveryAttempt", dict[str, Any]], Awaitable[bool]]
TraceProbe = Callable[["DeliveryAttempt"], Awaitable[dict[str, Any]]]


@dataclass
class DeliveryAttempt:
    """One request actually sent, with what the server said about it."""

    round: int
    method: str
    url: str = ""
    values: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    payload: str = ""
    status: Any = None
    content_type: str = ""
    html: str = ""
    probe_hit: bool = False
    plan_source: str = "local"
    account: str = ""
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "method": self.method,
            "url": self.url,
            "values": self.values,
            "files": self.files,
            "payload": self.payload,
            "status": self.status,
            "content_type": self.content_type,
            "probe_hit": self.probe_hit,
            "plan_source": self.plan_source,
            "account": self.account,
            "warnings": self.warnings,
            "error": self.error,
            "extra": self.extra,
        }


@dataclass
class Delivery:
    """The last planned request plus every attempt made for it."""

    plan: PlannedRequest | None = None
    attempts: list[DeliveryAttempt] = field(default_factory=list)

    @property
    def last(self) -> DeliveryAttempt | None:
        return self.attempts[-1] if self.attempts else None

    @property
    def payload(self) -> str:
        if self.plan is not None and self.plan.payload:
            return self.plan.payload
        return self.last.payload if self.last else ""

    @property
    def files(self) -> dict[str, str]:
        if self.plan is not None and self.plan.files:
            return dict(self.plan.files)
        return dict(self.last.files) if self.last else {}


def diagnose(html: str, status: Any, probe_hit: bool, tag: str = "") -> str:
    """Summarize why a delivery probably failed, for the next planning round."""

    parts = [f"HTTP {status}"]
    if not probe_hit:
        parts.append("no probe hit: the request never executed the watched statement")
    if tag and tag not in html:
        parts.append("the tag did not appear in the response")
    snippets: list[str] = []
    for match in _PAGE_ERROR.finditer(html or ""):
        text = " ".join(match.group(0).split())
        if text not in snippets:
            snippets.append(text)
        if len(snippets) >= 3:
            break
    if snippets:
        parts.append("page says: " + " | ".join(snippets))
    return "; ".join(parts)


def login_gate(status: Any, html: str, location: str) -> bool:
    """True when the response is a login page instead of the requested action."""
    if isinstance(status, int) and status in {401, 403}:
        return True
    if location and "login" in location.lower():
        return True
    return bool(_LOGIN_FORM.search(html or ""))


def _user_hint(accounts: list[dict[str, Any]] | None) -> str:
    rows = [
        f"- {item.get('label')}: roles={item.get('roles') or []} "
        f"description={item.get('description') or ''}"
        for item in accounts or []
    ]
    return "\n".join(rows)


async def deliver(
    *,
    client: LlmClient | None,
    goal: str,
    page_url: str,
    forms: list[PageForm],
    html: str = "",
    source_text: str = "",
    tag: str = "",
    sink: str = "",
    payload: str = "",
    hint: str = "",
    constraints: str = "",
    fallback_fields: dict[str, str] | None = None,
    fallback_method: str = "POST",
    observation: str = "",
    max_rounds: int = 2,
    send: Send,
    accept: Accept,
    accounts: list[dict[str, Any]] | None = None,
    trace: dict[str, Any] | None = None,
    trace_probe: TraceProbe | None = None,
    schema: str = "",
) -> Delivery:
    """Plan and send a request, replanning with the failure as feedback."""

    delivery = Delivery()
    trace_view: dict[str, Any] | None = trace
    trace_diff: dict[str, Any] | None = None
    baseline_raw: list[Any] | None = None
    rounds = max(1, max_rounds)
    for round_index in range(rounds):
        plan = await plan_request(
            client=client,
            goal=goal,
            page_url=page_url,
            forms=forms,
            source_text=source_text,
            payload=payload or tag,
            hint=hint,
            observation=observation,
            constraints=constraints,
            html=html,
            tag=tag,
            sink=sink,
            fallback_fields=fallback_fields,
            fallback_method=fallback_method,
            accounts=accounts,
            trace=trace_view,
            trace_diff=trace_diff,
            schema=schema,
        )
        if plan is None:
            return delivery
        if plan.source == "rejected":
            observation = f"the local validator rejected that plan: {plan.rejection}"
            continue
        delivery.plan = plan
        values = dict(plan.values)
        if plan.payload_field and plan.payload:
            values[plan.payload_field] = plan.payload
        files = dict(plan.files)
        attempt = DeliveryAttempt(
            round=round_index,
            method=plan.method,
            url=plan.url,
            values=values,
            files=files,
            payload=plan.payload or payload,
            plan_source=plan.source,
            account=plan.account,
            warnings=list(plan.warnings),
        )
        try:
            page = await send(plan.method, values, files, plan.account)
        except Exception as exc:  # noqa: BLE001 - a failed send is just feedback
            attempt.error = f"{type(exc).__name__}: {exc}"
            delivery.attempts.append(attempt)
            observation = attempt.error
            continue
        attempt.status = page.get("status")
        attempt.content_type = str(page.get("content_type") or "")
        attempt.html = str(page.get("body") or page.get("html") or "")
        attempt.probe_hit = bool(page.get("probe_hit"))
        delivery.attempts.append(attempt)
        snapshot = echo_snapshot(attempt.html, tag) if tag and attempt.html else ""
        if snapshot:
            attempt.extra["echo"] = snapshot
            html = snapshot
        try:
            accepted = await accept(attempt, page)
        except Exception as exc:  # noqa: BLE001 - a failed check is feedback too
            attempt.error = f"{type(exc).__name__}: {exc}"
            observation = attempt.error
            continue
        if accepted:
            return delivery
        observation = diagnose(attempt.html, attempt.status, attempt.probe_hit, tag)
        gate = login_gate(
            attempt.status,
            attempt.html,
            str((page.get("location") if isinstance(page, dict) else "") or ""),
        )
        if gate and accounts:
            attempt.extra["login_gate"] = True
            observation += (
                "\n\nLOGIN GATE: the response is a login page or a redirect to one, "
                "so the current user cannot finish this action. Available users:\n"
                f"{_user_hint(accounts)}\n"
                "Set \"account\" to one of these labels if a different identity may "
                "have access; leave it empty to keep the current user."
            )
        if snapshot:
            observation = f"{observation}\n\nECHO AROUND TAG (only the markup wrapping it):\n{snapshot}"
        if trace_probe is not None:
            try:
                probe = await trace_probe(attempt)
            except Exception:  # noqa: BLE001 - trace evidence is optional
                probe = None
            view = (probe or {}).get("slice") or None
            raw = (probe or {}).get("raw") or None
            if view:
                attempt.extra["trace"] = view
                if trace_view is None:
                    trace_view = view
                    baseline_raw = raw
                elif baseline_raw and raw:
                    try:
                        trace_diff = diff_view(
                            diff_entries(baseline_raw, raw, max_regions=8)
                        )
                    except Exception:  # noqa: BLE001
                        trace_diff = None
    last_plan = delivery.plan
    if last_plan is not None and last_plan.payload_field:
        values = {last_plan.payload_field: last_plan.payload or payload}
        attempt = DeliveryAttempt(
            round=rounds,
            method=last_plan.method,
            values=values,
            files=dict(last_plan.files),
            payload=last_plan.payload or payload,
            plan_source="single-field",
        )
        try:
            page = await send(attempt.method, values, attempt.files, last_plan.account)
        except Exception as exc:  # noqa: BLE001
            attempt.error = f"{type(exc).__name__}: {exc}"
            delivery.attempts.append(attempt)
            return delivery
        attempt.status = page.get("status")
        attempt.content_type = str(page.get("content_type") or "")
        attempt.html = str(page.get("body") or page.get("html") or "")
        attempt.probe_hit = bool(page.get("probe_hit"))
        delivery.attempts.append(attempt)
        await accept(attempt, page)
    return delivery
