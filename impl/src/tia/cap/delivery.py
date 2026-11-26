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
from tia.cap.forms import PageForm
from tia.cap.request_plan import PlannedRequest, plan_request

_PAGE_ERROR = re.compile(
    r"(fatal error|parse error|warning|error|invalid|required|missing|"
    r"not found|can not|can't|cannot|must be|denied|forbidden)[^<\n]{0,160}",
    re.IGNORECASE,
)

Send = Callable[[str, dict[str, str], dict[str, str]], Awaitable[dict[str, Any]]]
Accept = Callable[["DeliveryAttempt", dict[str, Any]], Awaitable[bool]]


@dataclass
class DeliveryAttempt:
    """One request actually sent, with what the server said about it."""

    round: int
    method: str
    values: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    payload: str = ""
    status: Any = None
    content_type: str = ""
    html: str = ""
    probe_hit: bool = False
    plan_source: str = "local"
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round,
            "method": self.method,
            "values": self.values,
            "files": self.files,
            "payload": self.payload,
            "status": self.status,
            "content_type": self.content_type,
            "probe_hit": self.probe_hit,
            "plan_source": self.plan_source,
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
) -> Delivery:
    """Plan and send a request, replanning with the failure as feedback."""

    delivery = Delivery()
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
            values=values,
            files=files,
            payload=plan.payload or payload,
            plan_source=plan.source,
            warnings=list(plan.warnings),
        )
        try:
            page = await send(plan.method, values, files)
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
        if await accept(attempt, page):
            return delivery
        observation = diagnose(attempt.html, attempt.status, attempt.probe_hit, tag)
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
            page = await send(attempt.method, values, attempt.files)
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
