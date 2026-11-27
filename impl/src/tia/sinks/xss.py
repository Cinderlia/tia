"""XSS plugin: the behaviour that used to be scattered in payloads/verify/judge.

The plugin does not parse pages itself; the ``verify_tag`` capability still
does the DOM work. The plugin only decides *which* observations prove the
sink and how to seed candidate payloads for a context.
"""

from __future__ import annotations

from typing import Any

from tia.cap.payloads import infer_sink_context, render, shapes_for
from tia.sinks.base import Observation, Outcome

#: Context hints we understand today; unknown contexts fall back to html_text.
_CONTEXT_ALIASES = {
    "html": "html_text",
    "text": "html_text",
    "attribute": "attr",
    "script": "script_string",
}


class XssSinkClass:
    name = "xss"
    site_kinds = frozenset({"Xss", "SqlInjection"})

    def channels(self) -> frozenset[str]:
        return frozenset({"page", "browser"})

    def context(self, site: dict[str, Any], code: str) -> str:
        text = code or str(site.get("sink") or "")
        hint = infer_sink_context(text)
        return _CONTEXT_ALIASES.get(hint, hint)

    def seed(self, site: dict[str, Any], context: str, tag: str) -> list[str]:
        payloads: list[str] = []
        for shape in shapes_for(context):
            rendered = render(shape, tag)
            if rendered and rendered not in payloads:
                payloads.append(rendered)
        if not payloads:
            payloads.append(f"<script>alert(1)</script>{tag}")
        return payloads

    def accept(self, observation: Observation, context: str) -> Outcome:
        """Map a ``verify_tag`` observation (plus optional browser execution)."""

        verify = observation.facts.get("verify")
        if not isinstance(verify, dict):
            return Outcome(confirmed=False, level="NO_OBSERVATION", reason="no verify result")
        evidence = [str(item) for item in (verify.get("evidence_refs") or [])]
        raw_best = verify.get("best")
        best: dict[str, Any] = raw_best if isinstance(raw_best, dict) else {}
        executable = bool(best.get("executable"))
        reason = str(best.get("executable_reason") or "")
        found = bool(verify.get("found"))
        execution = observation.facts.get("execution")
        executed: bool | None = None
        if isinstance(execution, dict) and not execution.get("error"):
            executed = bool(execution.get("executed"))
        if executable and executed is False:
            return Outcome(False, "INERT", "did not execute in the browser", 20, evidence)
        if executable:
            confirmed = executed is not False
            return Outcome(
                confirmed=confirmed,
                level="EXECUTABLE" if confirmed else "UNCONFIRMED",
                reason=reason or "executable context",
                confidence=90 if executed else 70,
                evidence_refs=evidence,
                notes={"context_kind": best.get("context_kind")},
            )
        if not found:
            return Outcome(False, "NOT_REFLECTED", "payload did not appear", 30, evidence)
        if str(best.get("match_kind") or "") == "encoded":
            return Outcome(False, "ENCODED", "payload was encoded", 40, evidence)
        return Outcome(False, "INERT", reason or "no executable context", 30, evidence)

    def diagnose(self, observation: Observation, outcome: Outcome) -> list[str]:
        hints: list[str] = []
        if outcome.level == "NOT_REFLECTED":
            hints.append("the payload is not visible on the page; check the read request and the read target")
        elif outcome.level == "ENCODED":
            hints.append("the payload is encoded on output; try a shape that survives the filter")
        elif outcome.level == "INERT":
            hints.append("the payload is inert in this context; adjust quoting/closure for the sink")
        elif outcome.level == "UNCONFIRMED":
            hints.append("the payload looked executable statically but the browser did not run it")
        return hints

    def priority(self, site: dict[str, Any]) -> int:
        code = str(site.get("sink") or site.get("sinkCode") or "")
        return 8 if infer_sink_context(code) in {"attr", "script_string", "script_block"} else 4
