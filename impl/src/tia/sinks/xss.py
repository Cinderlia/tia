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

    def writes_database(self) -> bool:
        return True

    def observation_channel(self) -> str:
        return "page"

    def channels(self) -> frozenset[str]:
        return frozenset({"page", "browser"})

    def context(self, site: dict[str, Any], code: str) -> str:
        text = code or str(site.get("sink") or "")
        hint = infer_sink_context(text)
        return _CONTEXT_ALIASES.get(hint, hint)

    def shapes(self, context: str) -> list[str]:
        return shapes_for(context)

    def render(self, shape: str, tag: str) -> str:
        return render(shape, tag)

    def seed(
        self,
        site: dict[str, Any],
        context: str,
        tag: str,
        payload_base: str = "",
    ) -> list[tuple[str, str]]:
        """Ordered ``(shape, payload)`` candidates for this sink context."""
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        custom = f"{payload_base}{tag}" if payload_base else ""
        if custom:
            out.append(("custom", custom))
            seen.add(custom)
        for shape in shapes_for(context):
            payload = render(shape, tag)
            if payload and payload not in seen:
                out.append((shape, payload))
                seen.add(payload)
        if not out:
            out.append(("script_tag", f"<script>alert(1)</script>{tag}"))
        return out

    def accept(self, observation: Observation, context: str) -> Outcome:
        """Turn one observation into a class verdict.

        Three channels share the verdict vocabulary:
        ``page`` (trigger verify facts), ``attempts`` (direct deliveries) and
        ``inject`` (the three-state write/read/execute matrix).
        """
        if observation.channel == "attempts":
            return self._accept_attempts(observation)
        if observation.channel == "inject":
            return self._accept_inject(observation)
        return self._accept_verify(observation)

    @staticmethod
    def _execution_state(execution: Any) -> bool | None:
        if not isinstance(execution, dict) or execution.get("error"):
            return None
        executed = execution.get("executed")
        return bool(executed) if isinstance(executed, bool) else None

    def _accept_verify(self, observation: Observation) -> Outcome:
        verify = observation.facts.get("verify")
        evidence = [str(item) for item in (verify.get("evidence_refs") or [])] if isinstance(verify, dict) else []
        if observation.facts.get("written") is False:
            return Outcome(False, "NOT_EXECUTED", "Payload not written to target table; flow did not reach the read point", 20, evidence)
        if not isinstance(verify, dict):
            return Outcome(False, "NOT_EXECUTED", "No verify_tag result", 20)
        if not verify.get("found"):
            return Outcome(False, "READ_NOT_REFLECTED", "Tag written but not found in page; read path did not reflect it", 30, evidence)
        raw_best = verify.get("best")
        best: dict[str, Any] = raw_best if isinstance(raw_best, dict) else {}
        reason = str(best.get("executable_reason") or "")
        state = self._execution_state(verify.get("execution"))
        if best.get("executable"):
            if state is False:
                return Outcome(False, "REFLECTED_INERT", "Static hit, but the payload did not execute when the page was loaded in Chrome", 40, evidence)
            suffix = " (browser-confirmed)" if state else ""
            return Outcome(True, "EXECUTABLE", f"Hit {best.get('context_kind')}, executable ({reason}){suffix}", 90 if state else 70, evidence)
        if reason == "ENCODED_ONLY":
            return Outcome(False, "ENCODED", "Hit is encoded and cannot be restored to an executable marker", 40, evidence)
        if reason in {"CSP_BLOCKED", "SANDBOXED"}:
            return Outcome(False, "BLOCKED_CSP", f"Context reachable but blocked: {reason}", 50, evidence)
        if reason in {"NO_CARRIER", "NEEDS_RUNTIME", "INERT_PAYLOAD", "NEEDS_EXECUTABLE_PAYLOAD"}:
            return Outcome(False, "REFLECTED_INERT", f"Hit but context not executable: {reason}", 40, evidence)
        return Outcome(False, "REFLECTED_INERT", f"Hit but not judged executable: {reason}", 40, evidence)

    def _accept_attempts(self, observation: Observation) -> Outcome:
        attempts = observation.facts.get("attempts")
        if not isinstance(attempts, list) or not attempts:
            return Outcome(False, "NOT_EXECUTED", "No delivery attempt was made", 10)
        executable = [item for item in attempts if isinstance(item, dict) and item.get("executable")]
        if executable:
            best = executable[0]
            state = self._execution_state(best.get("execution"))
            if state is False:
                return Outcome(False, "REFLECTED_INERT", "Static hit, but the payload did not execute when the page was loaded in Chrome", 40)
            suffix = " (browser-confirmed)" if state else ""
            return Outcome(True, "EXECUTABLE", f"Hit {best.get('context_kind')}, executable ({best.get('reason')}){suffix}", 90 if state else 70)
        reflected = [item for item in attempts if isinstance(item, dict) and item.get("found")]
        if not reflected:
            return Outcome(False, "READ_NOT_REFLECTED", "Payload never appeared in the response", 30)
        reasons = {str(item.get("reason")) for item in reflected}
        if "ENCODED_ONLY" in reasons:
            return Outcome(False, "ENCODED", "Hit is encoded and cannot be restored", 40)
        blocked = sorted(reasons & {"CSP_BLOCKED", "SANDBOXED"})
        if blocked:
            return Outcome(False, "BLOCKED_CSP", f"Context reachable but blocked: {blocked[0]}", 50)
        return Outcome(False, "REFLECTED_INERT", "Payload reflected but no shape was executable", 40)

    def _accept_inject(self, observation: Observation) -> Outcome:
        facts = observation.facts
        tag_in_db = bool(facts.get("tag_in_db"))
        tag_in_page = bool(facts.get("tag_in_page"))
        executable = bool(facts.get("executable"))
        if not tag_in_db and not tag_in_page:
            return Outcome(False, "WRITE_NOT_REACHED", "Tag not in DB or page: write path not reached", 20)
        if tag_in_db and not tag_in_page:
            return Outcome(False, "WRITTEN_NOT_VISIBLE", "Write succeeded but not readable on page: read selector or session issue", 40)
        if tag_in_db and tag_in_page and not executable:
            return Outcome(False, "NOT_EXECUTABLE", "Written and reflected, but context not executable", 50)
        if self._execution_state(facts.get("execution")) is False:
            return Outcome(False, "NOT_EXECUTABLE", "Static hit, but the payload did not execute in Chrome", 50)
        return Outcome(True, "EXECUTABLE", "In DB, in page, and context executable", 90)

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
