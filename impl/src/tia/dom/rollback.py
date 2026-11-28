"""Failure analysis for stage rollback.

The pipeline records what each stage produced.  When the final check fails,
this module turns the failure into a target stage plus a short, factual
feedback text: the model gets the reason, the local runner gets the stage name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Output contexts that a different payload shape can escape; the request itself
#: stays the same, only the payload written earlier is regenerated.
_ESCAPE_SHAPES: dict[str, str] = {
    "attr": "attr_breakout",
    "script_string": "script_string",
    "script_block": "script_block",
    "comment": "comment_breakout",
}

#: Verdicts that mean "the write path is fine, only the read request needs another
#: look" when the tag is already stored in the database.
_READ_AGAIN = {"WRITTEN_NOT_VISIBLE", "READ_NOT_REFLECTED"}


@dataclass(slots=True)
class FailureReport:
    stage: str
    reason: str
    detail: str = ""
    shape_hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def escape_shape(context_kind: str | None) -> str:
    return _ESCAPE_SHAPES.get(str(context_kind or ""), "")


def classify_inject(result: Any) -> FailureReport | None:
    """Pick the stage to redo for a failed inject case, if one is worth redoing."""
    verdict = str(getattr(result, "verdict", "") or "")
    notes: dict[str, Any] = getattr(result, "notes", None) or {}
    if verdict in {"EXECUTABLE", "EXECUTED"}:
        return None
    context_kind = str(notes.get("context_kind") or "")
    found = bool(notes.get("tag_in_page"))
    executable = bool(notes.get("executable"))
    in_db = bool(notes.get("tag_in_db"))
    if found and not executable and escape_shape(context_kind):
        shape = escape_shape(context_kind)
        return FailureReport(
            stage="inject",
            reason=(
                f"the payload reached the page but landed in {context_kind}, which needs "
                f"a different shape ({shape}); the write path and the read request both work"
            ),
            detail=_feedback(notes),
            shape_hint=shape,
        )
    if in_db and verdict in _READ_AGAIN:
        return FailureReport(
            stage="inject",
            reason=(
                "the payload is stored but the read request did not show it; the write "
                "path is not the problem"
            ),
            detail=_feedback(notes),
        )
    if in_db and not found:
        return FailureReport(
            stage="inject",
            reason="the payload is stored but the read page never rendered it",
            detail=_feedback(notes),
        )
    return None


def _feedback(notes: dict[str, Any]) -> str:
    parts: list[str] = []
    snapshots = notes.get("read_snapshots") or []
    if snapshots:
        last = snapshots[-1]
        snapshot = str(last.get("snapshot") or "") if isinstance(last, dict) else str(last)
        if snapshot:
            parts.append(f"the payload was rendered inside: {snapshot}")
    attempts = notes.get("write_attempts") or []
    if attempts:
        last_attempt = attempts[-1]
        if isinstance(last_attempt, dict):
            for key in ("status", "probe_hit", "error"):
                if last_attempt.get(key) not in (None, ""):
                    parts.append(f"write {key}={last_attempt.get(key)}")
    verify_attempts = notes.get("verify_attempts") or []
    if verify_attempts:
        last_verify = verify_attempts[-1]
        if isinstance(last_verify, dict):
            for key in ("status", "found", "executable", "context_kind", "error"):
                if last_verify.get(key) not in (None, ""):
                    parts.append(f"read {key}={last_verify.get(key)}")
    if notes.get("read_page_error"):
        parts.append(f"read request error: {notes['read_page_error']}")
    if notes.get("execution") is None and notes.get("verify_on"):
        parts.append(f"verification channel: {notes['verify_on']}")
    return "; ".join(parts)
