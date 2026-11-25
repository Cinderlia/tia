"""judge: Translate facts returned by tools into agent verdicts.

Pure rules, no IO, unit-testable. ``verify_tag`` only provides facts (found/best/verdict_ceiling),
verdicts are made here—this is the landing point for H5.
"""

from __future__ import annotations

from typing import Any

from tia.schemas.verdict import TriggerVerdict


def judge_trigger(
    *,
    verify: dict[str, Any] | None,
    written: bool,
    db_error: str | None = None,
) -> tuple[TriggerVerdict, str]:
    """Trigger agent verdicts (starting from "whether the payload reached the sink and executed")."""
    if db_error:
        return TriggerVerdict.SQL_ERROR, f"Write phase failed: {db_error}"
    if not written:
        return TriggerVerdict.NOT_EXECUTED, "Payload not written to target table; flow did not reach the read point"
    if verify is None:
        return TriggerVerdict.NOT_EXECUTED, "No verify_tag result"

    if not verify.get("found"):
        return TriggerVerdict.READ_NOT_REFLECTED, "Tag written but not found in page; read path did not reflect it"
    best = verify.get("best") or {}
    if best.get("executable"):
        return TriggerVerdict.EXECUTED, f"Hit {best.get('context_kind')}, executable ({best.get('executable_reason')})"

    reason = str(best.get("executable_reason", ""))
    if reason == "ENCODED_ONLY":
        return TriggerVerdict.REFLECTED_ENCODED, "Hit is encoded and cannot be restored to an executable marker"
    if reason in {"CSP_BLOCKED", "SANDBOXED"}:
        return TriggerVerdict.BLOCKED_CSP, f"Context reachable but blocked: {reason}"
    if reason in {"NO_CARRIER", "NEEDS_RUNTIME", "INERT_PAYLOAD", "NEEDS_EXECUTABLE_PAYLOAD"}:
        return TriggerVerdict.REFLECTED_INERT, f"Hit but context not executable: {reason}"
    return TriggerVerdict.REFLECTED_INERT, f"Hit but not judged executable: {reason}"


def judge_inject(
    tag_in_db: bool, tag_in_page: bool, executable: bool
) -> tuple[str, str]:
    """Three-state matrix (in DB / in page / executable) → inject verdict."""
    if not tag_in_db and not tag_in_page:
        return "WRITE_NOT_REACHED", "Tag not in DB or page: write path not reached"
    if tag_in_db and not tag_in_page:
        return "WRITTEN_NOT_VISIBLE", "Write succeeded but not readable on page: read selector or session issue"
    if tag_in_db and tag_in_page and not executable:
        return "NOT_EXECUTABLE", "Written and reflected, but context not executable"
    return "EXECUTABLE", "In DB, in page, and context executable"
