"""judge: Translate facts returned by tools into agent verdicts.

Pure rules, no IO, unit-testable. ``verify_tag`` only provides facts (found/best/verdict_ceiling),
verdicts are made here—this is the landing point for H5.
"""

from __future__ import annotations

from typing import Any

from tia.schemas.verdict import TriggerVerdict
from tia.sinks.base import Observation, inject_verdict, trigger_verdict
from tia.sinks.xss import XssSinkClass


def _execution_state(execution: Any) -> bool | None:
    """True/False when the browser actually ran the page, None when it did not run.

    ``execution`` comes from ``verify_tag(execute=true)``. A browser error is not
    evidence either way, so it yields None and static judgment stands.
    """
    if not isinstance(execution, dict) or execution.get("error"):
        return None
    executed = execution.get("executed")
    return bool(executed) if isinstance(executed, bool) else None


def judge_trigger(
    *,
    verify: dict[str, Any] | None,
    written: bool,
    db_error: str | None = None,
) -> tuple[TriggerVerdict, str]:
    """Trigger verdict, delegated to the sink class for this vulnerability."""
    if db_error:
        return TriggerVerdict.SQL_ERROR, f"Write phase failed: {db_error}"
    outcome = XssSinkClass().accept(
        Observation(
            channel="page",
            marker_seen=bool(verify and verify.get("found")),
            facts={"verify": verify, "written": written},
        ),
        context="",
    )
    return TriggerVerdict(trigger_verdict(outcome)), outcome.reason


def judge_direct(attempts: list[dict[str, Any]]) -> tuple[TriggerVerdict, str]:
    """Direct verdict; the sink class reads the bounded delivery attempts."""
    outcome = XssSinkClass().accept(
        Observation(channel="attempts", facts={"attempts": attempts}), context=""
    )
    return TriggerVerdict(trigger_verdict(outcome)), outcome.reason


def judge_inject(
    tag_in_db: bool,
    tag_in_page: bool,
    executable: bool,
    execution: Any = None,
) -> tuple[str, str]:
    """Three-state matrix (in DB / in page / executable) -> inject verdict."""
    outcome = XssSinkClass().accept(
        Observation(
            channel="inject",
            facts={
                "tag_in_db": tag_in_db,
                "tag_in_page": tag_in_page,
                "executable": executable,
                "execution": execution,
            },
        ),
        context="",
    )
    return inject_verdict(outcome), outcome.reason
