"""One-line log of every tool call, one file per case, switched on with ``TIA_TOOL_LOG``.

The database trace is good for machines; a person watching a run wants a file
they can read straight through. When the switch is on, the registry appends one
line per call with the time, the agent, the tool, the arguments and the first
few characters of the result. The kernel marks the current case, so each case
gets its own file (``<dir>/<case_id>.log``) even though every agent shares the
same dispatch path. The switch is off by default.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

CALL_LOG_ENV = "TIA_TOOL_LOG"
PREVIEW_CHARS = 40
ARGS_CHARS = 500
NO_CASE = "no-case"
_OFF = {"", "0", "off", "false", "no"}
_ON = {"1", "on", "true", "yes"}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_LOCK = threading.Lock()

CURRENT_CASE: ContextVar[str] = ContextVar("tia_current_case", default="")


@contextmanager
def case_scope(case_id: str | None) -> Iterator[None]:
    """Mark every tool call made inside the block as belonging to ``case_id``."""

    token = CURRENT_CASE.set(case_id or "")
    try:
        yield
    finally:
        CURRENT_CASE.reset(token)


def _base_dir() -> Path | None:
    raw = os.environ.get(CALL_LOG_ENV, "").strip()
    if raw.lower() in _OFF:
        return None
    if raw.lower() in _ON:
        return Path.cwd() / "tool-calls"
    return Path(raw).expanduser()


def log_path(case_id: str | None = None) -> Path | None:
    base = _base_dir()
    if base is None:
        return None
    case = _UNSAFE.sub("-", (case_id or CURRENT_CASE.get() or NO_CASE)).strip("-") or NO_CASE
    return base / f"{case}.log"


def _preview(value: Any, limit: int = PREVIEW_CHARS) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    text = " ".join(text.split())
    return text[:limit] if text else "(empty)"


def _arguments(arguments: dict[str, Any] | None, limit: int = ARGS_CHARS) -> str:
    text = json.dumps(arguments or {}, ensure_ascii=False, default=str, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def log_call(
    *,
    agent: str,
    tool: str,
    ok: bool,
    arguments: dict[str, Any] | None,
    data: Any = None,
    error: Any = None,
    observed_at: str = "",
) -> Path | None:
    """Append one call to the current case's log; never raises."""

    try:
        path = log_path()
        if path is None:
            return None
        detail = data if ok else (error if error is not None else "failed")
        stamp = observed_at or _now()
        line = (
            f"{stamp} agent={agent} tool={tool} ok={'true' if ok else 'false'} "
            f"args={_arguments(arguments)} result={_preview(detail)}\n"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK, path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return path
    except Exception:  # noqa: BLE001 - logging must never break a tool call
        return None


def _now() -> str:
    from tia.inf.store import now_iso

    return now_iso()
