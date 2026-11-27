"""The class-neutral contract between orchestration and a vulnerability class.

Orchestration (main agent, pairing, delivery loop) never branches on the
vulnerability kind. It asks the class plugin three questions:

* what context does this sink render into (``context``),
* which observation channels can carry evidence (``channels``),
* does this observation prove the sink was reached (``accept``).

``diagnose`` turns a failed observation into hints for the next planning round.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Observation:
    """One normalized observation produced by a capability call."""

    channel: str
    request: dict[str, Any] = field(default_factory=dict)
    payload: str = ""
    marker_seen: bool = False
    facts: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class Outcome:
    """A class-specific verdict plus the evidence that produced it."""

    confirmed: bool
    level: str
    reason: str = ""
    confidence: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)


class SinkClass(Protocol):
    """Minimal plugin surface; keep it small on purpose."""

    name: str
    site_kinds: frozenset[str]

    def channels(self) -> frozenset[str]: ...

    def writes_database(self) -> bool:
        """True when reaching the sink requires a value stored in the database."""
        ...

    def observation_channel(self) -> str:
        """The channel that decides whether the sink was reached."""
        ...

    def context(self, site: dict[str, Any], code: str) -> str: ...

    def shapes(self, context: str) -> list[str]: ...

    def render(self, shape: str, tag: str) -> str: ...

    def seed(
        self, site: dict[str, Any], context: str, tag: str, payload_base: str = ""
    ) -> list[tuple[str, str]]: ...

    def accept(self, observation: Observation, context: str) -> Outcome: ...

    def diagnose(self, observation: Observation, outcome: Outcome) -> list[str]: ...

    def priority(self, site: dict[str, Any]) -> int: ...


_TRIGGER_LEVELS = {
    "NOT_EXECUTED": "NOT_EXECUTED",
    "READ_NOT_REFLECTED": "READ_NOT_REFLECTED",
    "EXECUTED": "EXECUTED",
    "EXECUTABLE": "EXECUTED",
    "REFLECTED_ENCODED": "REFLECTED_ENCODED",
    "ENCODED": "REFLECTED_ENCODED",
    "REFLECTED_INERT": "REFLECTED_INERT",
    "BLOCKED_CSP": "BLOCKED_CSP",
    "SQL_ERROR": "SQL_ERROR",
    "SQLI_CONFIRMED": "EXECUTED",
    "SQLI_NOT_CONFIRMED": "NOT_EXECUTED",
    "NO_DB_OBSERVATION": "NOT_EXECUTED",
    "NOT_CONFIRMED": "NOT_EXECUTED",
}

_INJECT_LEVELS = {
    "WRITE_NOT_REACHED": "WRITE_NOT_REACHED",
    "WRITTEN_NOT_VISIBLE": "WRITTEN_NOT_VISIBLE",
    "NOT_EXECUTABLE": "NOT_EXECUTABLE",
    "EXECUTABLE": "EXECUTABLE",
    "SQLI_CONFIRMED": "EXECUTABLE",
    "NOT_CONFIRMED": "NOT_EXECUTABLE",
    "NO_DB_OBSERVATION": "NOT_EXECUTABLE",
}


def trigger_verdict(outcome: Outcome) -> str:
    """Map a sink-class outcome onto the trigger verdict vocabulary."""
    return _TRIGGER_LEVELS.get(outcome.level, "NOT_EXECUTED")


def inject_verdict(outcome: Outcome) -> str:
    """Map a sink-class outcome onto the inject verdict vocabulary."""
    return _INJECT_LEVELS.get(outcome.level, "NOT_EXECUTABLE")

