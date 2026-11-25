"""verdict enum: the closed-set vocabulary of verdicts for each agent.

Note: ``verify_tag`` **does not** return a verdict, only ``verdict_ceiling``; the verdict is
computed by each agent's judge (H5). The three vocabularies are mutually exclusive, and the report specifies the source agent.
"""

from __future__ import annotations

from enum import StrEnum


class TriggerVerdict(StrEnum):
    """The verdict of the trigger agent (Trigger Agent Doc §verdict)."""

    NOT_EXECUTED = "NOT_EXECUTED"
    SQL_ERROR = "SQL_ERROR"
    READ_EMPTY = "READ_EMPTY"
    READ_NOT_REFLECTED = "READ_NOT_REFLECTED"
    REFLECTED_ENCODED = "REFLECTED_ENCODED"
    REFLECTED_INERT = "REFLECTED_INERT"
    REFLECTED_ESCAPED = "REFLECTED_ESCAPED"
    BLOCKED_CSP = "BLOCKED_CSP"
    EXECUTED = "EXECUTED"


class InjectVerdict(StrEnum):
    """The verdict of the injection agent (Injection Agent Doc §I6 tri-state matrix)."""

    BASELINE_DIRTY = "BASELINE_DIRTY"
    PATH_UNREACHABLE = "PATH_UNREACHABLE"
    NO_HTTP_ENTRY = "NO_HTTP_ENTRY"
    ENTRY_AMBIGUOUS = "ENTRY_AMBIGUOUS"
    WRITE_NOT_REACHED = "WRITE_NOT_REACHED"
    CONSTRAINT_UNSAT = "CONSTRAINT_UNSAT"
    UNKNOWN_TRANSFORM = "UNKNOWN_TRANSFORM"
    TYPE_COERCED = "TYPE_COERCED"
    LENGTH_EXCEEDED = "LENGTH_EXCEEDED"
    WRITTEN_NOT_VISIBLE = "WRITTEN_NOT_VISIBLE"
    OUTPUT_FILTERED = "OUTPUT_FILTERED"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"
    EXECUTABLE = "EXECUTABLE"
    ENV_ERROR = "ENV_ERROR"
    AUTH_BLOCKED = "AUTH_BLOCKED"


class MainVerdict(StrEnum):
    """The scheduling conclusion of the main agent; used only for scheduling statistics, never for report security conclusions."""

    ARCHIVED_EXECUTABLE = "ARCHIVED_EXECUTABLE"
    ARCHIVED_FAILED = "ARCHIVED_FAILED"
    HANDOFF_INCOMPLETE = "HANDOFF_INCOMPLETE"
    SKIPPED_BUDGET = "SKIPPED_BUDGET"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"
    SKIPPED_UNREADABLE = "SKIPPED_UNREADABLE"
    BLOCKED_NEEDS_HUMAN = "BLOCKED_NEEDS_HUMAN"


class VerdictCeiling(StrEnum):
    """The upper bound provable by verify_tag, not a security conclusion."""

    EXECUTABLE = "EXECUTABLE"
