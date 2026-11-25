"""Unified envelope and error codes.

The tool layer returns only these two forms and does not raise exceptions to callers:

* Success: ``{"ok": true, "tool": "...", "data": {...}, "evidence_refs": [...], ...}``
* Failure: ``{"ok": false, "tool": "...", "error": {"code": "...", ...}}``

Error codes form a closed set; new codes require updating the design document first.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

#: Envelope data allows only JSON structures; deep elements are handled by each tool's own pydantic models.
#: Note: Recursive aliases are intentionally avoided—pydantic 2.14 causes stack overflow with implicit recursive aliases during schema construction,
#: and PEP 695's ``type`` syntax requires Python 3.12+ (project minimum is 3.11).
JsonValue: TypeAlias = dict[str, Any] | list[Any] | str | int | float | bool | None


class ErrorCode(StrEnum):
    """Closed set of error codes (H9)."""

    BAD_ARGS = "BAD_ARGS"
    NOT_FOUND = "NOT_FOUND"
    POLICY_DENIED = "POLICY_DENIED"
    SESSION_INVALID = "SESSION_INVALID"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ENV_ERROR = "ENV_ERROR"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    CONFLICT = "CONFLICT"
    TRUNCATED = "TRUNCATED"
    UNSUPPORTED = "UNSUPPORTED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ErrorCode
    message: str
    retryable: bool = False
    hint: str | None = None


class Envelope(BaseModel):
    """Unified return type for tool calls."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    tool: str
    data: JsonValue = None
    evidence_refs: list[str] = Field(default_factory=list)
    cost_ms: int = 0
    profile: str
    warnings: list[str] = Field(default_factory=list)
    error: ErrorBody | None = None

    @classmethod
    def success(
        cls,
        *,
        tool: str,
        profile: str,
        data: JsonValue = None,
        evidence_refs: list[str] | None = None,
        cost_ms: int = 0,
        warnings: list[str] | None = None,
    ) -> Envelope:
        return cls(
            ok=True,
            tool=tool,
            profile=profile,
            data=data,
            evidence_refs=evidence_refs or [],
            cost_ms=cost_ms,
            warnings=warnings or [],
        )

    @classmethod
    def failure(
        cls,
        *,
        tool: str,
        profile: str,
        error: ErrorBody,
        cost_ms: int = 0,
        evidence_refs: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> Envelope:
        return cls(
            ok=False,
            tool=tool,
            profile=profile,
            cost_ms=cost_ms,
            evidence_refs=evidence_refs or [],
            warnings=warnings or [],
            error=error,
        )


class ToolError(Exception):
    """Internal to handlers for expressing business failures; converted to envelope by the registry."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        retryable: bool = False,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.hint = hint

    def to_body(self) -> ErrorBody:
        return ErrorBody(
            code=self.code,
            message=self.message,
            retryable=self.retryable,
            hint=self.hint,
        )


def as_json_value(value: Any) -> JsonValue:  # noqa: ANN401 - boundary normalization
    """Converges handler return values into JSON-serializable structures."""
    if isinstance(value, BaseModel):
        return as_json_value(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): as_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [as_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
