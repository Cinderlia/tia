"""统一信封与错误码。

工具层只返回这两种形态，不向调用方抛异常：

* 成功：``{"ok": true, "tool": "...", "data": {...}, "evidence_refs": [...], ...}``
* 失败：``{"ok": false, "tool": "...", "error": {"code": "...", ...}}``

错误码是闭集；新增错误码必须先改设计文档。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

#: 信封 data 只允许 JSON 结构；深层元素交给各工具自己的 pydantic 模型。
#: 注意：这里刻意不用递归别名——pydantic 2.14 对隐式递归别名会在建 schema 时爆栈，
#: 而 PEP 695 的 ``type`` 语法要求 Python 3.12+（本项目下限 3.11）。
JsonValue: TypeAlias = dict[str, Any] | list[Any] | str | int | float | bool | None


class ErrorCode(StrEnum):
    """错误码闭集（H9）。"""

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
    """工具调用的统一返回。"""

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
    """handler 内部用于表达业务失败；由 registry 统一转信封。"""

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


def as_json_value(value: Any) -> JsonValue:  # noqa: ANN401 - 边界归一化
    """把 handler 的返回值收敛成 JSON 可序列化结构。"""
    if isinstance(value, BaseModel):
        return as_json_value(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): as_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [as_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
