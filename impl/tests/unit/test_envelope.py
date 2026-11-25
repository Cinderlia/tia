"""信封的字段契约（T03 的骨架，后续逐工具补全）。"""

from __future__ import annotations

import json

from tia.schemas.envelope import Envelope, ErrorBody, ErrorCode, ToolError, as_json_value


def test_success_envelope_shape() -> None:
    envelope = Envelope.success(
        tool="verify_tag",
        profile="trigger",
        data={"found": True},
        evidence_refs=["ev://c001/verify/1"],
        cost_ms=3,
    )
    payload = json.loads(envelope.model_dump_json())
    assert payload == {
        "ok": True,
        "tool": "verify_tag",
        "data": {"found": True},
        "evidence_refs": ["ev://c001/verify/1"],
        "cost_ms": 3,
        "profile": "trigger",
        "warnings": [],
        "error": None,
    }


def test_failure_envelope_shape() -> None:
    envelope = Envelope.failure(
        tool="db_write",
        profile="inject",
        error=ErrorBody(code=ErrorCode.POLICY_DENIED, message="write not allowed"),
    )
    payload = json.loads(envelope.model_dump_json())
    assert payload["ok"] is False
    assert payload["error"]["code"] == "POLICY_DENIED"
    assert payload["error"]["retryable"] is False


def test_error_codes_are_closed_set() -> None:
    assert {code.value for code in ErrorCode} == {
        "BAD_ARGS",
        "NOT_FOUND",
        "POLICY_DENIED",
        "SESSION_INVALID",
        "RATE_LIMITED",
        "TIMEOUT",
        "ENV_ERROR",
        "VERSION_MISMATCH",
        "CONFLICT",
        "TRUNCATED",
        "UNSUPPORTED",
        "BUDGET_EXCEEDED",
    }


def test_tool_error_to_body() -> None:
    body = ToolError(
        ErrorCode.BAD_ARGS, "missing tag", retryable=False, hint="提供 tag"
    ).to_body()
    assert body.code is ErrorCode.BAD_ARGS
    assert body.hint == "提供 tag"


def test_as_json_value_normalizes_nested_models() -> None:
    assert as_json_value({"a": [1, 2], "b": None, "c": b"x"}) == {
        "a": [1, 2],
        "b": None,
        "c": "b'x'",
    }
