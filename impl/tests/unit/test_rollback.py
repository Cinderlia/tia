"""Failure analysis turns a final verdict into the stage that should be redone."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tia.dom.rollback import classify_inject, escape_shape


@dataclass
class FakeResult:
    verdict: str
    notes: dict[str, Any] = field(default_factory=dict)


def test_attribute_context_rolls_back_the_payload() -> None:
    result = FakeResult(
        "NOT_EXECUTABLE",
        {
            "tag_in_db": True,
            "tag_in_page": True,
            "executable": False,
            "context_kind": "attr",
            "read_snapshots": [{"snapshot": '"><span title="abc123">'}],
            "verify_attempts": [{"found": True, "executable": False, "context_kind": "attr"}],
        },
    )
    report = classify_inject(result)
    assert report is not None
    assert report.stage == "inject"
    assert report.shape_hint == "attr_breakout"
    assert "shape" in report.reason
    assert "abc123" in report.detail


def test_stored_but_invisible_rolls_back_the_read_request() -> None:
    result = FakeResult(
        "WRITTEN_NOT_VISIBLE",
        {"tag_in_db": True, "tag_in_page": False, "executable": False},
    )
    report = classify_inject(result)
    assert report is not None
    assert report.stage == "inject"
    assert report.shape_hint == ""


def test_executable_needs_no_rollback() -> None:
    assert classify_inject(FakeResult("EXECUTABLE", {"tag_in_page": True})) is None


def test_unrelated_failure_is_not_retried() -> None:
    result = FakeResult("ENV_ERROR", {"tag_in_db": False, "tag_in_page": False})
    assert classify_inject(result) is None


def test_escape_shape_is_closed_over_known_contexts() -> None:
    assert escape_shape("attr") == "attr_breakout"
    assert escape_shape("script_string") == "script_string"
    assert escape_shape("html_text") == ""
    assert escape_shape(None) == ""
