"""`verify_tag` 判定回归：fixtures 是最小可复现证据集。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tia.cap.verify import analyze

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "verify" / "cases.json"
_CASES: list[dict[str, Any]] = json.loads(_FIXTURES.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_verify_fixture(case: dict[str, Any]) -> None:
    options = case.get("options", {})
    result = analyze(
        case["html"],
        case["tag"],
        payload=options.get("payload"),
        content_type=options.get("content_type", "text/html"),
        headers=options.get("headers"),
        status=options.get("status"),
        max_occurrences=options.get("max_occurrences", 10),
    )
    expect = case["expect"]

    if "found" in expect:
        assert result.found is expect["found"], case["name"]
    if "occurrence_count" in expect:
        assert result.occurrence_count == expect["occurrence_count"], case["name"]
    if "encoded_count" in expect:
        assert result.encoded_count == expect["encoded_count"], case["name"]
    if expect.get("best_is_null"):
        assert result.best is None, case["name"]
    if "context_kind" in expect:
        assert result.best is not None, case["name"]
        assert result.best.context_kind.value == expect["context_kind"], case["name"]
    if "executable" in expect:
        assert result.best is not None, case["name"]
        assert result.best.executable is expect["executable"], case["name"]
    if "reason_prefix" in expect:
        assert result.best is not None, case["name"]
        assert result.best.executable_reason.startswith(expect["reason_prefix"]), case["name"]
    if "quoting" in expect:
        assert result.best is not None, case["name"]
        assert result.best.quoting == expect["quoting"], case["name"]
    warning = expect.get("warning")
    if warning is not None:
        assert any(item.startswith(warning) for item in result.warnings), case["name"]


def test_offline_and_online_share_rule_version() -> None:
    result = analyze("<p>a1b2</p>", "a1b2", payload="<script>x</script>")
    assert result.rule_version == "1.0"
    assert result.verdict_ceiling == "EXECUTABLE"


def test_sha256_and_observed_at_present() -> None:
    result = analyze("<p>a1b2</p>", "a1b2")
    assert len(result.sha256) == 64
    assert result.observed_at.endswith("+08:00") or "T" in result.observed_at


def test_chain_html_is_bounded() -> None:
    filler = "x" * 6000
    html = f"<div><p>{filler}a1b2{filler}</p></div>"
    result = analyze(html, "a1b2")
    assert result.best is not None
    assert result.best.chain_truncated is True
    assert len(result.best.chain_html) <= 4096
