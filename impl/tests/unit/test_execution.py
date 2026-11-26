"""Execution confirmation tests: the browser is stubbed, no Chrome is launched."""

from __future__ import annotations

from typing import Any

import pytest

from tia.ad.browser import BrowserExecutor, ExecutionResult
from tia.cap import verify as verify_module
from tia.cap.verify import verify_tag
from tia.orch.judge import judge_trigger

_HTML = "<html><body><p>hello q7z3</p><script>alert('q7z3')</script></body></html>"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch(input_: Any, cookies: Any = None) -> tuple[str, str, dict[str, str], int]:
        return _HTML, "text/html", {}, 200

    monkeypatch.setattr(verify_module, "_fetch", fake_fetch)


def _patch_browser(monkeypatch: pytest.MonkeyPatch, result: ExecutionResult) -> list[str]:
    calls: list[str] = []

    async def run(self: BrowserExecutor, url: str, **kwargs: Any) -> ExecutionResult:
        calls.append(url)
        return result

    monkeypatch.setattr(BrowserExecutor, "run", run)
    return calls


@pytest.mark.asyncio
async def test_verify_tag_adds_execution_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_browser(
        monkeypatch,
        ExecutionResult(executed=True, dialogs=[{"type": "alert", "message": "q7z3"}]),
    )
    out = await verify_tag(
        {"url": "http://example.test/page", "tag": "q7z3", "payload": "<script>alert('q7z3')</script>", "execute": True}
    )
    data = out.data
    assert data["found"] is True
    assert data["execution"]["executed"] is True
    assert calls == ["http://example.test/page"]


@pytest.mark.asyncio
async def test_execute_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_browser(monkeypatch, ExecutionResult(executed=True))
    out = await verify_tag({"url": "http://example.test/page", "tag": "q7z3"})
    assert out.data["execution"] is None
    assert calls == []


@pytest.mark.asyncio
async def test_browser_error_becomes_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_browser(monkeypatch, ExecutionResult(executed=False, error="BROWSER_UNAVAILABLE: no chrome"))
    out = await verify_tag({"url": "http://example.test/page", "tag": "q7z3", "execute": True})
    assert out.data["execution"]["error"].startswith("BROWSER_UNAVAILABLE")
    assert "BROWSER_UNAVAILABLE" in out.data["warnings"]


def test_judge_downgrades_when_browser_did_not_execute() -> None:
    verify = {
        "found": True,
        "best": {"executable": True, "context_kind": "html_text", "executable_reason": "HTML_EXECUTABLE"},
        "execution": {"executed": False, "error": None},
    }
    verdict, reason = judge_trigger(verify=verify, written=True)
    assert verdict.value == "REFLECTED_INERT"
    assert "did not execute" in reason


def test_judge_keeps_executed_when_browser_confirms() -> None:
    verify = {
        "found": True,
        "best": {"executable": True, "context_kind": "html_text", "executable_reason": "HTML_EXECUTABLE"},
        "execution": {"executed": True, "error": None},
    }
    verdict, reason = judge_trigger(verify=verify, written=True)
    assert verdict.value == "EXECUTED"
    assert "browser-confirmed" in reason


def test_judge_ignores_browser_errors() -> None:
    verify = {
        "found": True,
        "best": {"executable": True, "context_kind": "html_text", "executable_reason": "HTML_EXECUTABLE"},
        "execution": {"executed": False, "error": "BROWSER_ERROR: timeout"},
    }
    verdict, _ = judge_trigger(verify=verify, written=True)
    assert verdict.value == "EXECUTED"
