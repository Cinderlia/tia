from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tia.ad.login import LoginResult
from tia.cap import session as session_module
from tia.cap.session import login_account
from tia.inf.accounts import Account
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime


def _account() -> Account:
    return Account(
        label="first",
        base_url="http://x.test/app",
        login_url="http://x.test/app/login.php",
        username="first-user",
        password="p1",
    )


@pytest.fixture()
def runtime(tmp_path: Path):
    configure(
        Settings.load(
            "trigger", store_path=tmp_path / "state.db", db_name="tia_test", app_root=tmp_path
        )
    )
    yield
    reset_runtime()


def _patch(monkeypatch, http_results, browser_results):
    calls = {"http": 0, "browser": 0}

    def fake_http(account):
        calls["http"] += 1
        return http_results[min(calls["http"] - 1, len(http_results) - 1)]

    async def fake_browser(account, **_kwargs):
        calls["browser"] += 1
        return browser_results[min(calls["browser"] - 1, len(browser_results) - 1)]

    monkeypatch.setattr(session_module, "login", fake_http)
    monkeypatch.setattr(session_module, "browser_login", fake_browser)
    return calls


def test_browser_takes_over_after_two_http_failures(monkeypatch, runtime):
    calls = _patch(
        monkeypatch,
        http_results=[LoginResult(ok=False, reason="LOGIN_REJECTED")],
        browser_results=[LoginResult(ok=True, cookies={"SID": "b1"}, via="browser")],
    )
    first = asyncio.run(login_account(_account()))
    assert first.ok is False
    assert calls == {"http": 1, "browser": 0}

    second = asyncio.run(login_account(_account()))
    assert second.ok is True
    assert second.via == "browser"
    assert calls == {"http": 2, "browser": 1}

    # A success resets the counter, so the next run starts over HTTP again.
    asyncio.run(login_account(_account()))
    assert calls == {"http": 3, "browser": 1}


def test_http_success_never_starts_the_browser(monkeypatch, runtime):
    calls = _patch(
        monkeypatch,
        http_results=[LoginResult(ok=True, cookies={"SID": "h1"})],
        browser_results=[LoginResult(ok=True, cookies={"SID": "b1"}, via="browser")],
    )
    result = asyncio.run(login_account(_account()))
    assert result.ok is True
    assert result.via == "http"
    assert calls == {"http": 1, "browser": 0}


def test_forced_browser_path(monkeypatch, runtime):
    calls = _patch(
        monkeypatch,
        http_results=[LoginResult(ok=True, cookies={"SID": "h1"})],
        browser_results=[LoginResult(ok=True, cookies={"SID": "b1"}, via="browser")],
    )
    result = asyncio.run(login_account(_account(), force_browser=True))
    assert result.via == "browser"
    assert calls == {"http": 0, "browser": 1}


def test_missing_browser_keeps_the_http_failure_reason(monkeypatch, runtime):
    calls = _patch(
        monkeypatch,
        http_results=[LoginResult(ok=False, reason="LOGIN_REJECTED")],
        browser_results=[LoginResult(ok=False, reason="BROWSER_UNAVAILABLE: no Chrome")],
    )
    asyncio.run(login_account(_account()))
    result = asyncio.run(login_account(_account()))
    assert result.ok is False
    assert result.reason == "LOGIN_REJECTED"
    assert calls["browser"] == 1
