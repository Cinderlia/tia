from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tia.ad.http import HttpResult
from tia.ad.login import LoginResult
from tia.cap import http as http_module
from tia.cap import session as session_module
from tia.inf.accounts import Account
from tia.inf.config import Settings
from tia.inf.runtime import configure, get_runtime, reset_runtime


def _settings(tmp_path: Path) -> Settings:
    return Settings.load(
        "trigger", store_path=tmp_path / "state.db", db_name="tia_test", app_root=tmp_path
    )


def _account_file(tmp_path: Path) -> Path:
    path = tmp_path / "accounts.yaml"
    path.write_text(
        "- label: low\n  base_url: http://x.test/app\n  username: u\n"
        "  password: p\n  roles: []\n  description: low account\n",
        encoding="utf-8",
    )
    return path


def test_looks_like_login_detects_redirect_and_password_form():
    assert session_module.looks_like_login(302, "/bWAPP/login.php", "") is True
    page = "<form method=post action=/login.php><input type=password name=pw></form>"
    assert session_module.looks_like_login(200, "", page) is True
    assert session_module.looks_like_login(200, "", "<a href=logout.php>logout</a>") is False
    assert session_module.looks_like_login(200, "", "<h1>dashboard</h1>") is False


def test_renew_session_replaces_cookies(tmp_path, monkeypatch):
    accounts = _account_file(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))

    store = get_runtime().store
    old = store.add_session(
        label="low", base_url="http://x.test/app", cookies={"PHPSESSID": "old"},
        roles=[], username="u", description="low account", login_url="http://x.test/app/login.php",
    )

    def fake_login(account: Account, **_: object) -> LoginResult:
        return LoginResult(True, 200, "http://x.test/app/index.php", "LOGGED_IN", {"PHPSESSID": "new"})

    monkeypatch.setattr(session_module, "login", fake_login)
    new_id, cookies = asyncio.run(session_module.renew_session(old))
    assert new_id != old
    assert cookies == {"PHPSESSID": "new"}
    assert store.get_session(old)["valid"] is False
    assert store.get_session(new_id)["cookies"] == {"PHPSESSID": "new"}
    reset_runtime()


def test_http_request_renews_once_after_login_page(tmp_path, monkeypatch):
    accounts = _account_file(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))

    store = get_runtime().store
    sid = store.add_session(
        label="low", base_url="http://x.test/app", cookies={"PHPSESSID": "old"},
        roles=[], username="u", description="low account", login_url="http://x.test/app/login.php",
    )

    calls: list[dict[str, str]] = []

    class FakeClient:
        def fetch(self, method, url, **kwargs):  # noqa: ANN001, ANN003
            calls.append(dict(kwargs.get("cookies") or {}))
            if len(calls) == 1:
                return HttpResult(
                    status=200,
                    final_url=url,
                    content_type="text/html",
                    headers={},
                    redirect_chain=[],
                    body_bytes=10,
                    body="<form><input type=password></form>",
                    truncated=False,
                )
            return HttpResult(
                status=200,
                final_url=url,
                content_type="text/html",
                headers={},
                redirect_chain=[],
                body_bytes=9,
                body="dashboard",
                truncated=False,
            )

    monkeypatch.setattr(http_module, "HttpClient", FakeClient)

    def fake_login(account: Account, **_: object) -> LoginResult:
        return LoginResult(True, 200, "http://x.test/app/", "LOGGED_IN", {"PHPSESSID": "new"})

    monkeypatch.setattr(session_module, "login", fake_login)
    result = asyncio.run(
        http_module.http_request(
            {"url": "http://x.test/app/private.php", "session_id": sid, "capture": {"marker": "x"}}
        )
    )
    assert result.data["body"] == "dashboard"
    assert "SESSION_RENEWED" in result.warnings
    assert calls == [{"PHPSESSID": "old"}, {"PHPSESSID": "new"}]
    reset_runtime()


def test_http_request_session_invalid_for_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setenv("TIA_ACCOUNTS", str(_account_file(tmp_path)))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))
    from tia.schemas.envelope import ToolError

    with pytest.raises(ToolError):
        asyncio.run(http_module.http_request({"url": "http://x.test/", "session_id": "nope"}))
    reset_runtime()


def test_verify_tag_reuses_session_cookies(tmp_path, monkeypatch):
    accounts = _account_file(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))

    store = get_runtime().store
    sid = store.add_session(
        label="low", base_url="http://x.test/app", cookies={"PHPSESSID": "old"},
        roles=[], username="u", description="low account", login_url="http://x.test/app/login.php",
    )

    seen: list[dict[str, str]] = []

    async def fake_fetch(input_, cookies=None):  # noqa: ANN001
        seen.append(dict(cookies or {}))
        return "<p>hello tia-tag</p>", "text/html", {}, 200

    from tia.cap import verify as verify_module

    monkeypatch.setattr(verify_module, "_fetch", fake_fetch)
    result = asyncio.run(
        verify_module.verify_tag(
            {"url": "http://x.test/app/page.php", "tag": "tia-tag", "session_id": sid}
        )
    )
    assert seen == [{"PHPSESSID": "old"}]
    assert result.data["found"] is True
    assert "SESSION_NOT_IMPLEMENTED" not in " ".join(result.warnings)
    reset_runtime()
