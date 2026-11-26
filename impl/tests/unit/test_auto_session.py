from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from tia.ad import login as login_module
from tia.ad.login import LoginResult, login
from tia.cap import http as http_module
from tia.cap import session as session_module
from tia.inf.accounts import Account
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime

FORM_PAGE = """
<html><body><form method="post" action="/app/login.php">
<input type="text" name="username">
<input type="password" name="password">
<input type="hidden" name="csrf" value="tok">
<button type="submit" name="submit" value="go">Login</button>
</form></body></html>
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings.load(
        "trigger", store_path=tmp_path / "state.db", db_name="tia_test", app_root=tmp_path
    )


def _accounts(tmp_path: Path) -> Path:
    path = tmp_path / "accounts.yaml"
    path.write_text(
        "- label: first\n  base_url: http://x.test/app\n  login_url: http://x.test/app/login.php\n"
        "  username: first-user\n  password: p1\n  roles: []\n  description: first account\n"
        "- label: second\n  base_url: http://x.test/app\n  login_url: http://x.test/app/login.php\n"
        "  username: second-user\n  password: p2\n  roles: [admin]\n  description: admin\n",
        encoding="utf-8",
    )
    return path


def test_login_keeps_cookies_set_on_the_get_login_page(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path.endswith("/login.php"):
            return httpx.Response(
                200, text=FORM_PAGE, headers={"set-cookie": "PRE=1; Path=/app"}
            )
        if request.method == "POST":
            assert request.content and b"username=first-user" in request.content
            return httpx.Response(302, headers={"location": "/app/index.php"})
        return httpx.Response(200, text="<a href='/app/logout.php'>logout</a>")

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client
    monkeypatch.setattr(
        login_module.httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs)
    )
    account = Account(
        label="first",
        base_url="http://x.test/app",
        login_url="http://x.test/app/login.php",
        username="first-user",
        password="p1",
    )
    result = login(account)
    assert result.ok is True
    # The POST response set no cookie; the GET login page did, and it must survive.
    assert result.cookies.get("PRE") == "1"
    assert result.cookies.get("PHPSESSID") is None


def test_ensure_session_reuses_the_first_account(tmp_path, monkeypatch):
    accounts = _accounts(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    monkeypatch.setenv("TIA_ACCOUNT", "")
    configure(_settings(tmp_path))

    calls: list[str] = []

    def fake_login(account: Account, **_: object) -> LoginResult:
        calls.append(account.label)
        return LoginResult(True, 200, "http://x.test/app/index.php", "LOGGED_IN", {"SESSION": account.label})

    monkeypatch.setattr(session_module, "login", fake_login)
    row, warnings = session_module.ensure_session("http://x.test/app/page.php")
    assert warnings == []
    assert row is not None and row["label"] == "first"
    assert row["cookies"] == {"SESSION": "first"}

    again, warnings2 = session_module.ensure_session("http://x.test/app/other.php")
    assert warnings2 == []
    assert again is not None and again["id"] == row["id"]
    assert calls == ["first"]
    reset_runtime()


def test_ensure_session_honours_an_explicit_label(tmp_path, monkeypatch):
    accounts = _accounts(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))
    monkeypatch.setattr(
        session_module,
        "login",
        lambda account, **_: LoginResult(True, 200, "http://x.test/app/i.php", "LOGGED_IN", {"S": account.label}),
    )
    row, _ = session_module.ensure_session("http://x.test/app/page.php", label="second")
    assert row is not None and row["label"] == "second"
    assert row["cookies"] == {"S": "second"}
    reset_runtime()


def test_http_request_attaches_the_default_session(tmp_path, monkeypatch):
    accounts = _accounts(tmp_path)
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))
    monkeypatch.setattr(
        session_module,
        "login",
        lambda account, **_: LoginResult(True, 200, "http://x.test/app/i.php", "LOGGED_IN", {"S": "cookie"}),
    )

    seen: list[dict[str, str]] = []

    def fake_fetch(params, rt, cookies, *, around):  # noqa: ANN001, ANN202
        seen.append(dict(cookies))
        return FakeResult()

    class FakeResult:
        status = 200
        final_url = "http://x.test/app/page.php"
        content_type = "text/html"
        headers: dict[str, str] = {}
        redirect_chain: list[str] = []
        body_bytes = 10
        body = "<p>ok</p>"
        truncated = False

    monkeypatch.setattr(http_module, "_fetch", fake_fetch)
    data = asyncio.run(http_module.http_request({"url": "http://x.test/app/page.php"}))
    assert data.data["session_id"].startswith("sess-")
    assert seen == [{"S": "cookie"}]
    reset_runtime()
