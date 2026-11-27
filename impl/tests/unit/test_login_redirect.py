"""The login flow must not fail because the landing page is slow."""

from __future__ import annotations

import httpx

from tia.ad import login as login_module
from tia.ad.login import login
from tia.inf.accounts import Account

_LOGIN_PAGE = """
<html><body>
<form name="login" action="/admin/login.php?action=process" method="post">
  <input name="formid" type="hidden" value="token" />
  <input name="username" type="text" />
  <input type="password" name="password" />
  <button name="submit" type="submit" value="1">Log In</button>
</form>
</body></html>
"""


class _Response:
    def __init__(self, url: str, status: int = 200, text: str = "", location: str = "") -> None:
        self.url = httpx.URL(url)
        self.status_code = status
        self.text = text
        self.headers = {"location": location} if location else {}

    @property
    def is_redirect(self) -> bool:
        return self.status_code in {301, 302, 303, 307, 308}


class _FakeClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.cookies: dict[str, str] = {}
        self.posts: list[tuple[str, dict[str, str]]] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, url: str, **kwargs: object) -> _Response:
        if "admin/index.php" in url:
            raise httpx.ReadTimeout("timed out")
        return _Response(url, 200, _LOGIN_PAGE)

    def request(self, method: str, url: str, data: dict[str, str] | None = None, **kw: object) -> _Response:
        self.posts.append((url, data or {}))
        self.cookies["cepcAdminID"] = "abc"
        return _Response(url, 302, location="http://shop.test/admin/index.php")


def test_slow_landing_page_is_not_a_failed_login(monkeypatch) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(login_module.httpx, "Client", lambda *a, **k: fake)
    account = Account(
        label="admin",
        base_url="http://shop.test/admin/",
        login_url="http://shop.test/admin/login.php",
        username="admin",
        password="admin",
    )
    result = login(account, timeout=10)
    assert result.ok is True
    assert result.reason == "LOGGED_IN_TIMEOUT"
    assert result.cookies == {"cepcAdminID": "abc"}
    assert fake.posts and fake.posts[0][1]["username"] == "admin"


def test_redirect_back_to_the_login_page_is_still_rejected(monkeypatch) -> None:
    class _Rejecting(_FakeClient):
        def request(self, method: str, url: str, data: dict[str, str] | None = None, **kw: object) -> _Response:
            return _Response(url, 200, _LOGIN_PAGE)

    fake = _Rejecting()
    monkeypatch.setattr(login_module.httpx, "Client", lambda *a, **k: fake)
    account = Account(
        label="admin",
        base_url="http://shop.test/admin/",
        login_url="http://shop.test/admin/login.php",
        username="admin",
        password="bad",
    )
    result = login(account, timeout=10)
    assert result.ok is False
    assert result.reason == "LOGIN_REJECTED"
