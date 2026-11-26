from __future__ import annotations

import json
from pathlib import Path

import pytest

from tia.ad.login import LoginResult, _login_page_is_over, _submit_values, pick_login_form
from tia.cap import session as session_module
from tia.cap.forms import FormField, PageForm
from tia.inf.accounts import (
    Account,
    AccountsConfigError,
    load_accounts,
    pick_account,
)
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime


def _form(*fields: FormField, action: str = "/login.php", method: str = "POST") -> PageForm:
    return PageForm(action=action, method=method, fields=list(fields))


def test_load_accounts_resolves_env_and_description(tmp_path, monkeypatch):
    monkeypatch.setenv("TIA_TEST_PASSWORD", "s3cret")
    path = tmp_path / "accounts.yaml"
    path.write_text(
        "accounts:\n"
        "  - label: low\n"
        "    base_url: http://127.0.0.1/bwapp\n"
        "    login_url: /bwapp/login.php\n"
        "    username: bee\n"
        "    password: env:TIA_TEST_PASSWORD\n"
        "    roles: []\n"
        "    description: default user\n",
        encoding="utf-8",
    )
    accounts = load_accounts(path)
    assert len(accounts) == 1
    assert accounts[0].password == "s3cret"
    assert accounts[0].login_url == "http://127.0.0.1/bwapp/login.php"
    assert "password" not in accounts[0].public()
    assert accounts[0].public()["description"] == "default user"


def test_load_accounts_rejects_empty_env(tmp_path, monkeypatch):
    monkeypatch.delenv("TIA_MISSING_PASSWORD", raising=False)
    path = tmp_path / "accounts.yaml"
    path.write_text(
        "- label: low\n  base_url: http://x.test\n  username: u\n"
        "  password: env:TIA_MISSING_PASSWORD\n",
        encoding="utf-8",
    )
    with pytest.raises(AccountsConfigError):
        load_accounts(path)


def test_pick_account_prefers_least_privilege_then_label():
    low = Account("low", "http://x.test/app", "http://x.test/app/login.php", "u", "p")
    low_admin = Account(
        "low-admin", "http://x.test/app", "http://x.test/app/login.php", "u", "p", ("admin",)
    )
    picks_low = pick_account([low_admin, low], base_url="http://x.test/app")
    assert picks_low is not None and picks_low.label == "low"
    picks_admin = pick_account([low_admin, low], required_roles=["admin"], base_url="http://x.test/app")
    assert picks_admin is not None and picks_admin.label == "low-admin"
    assert pick_account([low], label="nope") is None
    assert pick_account([low], base_url="http://other.test") is None


def test_login_form_heuristics():
    login = _form(
        FormField("username", "text"),
        FormField("password", "password"),
        FormField("submit", "submit"),
    )
    noise = _form(FormField("q", "text"))
    assert pick_login_form([noise, login]) is login

    values = _submit_values(login, "bee", "bug")
    assert values == {"username": "bee", "password": "bug", "submit": ""}

    assert _login_page_is_over("<a href='logout.php'>logout</a>", "http://x.test/") is True
    page = "<form method=post action=/login.php><input name=pw type=password></form>"
    assert _login_page_is_over(page, "http://x.test/") is False


def _settings(tmp_path: Path) -> Settings:
    return Settings.load(
        "trigger",
        store_path=tmp_path / "state.db",
        db_name="tia_test",
        app_root=tmp_path,
    )


def test_session_bind_logs_in_once_and_never_returns_password(tmp_path, monkeypatch):
    accounts = tmp_path / "accounts.yaml"
    accounts.write_text(
        "- label: low\n  base_url: http://x.test/app\n  username: bee\n"
        "  password: literal-secret\n  roles: []\n  description: default\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TIA_ACCOUNTS", str(accounts))
    monkeypatch.setenv("TIA_STORE", str(tmp_path / "state.db"))
    configure(_settings(tmp_path))

    calls: list[str] = []

    def fake_login(account: Account, **_: object) -> LoginResult:
        calls.append(account.label)
        return LoginResult(True, 200, "http://x.test/app/index.php", "LOGGED_IN", {"PHPSESSID": "abc"})

    monkeypatch.setattr(session_module, "login", fake_login)

    import asyncio

    first = asyncio.run(session_module.session_bind({"account_label": "low"}))
    assert first.data["bound"] is True
    assert first.data["session_id"].startswith("sess-")
    assert "literal-secret" not in json.dumps(first.data)
    session_id = first.data["session_id"]

    second = asyncio.run(session_module.session_bind({"account_label": "low"}))
    assert second.data["session_id"] == session_id
    assert second.data["reused"] is True
    assert calls == ["low"]

    catalog = asyncio.run(session_module.session_bind({}))
    assert catalog.data["bound"] is False
    assert catalog.warnings == ["CATALOG_ONLY"]
    assert catalog.data["accounts"][0]["description"] == "default"
    reset_runtime()
