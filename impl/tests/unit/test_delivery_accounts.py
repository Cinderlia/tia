"""Delivery: offer a different identity only after the action actually failed."""

from __future__ import annotations

import pytest

from tia.cap.delivery import deliver, login_gate
from tia.cap.forms import FormField, PageForm

pytestmark = pytest.mark.asyncio

LOGIN_HTML = "<html><form><input type='text' name='user'>" \
             "<input type='password' name='pass'></form></html>"


class FakeLlm:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def complete_json(self, system: str, user: str) -> dict[str, object]:
        self.prompts.append(user)
        return {
            "url": "http://app.test/action",
            "method": "POST",
            "fields": {"entry": "tia", "submit": "1"},
            "payload_field": "entry",
            "account": "",
            "reason": "post the form",
        }


def _forms() -> list[PageForm]:
    return [
        PageForm(
            action="http://app.test/action",
            method="post",
            fields=[FormField(name="entry"), FormField(name="submit")],
        )
    ]


ACCOUNTS = [
    {"label": "customer", "roles": ["customer"], "description": "can post a testimonial"},
    {"label": "admin", "roles": ["administrator"], "description": "can approve a testimonial"},
]


async def test_login_gate_detects_password_form() -> None:
    assert login_gate(200, LOGIN_HTML, "")
    assert login_gate(302, "<html></html>", "http://app.test/login.php")
    assert not login_gate(200, "<html>saved</html>", "http://app.test/action")


async def test_failed_login_page_offers_the_switchable_identities() -> None:
    llm = FakeLlm()
    sent: list[str] = []

    async def send(method: str, values: dict[str, str], files: dict[str, str], account: str) -> dict:
        sent.append(account)
        return {"status": 200, "body": LOGIN_HTML, "content_type": "text/html", "probe_hit": False}

    async def accept(attempt, page) -> bool:  # type: ignore[no-untyped-def]
        return False

    delivery = await deliver(
        client=llm,  # type: ignore[arg-type]
        goal="store a record",
        page_url="http://app.test/action",
        forms=_forms(),
        tag="ab12",
        payload="<script>alert(1)</script>ab12",
        send=send,
        accept=accept,
        accounts=ACCOUNTS,
        max_rounds=2,
    )
    assert delivery.attempts[0].extra.get("login_gate") is True
    assert len(llm.prompts) == 2
    assert "SWITCHABLE USERS" in llm.prompts[0]
    assert "admin" in llm.prompts[0]
    assert "LOGIN GATE" in llm.prompts[1]
    assert sent == ["", "", ""]


async def test_a_normal_result_is_not_treated_as_a_login_gate() -> None:
    llm = FakeLlm()

    async def send(method: str, values: dict[str, str], files: dict[str, str], account: str) -> dict:
        return {"status": 200, "body": "<p>saved</p>", "probe_hit": True}

    async def accept(attempt, page) -> bool:  # type: ignore[no-untyped-def]
        return True

    delivery = await deliver(
        client=llm,  # type: ignore[arg-type]
        goal="store a record",
        page_url="http://app.test/action",
        forms=_forms(),
        tag="ab12",
        payload="<script>alert(1)</script>ab12",
        send=send,
        accept=accept,
        accounts=ACCOUNTS,
        max_rounds=2,
    )
    assert len(delivery.attempts) == 1
    assert "login_gate" not in delivery.attempts[0].extra
    assert len(llm.prompts) == 1
