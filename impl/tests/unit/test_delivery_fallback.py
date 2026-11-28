"""Delivery: an unusable model plan still produces one local attempt."""

from __future__ import annotations

import pytest

from tia.cap.delivery import deliver
from tia.cap.forms import FormField, PageForm

pytestmark = pytest.mark.asyncio


class UnusableLlm:
    def __init__(self) -> None:
        self.calls = 0

    async def complete_json(self, system: str, user: str) -> dict[str, object]:
        self.calls += 1
        return {"url": "", "method": "POST", "fields": {}, "reason": "nothing"}


def _forms() -> list[PageForm]:
    return [
        PageForm(
            action="http://app.test/action",
            method="post",
            fields=[FormField(name="item")],
        )
    ]


async def test_rejected_plan_falls_back_to_one_local_request() -> None:
    llm = UnusableLlm()
    sent: list[dict[str, str]] = []

    async def send(
        method: str,
        values: dict[str, str],
        files: dict[str, str],
        account: str,
        url: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict:
        sent.append(values)
        return {"status": 200, "body": "<html>ok</html>", "content_type": "text/html"}

    async def accept(attempt, page) -> bool:  # type: ignore[no-untyped-def]
        return False

    delivery = await deliver(
        client=llm,  # type: ignore[arg-type]
        goal="reach the page",
        page_url="http://app.test/action",
        forms=_forms(),
        tag="ab12",
        payload="<script>ab12</script>",
        fallback_fields={"item": ""},
        max_rounds=2,
        send=send,
        accept=accept,
    )

    assert llm.calls == 2
    assert sent == [{"item": ""}]
    assert len(delivery.attempts) == 1
    assert delivery.attempts[0].plan_source == "local_fallback"
