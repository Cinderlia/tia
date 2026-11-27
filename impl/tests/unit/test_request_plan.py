"""Request planning: the model proposes a request, local code only validates it."""

from __future__ import annotations

import pytest

from tia.cap.forms import FormField, PageForm
from tia.cap.request_plan import plan_request

pytestmark = pytest.mark.asyncio


class FakeLlm:
    def __init__(self, reply: dict[str, object]) -> None:
        self.reply = reply
        self.calls = 0

    async def complete_json(self, system: str, user: str) -> dict[str, object]:
        self.calls += 1
        return self.reply


def _forms() -> list[PageForm]:
    return [
        PageForm(
            action="http://app.test/file/",
            method="post",
            fields=[
                FormField(name="item"),
                FormField(name="desc"),
                FormField(name="categ"),
                FormField(name="price"),
            ],
            files=["image"],
        )
    ]


async def test_model_plan_is_validated_and_payload_placed() -> None:
    llm = FakeLlm(
        {
            "url": "http://app.test/file/",
            "method": "POST",
            "fields": {"item": "x", "desc": "y", "categ": "c", "price": "1"},
            "payload_field": "desc",
            "payload_field_file": "image",
            "reason": "only the four fields plus a file reach the INSERT",
        }
    )
    plan = await plan_request(
        client=llm,  # type: ignore[arg-type]
        goal="write",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="if ($a != '' && $b != '') { insert ... }",
        payload="<script>alert(1)</script>ab12",
        fallback_fields={"desc": "fallback"},
    )
    assert plan is not None
    assert plan.source == "llm"
    assert plan.payload_field == "desc"
    assert plan.values["desc"] == "<script>alert(1)</script>ab12"
    assert plan.files == {"image": "tia-upload.png"}
    assert llm.calls == 1


async def test_cross_origin_plan_is_rejected() -> None:
    llm = FakeLlm(
        {
            "url": "http://evil.test/steal",
            "method": "POST",
            "fields": {"desc": "x"},
            "payload_field": "desc",
        }
    )
    plan = await plan_request(
        client=llm,  # type: ignore[arg-type]
        goal="write",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="",
        payload="p",
        fallback_fields={"desc": "local"},
    )
    assert plan is not None
    assert plan.source == "rejected"
    assert plan.values == {}
    assert "same-origin" in plan.rejection


async def test_no_model_falls_back_to_filled_fields() -> None:
    plan = await plan_request(
        client=None,
        goal="write",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="",
        payload="p",
        fallback_fields={"item": "tia", "desc": "p"},
    )
    assert plan is not None
    assert plan.source == "local"
    assert plan.values == {"item": "tia", "desc": "p"}
    assert plan.method == "POST"


async def test_unknown_field_is_sent_with_a_warning() -> None:
    llm = FakeLlm(
        {
            "url": "http://app.test/file/",
            "method": "POST",
            "fields": {"desc": "p", "bogus": "z"},
            "payload_field": "desc",
        }
    )
    plan = await plan_request(
        client=llm,  # type: ignore[arg-type]
        goal="write",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="",
        payload="p",
        fallback_fields={"desc": "p"},
    )
    assert plan is not None
    assert plan.source == "llm"
    assert plan.values["desc"] == "p"
    assert plan.values["bogus"] == "z"
    assert any("bogus" in warning for warning in plan.warnings)


async def test_planner_may_pick_a_configured_identity() -> None:
    llm = FakeLlm(
        {
            "url": "http://app.test/file/",
            "method": "POST",
            "fields": {"desc": "tia"},
            "payload_field": "desc",
            "account": "admin",
        }
    )
    accounts = [
        {"label": "customer", "roles": ["customer"], "description": "can post"},
        {"label": "admin", "roles": ["administrator"], "description": "can approve"},
    ]
    plan = await plan_request(
        client=llm,  # type: ignore[arg-type]
        goal="approve",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="",
        payload="<script>alert(1)</script>ab12",
        accounts=accounts,
    )
    assert plan is not None
    assert plan.account == "admin"


async def test_unknown_identity_is_dropped_with_a_warning() -> None:
    llm = FakeLlm(
        {
            "url": "http://app.test/file/",
            "method": "POST",
            "fields": {"desc": "tia"},
            "payload_field": "desc",
            "account": "superuser",
        }
    )
    accounts = [{"label": "customer", "roles": ["customer"], "description": "can post"}]
    plan = await plan_request(
        client=llm,  # type: ignore[arg-type]
        goal="approve",
        page_url="http://app.test/file/",
        forms=_forms(),
        source_text="",
        payload="<script>alert(1)</script>ab12",
        accounts=accounts,
    )
    assert plan is not None
    assert plan.account == ""
    assert any("superuser" in warning for warning in plan.warnings)
