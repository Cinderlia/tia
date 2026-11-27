"""Thinking is a best-effort request: servers that reject it still get answers."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tia.ad.llm import LlmClient


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self.payload = payload
        self.text = str(payload)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=httpx.Request("POST", "http://x"), response=None)  # type: ignore[arg-type]

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeAsyncClient:
    calls: list[dict[str, Any]] = []
    reject: set[str] = set()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> FakeAsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> bool:
        return False

    async def post(self, url: str, json: dict[str, Any] | None = None, headers: Any = None) -> FakeResponse:
        body = dict(json or {})
        FakeAsyncClient.calls.append(body)
        if body.get("reasoning_effort") or (body.get("chat_template_kwargs") or {}).get("enable_thinking"):
            return FakeResponse(400, {"error": "unsupported parameter"})
        return FakeResponse(200, {"choices": [{"message": {"content": '{"ok": true}'}}]})


@pytest.fixture(autouse=True)
def fake_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeAsyncClient.calls = []
    monkeypatch.setattr("tia.ad.llm.httpx.AsyncClient", FakeAsyncClient)


@pytest.mark.asyncio
async def test_thinking_styles_end_with_the_plain_payload() -> None:
    client = LlmClient("http://x/v1", "m", reasoning_effort="low")

    assert client._styles() == [
        {"reasoning_effort": "low", "chat_template_kwargs": {"enable_thinking": True}},
        {"reasoning_effort": "low"},
        {"chat_template_kwargs": {"enable_thinking": False}},
        {},
    ]


@pytest.mark.asyncio
async def test_client_falls_back_and_remembers_the_working_style() -> None:
    client = LlmClient("http://x/v1", "m", reasoning_effort="low")

    first = await client.complete_json("s", "u")

    assert first == {"ok": True}
    assert len(FakeAsyncClient.calls) == 3  # two thinking styles rejected, then the plain one
    assert "reasoning_effort" not in FakeAsyncClient.calls[-1]

    second = await client.complete_json("s", "u")

    assert second == {"ok": True}
    assert len(FakeAsyncClient.calls) == 4  # the remembered style is tried first

    client._style = 0
