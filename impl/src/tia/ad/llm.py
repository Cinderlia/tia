"""Minimal OpenAI-compatible JSON client for best-effort model guesses.

The agents prefer evidence: values are derived from source constraints and the
row the agent itself wrote. When a parameter cannot be derived, a model guess
is allowed and encouraged -- it is recorded as a guess and the subsequent
execution (probe / verify_tag) decides whether it was right. The client is
disabled unless the environment provides an endpoint, and every failure
degrades to "no guess" instead of raising.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

_LOG = logging.getLogger(__name__)


class LlmClient:
    """Small chat-completions wrapper that only ever returns a JSON object."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        max_tokens: int = 512,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens

    @classmethod
    def from_env(cls) -> LlmClient | None:
        """Build a client from ``TIA_LLM_*``; return None when unconfigured."""
        base = os.environ.get("TIA_LLM_BASE", "").strip()
        model = os.environ.get("TIA_LLM_MODEL", "").strip()
        if not base or not model:
            return None
        return cls(base, model, os.environ.get("TIA_LLM_KEY") or None)

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Ask for one JSON object; return ``{}`` on any transport/parse failure."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
                response.raise_for_status()
                body = response.json()
            text = str(body["choices"][0]["message"]["content"] or "")
            return _parse_object(text)
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            _LOG.debug("llm guess skipped: %s", exc)
            return {}


def _parse_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from a model reply, fenced or bare."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```")[1] if "```" in stripped[3:] else stripped[3:]
        stripped = stripped.removeprefix("json").strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        value = json.loads(stripped[start : end + 1])
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
