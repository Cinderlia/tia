"""Minimal OpenAI-compatible JSON client for best-effort model guesses.

The agents prefer evidence: values are derived from source constraints and the
row the agent itself wrote. When a parameter cannot be derived, a model guess
is allowed and encouraged -- it is recorded as a guess and the subsequent
execution (probe / verify_tag) decides whether it was right. The client is
disabled unless the environment provides an endpoint, and every failure
degrades to "no guess" instead of raising.

Thinking is opt-in per profile (``reasoning_effort``), but there is no single
way to ask for it: OpenAI-style endpoints take ``reasoning_effort``, Qwen-style
servers take ``chat_template_kwargs.enable_thinking``, and older servers reject
both. The client therefore tries the richest style first, remembers the one
that worked, and silently falls back for models that do not accept it.
"""

from __future__ import annotations

import json
import logging
import os
import time
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
        enable_thinking: bool = False,
        reasoning_effort: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.enable_thinking = enable_thinking
        self.reasoning_effort = reasoning_effort.strip()
        # Index into ``_styles()`` that the endpoint last accepted, so a model
        # that rejects the richer payloads is only probed once per client.
        self._style: int | None = None

    def _styles(self) -> list[dict[str, Any]]:
        """Thinking request shapes, richest first, ending with the plain one."""
        styles: list[dict[str, Any]] = []
        if self.reasoning_effort:
            styles.append(
                {
                    "reasoning_effort": self.reasoning_effort,
                    "chat_template_kwargs": {"enable_thinking": True},
                }
            )
            styles.append({"reasoning_effort": self.reasoning_effort})
        styles.append({"chat_template_kwargs": {"enable_thinking": self.enable_thinking}})
        styles.append({})
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for style in styles:
            key = json.dumps(style, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(style)
        return unique

    @classmethod
    def from_env(cls) -> LlmClient | None:
        """Build a client from ``llm.yaml`` (``TIA_LLM_*`` overrides it)."""
        from tia.inf.settings import llm_profile

        profile = llm_profile()
        base = os.environ.get("TIA_LLM_BASE", "").strip() or (profile.base_url if profile else "")
        model = os.environ.get("TIA_LLM_MODEL", "").strip() or (profile.model if profile else "")
        if not base or not model:
            return None
        key = os.environ.get("TIA_LLM_KEY", "").strip() or (profile.resolved_key() if profile else "")
        timeout = profile.timeout if profile else 30.0
        max_tokens = profile.max_tokens if profile else 512
        effort = profile.reasoning_effort if profile else ""
        override = os.environ.get("TIA_LLM_REASONING_EFFORT")
        if override is not None:  # empty string turns thinking off for an A/B run
            effort = override.strip()
        return cls(
            base,
            model,
            key or None,
            timeout=timeout,
            max_tokens=max_tokens,
            enable_thinking=profile.enable_thinking if profile else False,
            reasoning_effort=effort,
        )

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Ask for one JSON object; return ``{}`` on any transport/parse failure."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
        }
        styles = self._styles()
        start = self._style or 0
        order = styles[start:] + styles[:start]
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                for style in order:
                    try:
                        response = await client.post(
                            f"{self.base_url}/chat/completions",
                            json={**payload, **style},
                            headers=headers,
                        )
                    except httpx.HTTPError as exc:
                        _LOG.debug("llm guess skipped: %s", exc)
                        return {}
                    if response.status_code in (400, 422):
                        _LOG.info(
                            "model %s rejected request style %s (%s); trying a simpler one",
                            self.model,
                            style,
                            response.status_code,
                        )
                        continue
                    try:
                        response.raise_for_status()
                        body = response.json()
                        text = str(body["choices"][0]["message"]["content"] or "")
                    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                        _LOG.debug("llm guess skipped: %s", exc)
                        return {}
                    self._style = styles.index(style)
                    return _parse_object(text)
        except (httpx.HTTPError, ValueError) as exc:  # pragma: no cover - client bootstrap
            _LOG.debug("llm guess skipped: %s", exc)
        return {}

    async def probe_thinking(self) -> dict[str, Any]:
        """Send one tiny request per style and report which one the model accepts."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        prompt = 'Reply with the JSON object {"ok": true} and nothing else.'
        attempts: list[dict[str, Any]] = []
        supported: dict[str, Any] | None = None
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for style in self._styles():
                started = time.perf_counter()
                entry: dict[str, Any] = {"style": style}
                try:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        json={
                            "model": self.model,
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2,
                            "max_tokens": 256,
                            **style,
                        },
                        headers=headers,
                    )
                except httpx.HTTPError as exc:
                    entry.update({"status": None, "error": f"{type(exc).__name__}: {exc}"})
                    attempts.append(entry)
                    continue
                entry["status"] = response.status_code
                entry["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
                if response.status_code < 400:
                    try:
                        body = response.json()
                        message = body["choices"][0]["message"]
                        entry["content"] = str(message.get("content") or "")[:200]
                        entry["reasoning_chars"] = len(
                            str(message.get("reasoning_content") or message.get("reasoning") or "")
                        )
                        entry["usage"] = body.get("usage")
                    except (KeyError, IndexError, TypeError, ValueError) as exc:
                        entry["parse_error"] = str(exc)
                    if supported is None:
                        supported = style
                else:
                    entry["error"] = response.text[:300]
                attempts.append(entry)
        return {
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "supported_style": supported,
            "attempts": attempts,
        }


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
