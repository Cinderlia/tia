"""Unit-test defaults: never call a real model from a test."""

from __future__ import annotations

import pytest

from tia.ad.llm import LlmClient


@pytest.fixture(autouse=True)
def _no_live_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Agents fall back to their deterministic defaults unless a test injects a client."""
    monkeypatch.setattr(LlmClient, "from_env", classmethod(lambda cls: None))
