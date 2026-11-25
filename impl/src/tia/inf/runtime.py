"""Process-level runtime: Settings + Store + MysqlAdapter.

Injected once at startup by the entry point (``tia-server`` / ``tia-agent``) via :func:`configure`;
handlers access it via :func:`get_runtime`. Immutable at runtime to prevent handlers from reading environment variables directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from tia.ad.mysql import MysqlAdapter
from tia.inf.config import Settings
from tia.inf.store import Store


@dataclass(frozen=True, slots=True)
class Runtime:
    settings: Settings
    store: Store
    mysql: MysqlAdapter


_runtime: Runtime | None = None


def configure(settings: Settings) -> Runtime:
    global _runtime
    _runtime = Runtime(settings=settings, store=Store(settings.store_path), mysql=MysqlAdapter(settings.db))
    return _runtime


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = configure(Settings.load("trigger"))
    return _runtime


def reset_runtime() -> None:
    """For testing only: clear the injected runtime."""
    global _runtime
    _runtime = None
