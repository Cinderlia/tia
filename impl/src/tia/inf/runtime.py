"""进程级运行时：Settings + Store + MysqlAdapter。

由入口（``tia-server`` / ``tia-agent``）在启动时调用 :func:`configure` 注入一次；
handler 通过 :func:`get_runtime` 取用。运行期不可变，避免各 handler 自行读环境变量。
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
    """仅供测试：清空注入的运行时。"""
    global _runtime
    _runtime = None
