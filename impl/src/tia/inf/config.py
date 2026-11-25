"""配置：profile yaml + 环境变量 + 路径。

所有配置在进程启动时读一次，运行期不可变（对应 H12 / G3：身份与预算由启动参数决定）。
路径与连接信息的默认值只服务于容器内开发环境，部署时全部走环境变量。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

#: 本文件位于 ``impl/src/tia/inf/config.py``。
_IMPL_ROOT = Path(__file__).resolve().parents[3]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True, slots=True)
class DbConfig:
    """目标库连接信息。

    ``name`` 是用户填写的库名；账号按约定为 ``tia_<name>`` 且只授权该库
    （``scripts/setup-db.sh`` 用 root 创建），因此 agent 即使写错 SQL 也碰不到别的库。
    """

    host: str = "127.0.0.1"
    port: int = 3306
    user: str = ""
    password: str = ""
    name: str = ""
    charset: str = "utf8mb4"

    @property
    def configured(self) -> bool:
        return bool(self.name and self.user)

    def masked(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "name": self.name,
            "charset": self.charset,
        }


@dataclass(frozen=True, slots=True)
class ProfileConfig:
    """``impl/profiles/<profile>.yaml`` 的内容。"""

    name: str
    write_allow_tables: frozenset[str] = frozenset()
    write_deny_columns: frozenset[str] = frozenset()
    max_rows_per_write: int = 1
    max_source_lines: int = 500
    max_http_bytes: int = 32 * 1024

    @classmethod
    def load(cls, profile: str) -> ProfileConfig:
        path = _IMPL_ROOT / "profiles" / f"{profile}.yaml"
        raw: dict[str, Any] = {}
        if path.is_file():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                raw = loaded
        return cls(
            name=profile,
            write_allow_tables=frozenset(map(str, raw.get("write_allow_tables") or [])),
            write_deny_columns=frozenset(map(str, raw.get("write_deny_columns") or [])),
            max_rows_per_write=int(raw.get("max_rows_per_write") or 1),
            max_source_lines=int(raw.get("max_source_lines") or 500),
            max_http_bytes=int(raw.get("max_http_bytes") or 32 * 1024),
        )


@dataclass(frozen=True, slots=True)
class Settings:
    impl_root: Path
    app_root: Path
    store_path: Path
    db: DbConfig
    profile: ProfileConfig

    @classmethod
    def load(
        cls,
        profile: str,
        *,
        db_name: str | None = None,
        db_user: str | None = None,
        db_password: str | None = None,
        app_root: Path | None = None,
        store_path: Path | None = None,
    ) -> Settings:
        name = (db_name if db_name is not None else _env("TIA_DB_NAME")).strip()
        user = db_user if db_user is not None else _env("TIA_DB_USER", f"tia_{name}" if name else "")
        password = db_password if db_password is not None else _env("TIA_DB_PASSWORD", "tia-dev-pass")
        db = DbConfig(
            host=_env("TIA_DB_HOST", "127.0.0.1"),
            port=int(_env("TIA_DB_PORT", "3306")),
            user=user,
            password=password,
            name=name,
            charset=_env("TIA_DB_CHARSET", "utf8mb4"),
        )
        root = Path(_env("TIA_APP_ROOT", str(app_root or "/app"))).resolve()
        store = Path(store_path or _env("TIA_STORE", str(_IMPL_ROOT / "var" / "tia.db")))
        return cls(
            impl_root=_IMPL_ROOT,
            app_root=root,
            store_path=store,
            db=db,
            profile=ProfileConfig.load(profile),
        )

    def with_db_name(self, name: str) -> Settings:
        name = name.strip()
        user = f"tia_{name}" if name else ""
        return replace(self, db=replace(self.db, name=name, user=user))
