"""Config: profile yaml + env vars + paths.

All config is read once at process startup and is immutable at runtime (per H12 / G3: identity and budget are determined by startup parameters).
Default values for paths and connection info serve only the in-container dev environment; all are overridden by env vars in deployment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from tia.inf import settings as file_settings

#: This file is located at ``impl/src/tia/inf/config.py``.
_IMPL_ROOT = Path(__file__).resolve().parents[3]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True, slots=True)
class DbConfig:
    """Target database connection info.

    ``name`` is the user-provided database name; the account is conventionally ``tia_<name>`` and granted access only to that database
    (created by root via ``scripts/setup-db.sh``), so the agent cannot access other databases even if it writes incorrect SQL.
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
    """Content of ``impl/profiles/<profile>.yaml``."""

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
    accounts_path: Path
    default_account: str = ""
    chrome: str = ""
    reports_path: Path | None = None

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
        app: dict[str, Any] = file_settings.settings_file("app.yaml")
        raw_db = app.get("db")
        file_db: dict[str, Any] = raw_db if isinstance(raw_db, dict) else {}
        name = (db_name if db_name is not None else _env("TIA_DB_NAME", str(file_db.get("name") or ""))).strip()
        user = db_user if db_user is not None else _env(
            "TIA_DB_USER", str(file_db.get("user") or (f"tia_{name}" if name else ""))
        )
        password = db_password if db_password is not None else _env(
            "TIA_DB_PASSWORD", str(file_db.get("password") or "tia-dev-pass")
        )
        db = DbConfig(
            host=_env("TIA_DB_HOST", str(file_db.get("host") or "127.0.0.1")),
            port=int(_env("TIA_DB_PORT", str(file_db.get("port") or 3306))),
            user=user,
            password=password,
            name=name,
            charset=_env("TIA_DB_CHARSET", str(file_db.get("charset") or "utf8mb4")),
        )
        root = Path(
            _env("TIA_APP_ROOT", str(app_root or app.get("app_root") or "/app"))
        ).resolve()
        store = Path(
            store_path
            or _env("TIA_STORE", str(app.get("store") or str(_IMPL_ROOT / "var" / "tia.db")))
        )
        accounts = Path(
            _env("TIA_ACCOUNTS", str(app.get("accounts") or str(store.parent / "accounts.yaml")))
        )
        return cls(
            impl_root=_IMPL_ROOT,
            app_root=root,
            store_path=store,
            db=db,
            profile=ProfileConfig.load(profile),
            accounts_path=accounts,
            default_account=_env("TIA_ACCOUNT", str(app.get("default_account") or "")),
            chrome=_env("TIA_CHROME", str(app.get("chrome") or "")),
            reports_path=(
                Path(_env("TIA_REPORTS", str(app.get("reports"))))
                if (_env("TIA_REPORTS", "") or app.get("reports"))
                else None
            ),
        )

    def with_db_name(self, name: str) -> Settings:
        name = name.strip()
        user = f"tia_{name}" if name else ""
        return replace(self, db=replace(self.db, name=name, user=user))
