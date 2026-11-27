"""Local settings files.

Two files live under ``impl/var/config`` (git-ignored) and hold the values that
used to be passed on every command line:

* ``app.yaml``   - target application, database, storage, reports, Chrome, budgets.
* ``llm.yaml``   - model endpoints. Plain text for now; the plan is to move the
  key to an environment variable once the rest of the settings are stable.

Both live in ``impl/config/local`` (git-ignored); ``impl/config/*.example.yaml``
are committed templates.

Precedence is CLI argument > environment variable > file > built-in default, so
the files are a convenience and never a hard dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_IMPL_ROOT = Path(__file__).resolve().parents[3]


def config_dir() -> Path:
    import os

    override = os.environ.get("TIA_CONFIG_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return _IMPL_ROOT / "config" / "local"


@lru_cache(maxsize=4)
def _load(name: str, mtime: float) -> dict[str, Any]:
    del mtime  # part of the cache key only
    path = config_dir() / name
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return loaded if isinstance(loaded, dict) else {}


def settings_file(name: str) -> dict[str, Any]:
    """Read ``app.yaml`` / ``llm.yaml`` and cache until the file changes."""
    path = config_dir() / name
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    return _load(name, mtime)


def section(name: str, key: str) -> dict[str, Any]:
    value = settings_file(name).get(key)
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True, slots=True)
class LlmProfile:
    name: str
    base_url: str
    model: str
    api_key: str = ""
    key_env: str = ""
    timeout: float = 60.0
    max_tokens: int = 4096
    enable_thinking: bool = False
    reasoning_effort: str = ""

    def resolved_key(self) -> str:
        import os

        if self.api_key:
            return self.api_key
        if self.key_env:
            return os.environ.get(self.key_env, "").strip()
        return ""

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "model": self.model,
            "key": "set" if self.resolved_key() else "missing",
            "key_env": self.key_env,
            "enable_thinking": self.enable_thinking,
            "reasoning_effort": self.reasoning_effort,
        }


def load_llm_profiles() -> dict[str, LlmProfile]:
    raw = section("llm.yaml", "profiles")
    profiles: dict[str, LlmProfile] = {}
    for name, item in raw.items():
        if not isinstance(item, dict):
            continue
        profiles[str(name)] = LlmProfile(
            name=str(name),
            base_url=str(item.get("base_url") or ""),
            model=str(item.get("model") or ""),
            api_key=str(item.get("api_key") or ""),
            key_env=str(item.get("key_env") or ""),
            timeout=float(item.get("timeout") or 60.0),
            max_tokens=int(item.get("max_tokens") or 4096),
            enable_thinking=bool(item.get("enable_thinking") or False),
            reasoning_effort=str(item.get("reasoning_effort") or ""),
        )
    return profiles


def active_llm_profile() -> str:
    import os

    override = os.environ.get("TIA_LLM_PROFILE", "").strip()
    if override:
        return override
    return str(settings_file("llm.yaml").get("active") or "qwen")


def llm_profile(name: str | None = None) -> LlmProfile | None:
    profiles = load_llm_profiles()
    return profiles.get(name or active_llm_profile())


def attempt_limit(name: str, default: int) -> int:
    """Budget for one bounded exploration loop, from app.yaml or its env override."""
    import os

    env_name = f"TIA_{name.upper()}_ATTEMPTS"
    env_value = os.environ.get(env_name, "").strip()
    if env_value:
        return max(1, int(env_value))
    attempts = section("app.yaml", "attempts")
    value = attempts.get(name)
    if value is None:
        return default
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default
