"""Adapter for the ``sqlquery`` PHP extension (observation probe).

The extension is loaded into the target PHP runtime. It reads a small JSON
configuration from a fixed path, captures the SQL that the configured file and
line actually executed, and writes the captured fields and rows next to it at
the end of the request.

This adapter only touches the files that define that contract:

* ``<base>/sql_query.json`` — the arm configuration
* ``<base>/sql/<output>.json`` — the captured result of the last request
* ``<base>/sql/sqlquery_debug.log`` — the match summary of the last request

Nothing here starts, stops or reconfigures the extension itself; the target
runtime already has it loaded.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CONFIG_NAME = "sql_query.json"
OUTPUT_DIR_NAME = "sql"
DEBUG_LOG_NAME = "sqlquery_debug.log"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ProbeConfigError(ValueError):
    """Raised when an output name cannot be used as a plain file name."""


@dataclass(frozen=True)
class ProbeSnapshot:
    """State of the probe slot and of the last captured request."""

    config: dict[str, Any] | None
    output: dict[str, Any] | None
    debug: dict[str, str]


def default_base_dir() -> Path:
    """Directory that holds the probe configuration and captured results."""

    override = os.environ.get("TIA_PROBE_BASE")
    return Path(override) if override else Path("/tmp")


class SqlProbeAdapter:
    """File-level client of the ``sqlquery`` extension."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base = Path(base_dir) if base_dir is not None else default_base_dir()

    @property
    def config_path(self) -> Path:
        return self.base / CONFIG_NAME

    @property
    def output_dir(self) -> Path:
        return self.base / OUTPUT_DIR_NAME

    @property
    def debug_path(self) -> Path:
        return self.output_dir / DEBUG_LOG_NAME

    def output_path(self, name: str) -> Path:
        clean = self.normalize_name(name)
        return self.output_dir / clean

    @staticmethod
    def normalize_name(name: str) -> str:
        """Return a plain ``.json`` file name; refuse anything path-like."""

        candidate = name.strip()
        if not candidate:
            raise ProbeConfigError("output name must not be empty")
        if candidate.startswith((".", "/")) or "/" in candidate or "\\" in candidate:
            raise ProbeConfigError("output name must be a plain file name")
        if "${" in candidate or "}" in candidate:
            raise ProbeConfigError("output name must not contain template syntax")
        if not candidate.endswith(".json"):
            candidate += ".json"
        if not _SAFE_NAME.match(candidate):
            raise ProbeConfigError("output name contains unsupported characters")
        return candidate

    def arm(self, file: str, line: int, output: str) -> dict[str, Any]:
        """Write the configuration atomically so the runtime never reads half a file."""

        if line <= 0:
            raise ProbeConfigError("line must be a positive integer")
        config = {"file": file, "line": line, "output": self.normalize_name(output)}
        self.base.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(config), encoding="utf-8")
        os.replace(tmp, self.config_path)
        return config

    def disarm(self) -> bool:
        """Remove the configuration; returns whether one was armed."""

        try:
            self.config_path.unlink()
        except FileNotFoundError:
            return False
        return True

    def read_config(self) -> dict[str, Any] | None:
        try:
            raw = self.config_path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def read_output(self, name: str | None = None) -> dict[str, Any] | None:
        if name is None:
            config = self.read_config() or {}
            raw_name = config.get("output")
            if not isinstance(raw_name, str):
                return None
            name = raw_name
        try:
            path = self.output_path(name)
        except ProbeConfigError:
            return None
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def read_debug(self) -> dict[str, str]:
        """Parse the flat ``key=value`` debug log of the last request."""

        try:
            raw = self.debug_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}
        fields: dict[str, str] = {}
        for line in raw.splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip():
                fields[key.strip()] = value.strip()
        return fields

    def remove_output(self, name: str) -> bool:
        try:
            path = self.output_path(name)
        except ProbeConfigError:
            return False
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    def snapshot(self, output: str | None = None) -> ProbeSnapshot:
        return ProbeSnapshot(
            config=self.read_config(),
            output=self.read_output(output),
            debug=self.read_debug(),
        )
