"""Adapter for the directed opcode tracer extension.

The extension (``impl/probe-php/opcode-tracer``) reads a flat JSON config from a
fixed path on every request, then writes the trace of that request to the
configured file.  This module owns that file contract: it writes the config,
reads the produced trace, and removes stale traces.  No other module touches
the config or output paths.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TraceConfigError(RuntimeError):
    """Raised when the trace config cannot be written or read."""


DEFAULT_CONFIG_PATH = Path("/tmp/trace_query.json")
DEFAULT_OUTPUT_DIR = Path("/tmp/trace")
DEFAULT_MAX_LINES = 20000


@dataclass(frozen=True)
class TraceRequest:
    """Directed trace parameters, one request per arm."""

    file: str
    output: str
    line_from: int = 0
    line_to: int = 0
    function: str = ""
    max_depth: int = 0
    max_lines: int = DEFAULT_MAX_LINES
    exclude: str = ""

    def to_config(self) -> dict[str, Any]:
        config: dict[str, Any] = {
            "file": self.file,
            "line_from": self.line_from,
            "line_to": self.line_to,
            "function": self.function,
            "max_depth": self.max_depth,
            "max_lines": self.max_lines,
            "output": self.output,
        }
        if self.exclude:
            config["exclude"] = self.exclude
        return config


@dataclass(frozen=True)
class TraceSnapshot:
    """State of the tracer: current config and the produced trace."""

    config: dict[str, Any] = field(default_factory=dict)
    output: str | None = None
    text: str | None = None


class OpcodeTraceAdapter:
    """Read and write the opcode tracer's config and output files."""

    def __init__(
        self,
        config_path: Path | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.config_path = Path(
            os.environ.get("TIA_TRACE_CONFIG") or config_path or DEFAULT_CONFIG_PATH
        )
        self.output_dir = Path(
            os.environ.get("TIA_TRACE_DIR") or output_dir or DEFAULT_OUTPUT_DIR
        )

    @staticmethod
    def normalize_name(name: str) -> str:
        """Keep only plain file names; reject path tricks and shell metacharacters."""

        candidate = name.strip()
        if not candidate or len(candidate) > 120:
            raise TraceConfigError(f"Invalid trace output name: {name!r}")
        if "/" in candidate or "\\" in candidate or ".." in candidate:
            raise TraceConfigError(f"Invalid trace output name: {name!r}")
        if not all(c.isalnum() or c in "._-" for c in candidate):
            raise TraceConfigError(f"Invalid trace output name: {name!r}")
        return candidate

    def output_path(self, name: str) -> Path:
        return self.output_dir / self.normalize_name(name)

    def arm(self, request: TraceRequest) -> dict[str, Any]:
        config = request.to_config()
        config["output"] = self.normalize_name(req_output(config))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.config_path.write_text(json.dumps(config) + "\n", encoding="utf-8")
        except OSError as exc:  # pragma: no cover - environment failure
            raise TraceConfigError(f"Cannot write trace config: {exc}") from exc
        return config

    def disarm(self) -> None:
        try:
            self.config_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:  # pragma: no cover - environment failure
            raise TraceConfigError(f"Cannot remove trace config: {exc}") from exc

    def read_config(self) -> dict[str, Any]:
        try:
            raw = self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:  # pragma: no cover - environment failure
            raise TraceConfigError(f"Cannot read trace config: {exc}") from exc
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    def read_output(self, name: str) -> str | None:
        path = self.output_path(name)
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return None
        except OSError as exc:  # pragma: no cover - environment failure
            raise TraceConfigError(f"Cannot read trace output: {exc}") from exc

    def delete_output(self, name: str) -> bool:
        path = self.output_path(name)
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:  # pragma: no cover - environment failure
            raise TraceConfigError(f"Cannot remove trace output: {exc}") from exc


def req_output(config: dict[str, Any]) -> str:
    output = config.get("output")
    if not isinstance(output, str) or not output:
        raise TraceConfigError("Trace config needs an output name")
    return output
