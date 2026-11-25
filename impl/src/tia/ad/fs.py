"""Filesystem adapter: read-only source code.

All paths are confined to ``app_root`` (default /app); no write operations are performed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from tia.schemas.envelope import ErrorCode, ToolError


@dataclass(frozen=True, slots=True)
class FileSlice:
    path: str
    total_lines: int
    sha256: str
    lines: list[tuple[int, str]]


def _error(code: ErrorCode, message: str, hint: str = "") -> ToolError:
    return ToolError(code, message, hint=hint)


class FsAdapter:
    def __init__(self, app_root: Path) -> None:
        self.app_root = app_root.resolve()

    def resolve(self, path: str) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.app_root / candidate
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.app_root):
            raise _error(
                ErrorCode.POLICY_DENIED,
                f"Path is not within app_root: {path}",
                f"app_root={self.app_root}",
            )
        return resolved

    def read(self, path: str, line_from: int, line_to: int) -> FileSlice:
        resolved = self.resolve(path)
        if not resolved.is_file():
            raise _error(ErrorCode.NOT_FOUND, f"File not found: {path}")
        raw = resolved.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        all_lines = text.splitlines()
        begin = max(1, line_from)
        end = min(len(all_lines), line_to)
        selected = [(n, all_lines[n - 1]) for n in range(begin, end + 1)]
        return FileSlice(
            path=str(resolved),
            total_lines=len(all_lines),
            sha256=hashlib.sha256(raw).hexdigest(),
            lines=selected,
        )

    def grep(
        self,
        pattern: str,
        path: str,
        *,
        glob: str = "*.php",
        context: int = 2,
        max_hits: int = 50,
        fixed: bool = False,
        ignore_case: bool = False,
    ) -> tuple[list[dict[str, object]], bool, int]:
        root = self.resolve(path)
        flags = re.IGNORECASE if ignore_case else 0
        try:
            regex = re.compile(re.escape(pattern) if fixed else pattern, flags)
        except re.error as exc:
            raise _error(ErrorCode.BAD_ARGS, f"Invalid regex: {exc}") from exc

        files: list[Path] = []
        if root.is_file():
            files = [root]
        elif root.is_dir():
            files = sorted(p for p in root.rglob("*") if p.is_file() and fnmatch(p.name, glob))
        else:
            raise _error(ErrorCode.NOT_FOUND, f"Path does not exist: {path}")

        hits: list[dict[str, object]] = []
        truncated = False
        for file in files:
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if regex.search(line):
                    if len(hits) >= max_hits:
                        truncated = True
                        break
                    hits.append(
                        {
                            "file": str(file),
                            "line": index + 1,
                            "text": line,
                            "before": lines[max(0, index - context) : index],
                            "after": lines[index + 1 : index + 1 + context],
                        }
                    )
            if truncated:
                break
        return hits, truncated, len(files)
