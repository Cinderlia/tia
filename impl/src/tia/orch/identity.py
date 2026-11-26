"""Stable identities for slices and read/write pairs.

Deduplication must not rely on line numbers: the same write site is often
exported once per taint path, and one read site can render several columns on
consecutive lines. Identity keys therefore describe the *site*:

- write: ``file | write | table | op | columns``
- reads: ``file | read | sql:<line>`` when the slice carries a sqlprobe target,
  otherwise the projected columns of its SELECT, otherwise the file itself.

Identities are stable across runs so a concluded pair can be skipped later.
"""

from __future__ import annotations

import re
from typing import Any

from tia.orch.pairing import extract_ops

_BIND_RE = re.compile(r'bindParam\(\s*["\']:(\w+)["\']', re.IGNORECASE)
_PARAM_RE = re.compile(r"\$_(?:POST|GET|REQUEST)\[\s*[\"'](\w+)[\"']\s*\]")


def _sink(raw: dict[str, Any]) -> tuple[str, int, str]:
    raw_sink = raw.get("sink")
    sink: dict[str, Any] = raw_sink if isinstance(raw_sink, dict) else {}
    file = str(sink.get("file") or raw.get("sinkFile") or "")
    line = int(sink.get("line") or raw.get("sinkLine") or 0)
    code = str(sink.get("code") or raw.get("sinkCode") or "")
    if not file and ":" in str(raw.get("sink") or ""):
        path, _, number = str(raw.get("sink")).rpartition(":")
        file = path
        line = int(number) if number.isdigit() else line
    return file, line, code


def _sqlprobe_line(raw: dict[str, Any]) -> int:
    probe = raw.get("sqlProbe")
    config = probe.get("extensionConfig") if isinstance(probe, dict) else None
    if not isinstance(config, dict):
        return 0
    try:
        return int(config.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def bind_columns(code: str) -> list[str]:
    """Column names named by ``bindParam(':col', ...)`` calls."""

    return sorted({match.group(1).lower() for match in _BIND_RE.finditer(code)})


def write_identity(raw: dict[str, Any], source_text: str = "") -> str:
    """Identity of a write site, ignoring which taint path produced the slice."""

    file, line, code = _sink(raw)
    text = code or source_text
    ops = extract_ops(text)
    table = ""
    op = "write"
    columns: list[str] = bind_columns(text)
    for candidate in ops:
        if candidate.op in ("insert", "update", "delete"):
            table = candidate.table
            op = candidate.op
            columns = sorted(set(columns) | set(candidate.columns))
            break
    if not table and not columns:
        params = sorted({m.group(1) for m in _PARAM_RE.finditer(text)})
        columns = params
    payload = ",".join(sorted(columns)) or f"line:{line}"
    return f"{file}|{op}|{table}|{payload}"


def read_identity(raw: dict[str, Any], source_text: str = "") -> str:
    """Identity of a read site, grouping the render lines of one query."""

    file, line, code = _sink(raw)
    probe_line = _sqlprobe_line(raw)
    if probe_line:
        return f"{file}|read|sql:{probe_line}"
    text = code or source_text
    for candidate in extract_ops(text):
        if candidate.op == "select" and (candidate.table or candidate.columns):
            columns = ",".join(sorted(candidate.columns)) or "*"
            return f"{file}|read|{candidate.table}|{columns}"
    return f"{file}|read|line:{line}"


def direct_identity(raw: dict[str, Any]) -> str:
    """One first-order slice: same file and line, differing only by taint path."""

    file, line, _ = _sink(raw)
    return f"{file}|direct|line:{line}"


def identity_of(raw: dict[str, Any], order_mode: str, source_text: str = "") -> str:
    """Pick the identity flavour that matches the slice family."""

    if order_mode == "direct":
        return direct_identity(raw)
    if order_mode == "second":
        # Decide by the SQL statement and bind parameters, not by which list
        # the slice came from: the same site is exported once per taint path.
        code = _sink(raw)[2]
        text = code or source_text
        ops = extract_ops(text)
        if bind_columns(text) or any(op.op in ("insert", "update", "delete") for op in ops):
            return write_identity(raw, source_text)
        return read_identity(raw, source_text)
    return direct_identity(raw)


def pair_key(read_identity_value: str, write_identity_value: str) -> str:
    return f"{read_identity_value}||{write_identity_value}"
