"""Read/write slice pairing: a cheap, explainable prior for the injection queue.

The pairing idea follows the "Match Database Operations" step of STaint
(Ji, Cao, He; "STaint: Detecting Second-Order Vulnerabilities in PHP
Applications with LLM-Assisted Bi-Directional Static Taint Analysis",
ASE 2025 NIER track): a database operation is modelled as a
``(table, column)`` key and reads are matched against writes on the same key.

TIA only reuses that idea. Pairing is a *hypothesis*, never a verdict: it
orders the injection queue and gives the inject agent candidates to choose
from, and the runtime probe (php-ext-sqlquery) plus ``verify_tag`` decide
whether the hypothesis holds. A pair therefore never merges two slices and
never changes a verdict.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# A reader returns ``[(line_number, text), ...]`` for a source window.
Reader = Callable[[str, int, int], list[tuple[int, str]]]

_SELECT_RE = re.compile(
    r"\bselect\b(?P<cols>.*?)\bfrom\b\s*`?(?P<table>[A-Za-z_][\w.$]*)`?", re.I | re.S
)
_INSERT_RE = re.compile(
    r"\binsert\s+(?:ignore\s+)?into\s+`?(?P<table>[A-Za-z_][\w.$]*)`?\s*\((?P<cols>[^)]*)\)",
    re.I,
)
_UPDATE_RE = re.compile(
    r"\bupdate\s+`?(?P<table>[A-Za-z_][\w.$]*)`?\s+set\s+(?P<cols>.*?)(?:\bwhere\b|\border\b|$)",
    re.I | re.S,
)
_DELETE_RE = re.compile(r"\bdelete\s+from\s+`?(?P<table>[A-Za-z_][\w.$]*)`?", re.I)
_WHERE_RE = re.compile(r"\bwhere\b", re.I)
_BIND_RE = re.compile(r'bind(?:Param|Value)\(\s*[\'"]:([A-Za-z_][\w]*)[\'"]', re.I)

SUCCESS_VERDICTS = {"EXECUTABLE", "EXECUTED"}
FAILURE_VERDICTS = {
    "WRITE_NOT_REACHED",
    "WRITTEN_NOT_VISIBLE",
    "NOT_EXECUTABLE",
    "READ_NOT_REFLECTED",
    "REFLECTED_INERT",
    "REFLECTED_ENCODED",
    "ENTRY_AMBIGUOUS",
    "NO_HTTP_ENTRY",
    "LENGTH_EXCEEDED",
    "CONSTRAINT_UNSAT",
    "PATH_UNREACHABLE",
    "SWITCH_LIMIT_REACHED",
}


@dataclass(frozen=True)
class DbOp:
    """One database operation recovered from a slice or its source window."""

    op: str
    table: str
    columns: tuple[str, ...] = ()
    has_where: bool = False
    sql: str = ""


@dataclass
class SliceEntry:
    slice_id: str
    file: str
    line: int
    kind: str
    params: list[str] = field(default_factory=list)
    probe: bool = False
    guards: list[str] = field(default_factory=list)
    ops: list[DbOp] = field(default_factory=list)
    history: list[str] = field(default_factory=list)


def _split_top(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _ident(raw: str) -> str:
    text = raw.strip().strip("`\"'")
    text = text.split()[0] if text.split() else text
    if "." in text:
        text = text.rsplit(".", 1)[1]
    return text.strip("`\"'").lower()


def parse_columns(text: str) -> tuple[str, ...]:
    """Column names from a projection/column list; expressions and ``*`` are skipped."""
    columns: list[str] = []
    for part in _split_top(text):
        item = part.strip()
        if not item or item == "*" or "(" in item:
            continue
        item = re.split(r"\s+as\s+", item, maxsplit=1, flags=re.I)[0]
        name = _ident(item)
        if re.fullmatch(r"[a-z_][\w]*", name):
            columns.append(name)
    return tuple(dict.fromkeys(columns))


def extract_ops(text: str) -> list[DbOp]:
    """Recover ``select``/``insert``/``update``/``delete`` operations from source text."""
    ops: list[DbOp] = []
    for match in _SELECT_RE.finditer(text):
        ops.append(
            DbOp(
                op="select",
                table=_ident(match.group("table")),
                columns=parse_columns(match.group("cols")),
                sql=match.group(0).strip()[:400],
            )
        )
    for match in _INSERT_RE.finditer(text):
        ops.append(
            DbOp(
                op="insert",
                table=_ident(match.group("table")),
                columns=parse_columns(match.group("cols")),
                sql=match.group(0).strip()[:400],
            )
        )
    for match in _UPDATE_RE.finditer(text):
        assignments = [part.split("=", 1)[0] for part in _split_top(match.group("cols"))]
        ops.append(
            DbOp(
                op="update",
                table=_ident(match.group("table")),
                columns=parse_columns(",".join(assignments)),
                has_where=bool(_WHERE_RE.search(match.group(0))),
                sql=match.group(0).strip()[:400],
            )
        )
    for match in _DELETE_RE.finditer(text):
        ops.append(
            DbOp(
                op="delete",
                table=_ident(match.group("table")),
                has_where=bool(_WHERE_RE.search(text[match.start() : match.start() + 200])),
                sql=match.group(0).strip()[:200],
            )
        )
    return ops


def _inline_text(raw: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("sinkCode", "sink"):
        value = raw.get(key)
        if isinstance(value, str):
            chunks.append(value)
    nodes = raw.get("nodes")
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, dict) and isinstance(node.get("code"), str):
                chunks.append(str(node["code"]))
    for source in raw.get("sources") or []:
        if isinstance(source, dict) and isinstance(source.get("code"), str):
            chunks.append(str(source["code"]))
    return "\n".join(chunks)


def _slice_identity(raw: dict[str, Any], index: int) -> tuple[str, str, int]:
    sink = raw.get("sink")
    sink_text = sink if isinstance(sink, str) else ""
    if isinstance(sink, dict):
        file_ = str(sink.get("file") or "")
        line = int(sink.get("line") or 0)
    else:
        from tia.cap.case import parse_sink

        file_, line, _ = parse_sink(sink_text or str(raw.get("sinkFile") or ""))
    file_ = file_ or str(raw.get("sinkFile") or "")
    line = line or int(raw.get("sinkLine") or 0)
    slice_id = str(raw.get("slice_id") or f"slice-{index:03d}")
    return slice_id, file_, line


def _slice_params(raw: dict[str, Any]) -> list[str]:
    params = [str(item) for item in raw.get("params") or []]
    if not params:
        for source in raw.get("sources") or []:
            if isinstance(source, dict) and source.get("param"):
                params.append(str(source["param"]))
    return params


def _slice_guards(raw: dict[str, Any]) -> list[str]:
    guards = raw.get("optionalGuards") or raw.get("guards") or []
    return [str(item) for item in guards] if isinstance(guards, list) else []


def resolve_entry(
    raw: dict[str, Any],
    index: int = 0,
    *,
    reader: Reader | None = None,
    history: dict[str, list[str]] | None = None,
    context_lines: int = 40,
) -> SliceEntry:
    """Build a slice entry: recover DB operations inline or from a source window."""
    slice_id, file_, line = _slice_identity(raw, index)
    entry = SliceEntry(
        slice_id=slice_id,
        file=file_,
        line=line,
        kind=str(raw.get("kind") or ""),
        params=_slice_params(raw),
        probe=bool((raw.get("sqlProbe") or {}).get("extensionConfig")),
        guards=_slice_guards(raw),
    )
    if history:
        entry.history = history.get(f"{file_}:{line}", [])

    ops = extract_ops(_inline_text(raw))
    if reader is not None and file_ and line > 0:
        try:
            window = reader(file_, max(1, line - context_lines), line + 10)
        except Exception:  # noqa: BLE001 - source may be unavailable; pairing degrades
            window = []
        if window:
            text = "\n".join(text for _, text in window)
            ops.extend(extract_ops(text))
    if not ops:
        # Last resort: a bind parameter still names a column (table unknown).
        bind = _BIND_RE.search(_inline_text(raw))
        if bind:
            ops.append(DbOp(op="write", table="", columns=(bind.group(1).lower(),)))
    entry.ops = _dedupe_ops(ops)
    return entry


def _dedupe_ops(ops: Iterable[DbOp]) -> list[DbOp]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    unique: list[DbOp] = []
    for op in ops:
        key = (op.op, op.table, op.columns)
        if key in seen:
            continue
        seen.add(key)
        unique.append(op)
    return unique


def _is_read(entry: SliceEntry) -> bool:
    return any(op.op == "select" for op in entry.ops) or "select" in _inline_text({"sinkCode": entry.kind}).lower()


def _is_write(entry: SliceEntry) -> bool:
    return any(op.op in {"insert", "update", "write"} for op in entry.ops)


def _read_columns(entry: SliceEntry, table: str) -> tuple[tuple[str, ...], bool]:
    """Union of columns a slice reads from ``table``; second value is table-level (``select *``)."""
    columns: list[str] = []
    table_level = False
    for op in entry.ops:
        if op.op != "select":
            continue
        if table and op.table and op.table != table:
            continue
        if not op.columns:
            table_level = True
        columns.extend(op.columns)
    return tuple(dict.fromkeys(columns)), table_level


def _write_columns(entry: SliceEntry, table: str) -> tuple[str, ...]:
    columns: list[str] = []
    for op in entry.ops:
        if op.op not in {"insert", "update", "write"}:
            continue
        if table and op.table and op.table != table:
            continue
        columns.extend(op.columns)
    return tuple(dict.fromkeys(columns))


def pair_id_for(read_slice_id: str, write_slice_id: str) -> str:
    digest = hashlib.sha1(f"{read_slice_id}|{write_slice_id}".encode()).hexdigest()[:10]
    return f"pair-{digest}"


def build_pairs(entries: list[SliceEntry], *, min_confidence: int = 20) -> list[dict[str, Any]]:
    """Bidirectional read/write pairing; returns JSON-ready hints sorted by confidence."""
    hints: dict[tuple[str, str], dict[str, Any]] = {}
    for read_entry in entries:
        if not _is_read(read_entry):
            continue
        for write_entry in entries:
            if read_entry.slice_id == write_entry.slice_id or not _is_write(write_entry):
                continue
            for write_op in write_entry.ops:
                if write_op.op not in {"insert", "update", "write"}:
                    continue
                table = write_op.table
                read_columns, table_level = _read_columns(read_entry, table)
                write_columns = _write_columns(write_entry, table)
                if not table:
                    shared = tuple(sorted(set(read_columns) & set(write_columns)))
                    if not shared:
                        continue
                    confidence = 25
                    basis = ["column-only pair: write table unknown"]
                elif read_columns:
                    shared = tuple(sorted(set(read_columns) & set(write_columns)))
                    if not shared:
                        continue
                    confidence = 60
                    basis = [f"same table {table} and column {', '.join(shared)}"]
                elif table_level:
                    shared = tuple(sorted(write_columns))
                    if not shared:
                        continue
                    confidence = 40
                    basis = [f"table-level read (select *) matched writes on {table}"]
                else:
                    continue

                reasons = list(basis)
                if write_entry.params:
                    confidence += 12
                    reasons.append(f"write parameter known: {', '.join(write_entry.params)}")
                if read_entry.probe:
                    confidence += 8
                    reasons.append("read slice carries a sqlProbe extension config")
                if read_entry.file == write_entry.file:
                    confidence += 8
                    reasons.append("read and write live in the same file")
                    distance = abs(read_entry.line - write_entry.line)
                    if distance <= 50:
                        confidence += 6
                        reasons.append(f"sink distance {distance} lines")
                for verdict in write_entry.history + read_entry.history:
                    if verdict in SUCCESS_VERDICTS:
                        confidence += 10
                        reasons.append(f"earlier run produced {verdict}")
                        break
                failures = [v for v in write_entry.history + read_entry.history if v in FAILURE_VERDICTS]
                if failures:
                    confidence -= 8
                    reasons.append(f"earlier run produced {failures[0]}")
                if not read_entry.guards and not write_entry.guards:
                    confidence += 4
                    reasons.append("no guard recorded on either path")
                confidence = max(0, min(100, confidence))
                if confidence < min_confidence:
                    continue

                key = (read_entry.slice_id, write_entry.slice_id)
                existing = hints.get(key)
                if existing is not None and int(existing["confidence"]) >= confidence:
                    continue
                # Data direction: a write executed before the read is the
                # stored-then-rendered case; the reverse is rendered-then-written.
                order = "write_then_read" if write_entry.line <= read_entry.line else "read_then_write"
                hints[key] = {
                    "pair_id": pair_id_for(read_entry.slice_id, write_entry.slice_id),
                    "read_slice_id": read_entry.slice_id,
                    "write_slice_id": write_entry.slice_id,
                    "table": table,
                    "columns": list(shared),
                    "confidence": confidence,
                    "direction": order,
                    "reasons": reasons,
                }
    return sorted(
        hints.values(),
        key=lambda item: (-int(item["confidence"]), item["pair_id"]),
    )


def group_by_slice(pairs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Map every slice id to the pairs it participates in (both directions)."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for pair in pairs:
        for side in ("read_slice_id", "write_slice_id"):
            grouped.setdefault(str(pair[side]), []).append(pair)
    return grouped
