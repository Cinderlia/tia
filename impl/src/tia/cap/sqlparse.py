"""SQL syntax gate (pure function).

Performs only "structural checks"; no DB connection, no semantic interpretation:
- Single statement, no comment bypass, no DDL/multi-statement;
- Extracts op / table name / column names / presence of WHERE / VALUES row count.

All server-side write restrictions must be rejected here or in ``cap.policy`` (hard constraints, not relying on prompts).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from tia.schemas.envelope import ErrorCode, ToolError

_IDENT = r"[A-Za-z_][A-Za-z0-9_$]*"
_TABLE = rf"(?:`?{_IDENT}`?\.)?`?{_IDENT}`?"

_READ_OPS = ("select", "show", "explain", "describe", "desc")
_WRITE_OPS = ("insert", "update", "delete")

_FORBIDDEN = re.compile(
    r"\b(create|alter|drop|truncate|grant|revoke|rename|call|load_file|outfile|dumpfile|"
    r"into\s+outfile|into\s+dumpfile|information_schema|mysql\.|performance_schema|sys\.)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class WriteStatement:
    sql: str
    op: Literal["insert", "update", "delete"]
    table: str
    columns: list[str] = field(default_factory=list)
    has_where: bool = False
    value_rows: int = 1


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _strip_user_sql(sql: str) -> str:
    """Strip trailing whitespace and a single trailing semicolon; reject multi-statements."""
    stripped = sql.strip()
    while stripped.endswith(";"):
        stripped = stripped[:-1].rstrip()
    if not stripped:
        raise _bad("Empty SQL")
    if ";" in stripped:
        raise _bad("Only single statements allowed", "Multi-statements and comment separators are not allowed")
    if "--" in stripped or "/*" in stripped or "#" in stripped:
        raise _bad("Comments are not allowed in SQL", "Comments can be used to bypass statement checks")
    return stripped


def parse_read(sql: str) -> str:
    """Validate read-only SQL and return the original statement."""
    body = _strip_user_sql(sql)
    op = body.split(None, 1)[0].lower()
    if op not in _READ_OPS:
        raise _bad(f"Only SELECT/SHOW/EXPLAIN/DESCRIBE allowed, received {op.upper()!r}")
    if _FORBIDDEN.search(body):
        raise _bad("SQL contains forbidden keywords", "DDL, file writes, and system database access are not allowed")
    return body


def parse_write(sql: str) -> WriteStatement:
    """Validate write SQL and return a structured description."""
    body = _strip_user_sql(sql)
    op = body.split(None, 1)[0].lower()
    if op not in _WRITE_OPS:
        raise _bad(f"Only INSERT/UPDATE/DELETE allowed, received {op.upper()!r}")
    if _FORBIDDEN.search(body):
        raise _bad("SQL contains forbidden keywords", "DDL, file writes, and system database access are not allowed")

    if op == "insert":
        match = re.match(
            rf"insert\s+into\s+(?P<table>{_TABLE})\s*(?:\((?P<cols>[^)]*)\))?",
            body,
            re.IGNORECASE,
        )
        if not match:
            raise _bad("Cannot parse INSERT target table", "Format: INSERT INTO t (a,b) VALUES (1,2)")
        table = _unquote(match.group("table"))
        columns = []
        if match.group("cols"):
            columns = [c.strip().strip("`") for c in match.group("cols").split(",") if c.strip()]
        rows = _count_value_groups(body)
        return WriteStatement(sql=body, op="insert", table=table, columns=columns, value_rows=rows)

    if op == "update":
        match = re.match(
            rf"update\s+(?P<table>{_TABLE})\s+set\s+(?P<rest>.*)$",
            body,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            raise _bad("Cannot parse UPDATE", "Format: UPDATE t SET a=1 WHERE id=2")
        table = _unquote(match.group("table"))
        rest = match.group("rest")
        if not re.search(r"\bwhere\b", rest, re.IGNORECASE):
            raise _bad("UPDATE must include WHERE", "Full-table updates are prohibited")
        set_part = re.split(r"\bwhere\b", rest, maxsplit=1, flags=re.IGNORECASE)[0]
        columns = []
        for assignment in _split_top_level(set_part):
            name = assignment.split("=", 1)[0].strip().strip("`")
            if name:
                columns.append(name)
        return WriteStatement(
            sql=body, op="update", table=table, columns=columns, has_where=True, value_rows=1
        )

    match = re.match(
        rf"delete\s+from\s+(?P<table>{_TABLE})\s+(?P<rest>.*)$",
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise _bad("Cannot parse DELETE", "Format: DELETE FROM t WHERE id=2")
    rest = match.group("rest")
    if not re.search(r"\bwhere\b", rest, re.IGNORECASE):
        raise _bad("DELETE must include WHERE", "Full-table deletes are prohibited")
    return WriteStatement(
        sql=body, op="delete", table=_unquote(match.group("table")), has_where=True, value_rows=1
    )


def _unquote(table: str) -> str:
    """``db.t`` / ``t`` / ``` t ``` → table name (strip database name and backticks)."""
    return table.split(".")[-1].strip().strip("`")


def _split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    quote: str | None = None
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def _count_value_groups(body: str) -> int:
    """Count the number of top-level parenthesized groups after ``VALUES`` (one line = one group)."""
    match = re.search(r"\bvalues\b", body, re.IGNORECASE)
    if not match:
        return 1
    text = body[match.end() :]
    depth = 0
    groups = 0
    quote: str | None = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
            if depth == 1:
                groups += 1
        elif ch == ")":
            depth -= 1
    return max(groups, 1)
