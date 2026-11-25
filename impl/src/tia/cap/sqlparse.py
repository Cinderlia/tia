"""SQL 语法闸门（纯函数）。

只做"结构判断"，不连库、不解释语义：
- 单条语句、无注释绕过、无 DDL/多语句；
- 提取 op / 表名 / 列名 / 是否带 WHERE / VALUES 行数。

服务端的所有写库限制都必须在这里或 ``cap.policy`` 里拒绝（硬约束，不靠提示词）。
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
    """去掉尾部空白与单个结尾分号；拒绝多语句。"""
    stripped = sql.strip()
    while stripped.endswith(";"):
        stripped = stripped[:-1].rstrip()
    if not stripped:
        raise _bad("空 SQL")
    if ";" in stripped:
        raise _bad("只允许单条语句", "多语句、注释分隔都不允许")
    if "--" in stripped or "/*" in stripped or "#" in stripped:
        raise _bad("SQL 中不允许注释", "注释会被用于绕过语句检查")
    return stripped


def parse_read(sql: str) -> str:
    """校验只读 SQL 并返回原语句。"""
    body = _strip_user_sql(sql)
    op = body.split(None, 1)[0].lower()
    if op not in _READ_OPS:
        raise _bad(f"只允许 SELECT/SHOW/EXPLAIN/DESCRIBE，收到 {op.upper()!r}")
    if _FORBIDDEN.search(body):
        raise _bad("SQL 含被禁止的关键字", "不允许 DDL、文件写出与系统库访问")
    return body


def parse_write(sql: str) -> WriteStatement:
    """校验写库 SQL，返回结构化描述。"""
    body = _strip_user_sql(sql)
    op = body.split(None, 1)[0].lower()
    if op not in _WRITE_OPS:
        raise _bad(f"只允许 INSERT/UPDATE/DELETE，收到 {op.upper()!r}")
    if _FORBIDDEN.search(body):
        raise _bad("SQL 含被禁止的关键字", "不允许 DDL、文件写出与系统库访问")

    if op == "insert":
        match = re.match(
            rf"insert\s+into\s+(?P<table>{_TABLE})\s*(?:\((?P<cols>[^)]*)\))?",
            body,
            re.IGNORECASE,
        )
        if not match:
            raise _bad("无法解析 INSERT 目标表", "形如 INSERT INTO t (a,b) VALUES (1,2)")
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
            raise _bad("无法解析 UPDATE", "形如 UPDATE t SET a=1 WHERE id=2")
        table = _unquote(match.group("table"))
        rest = match.group("rest")
        if not re.search(r"\bwhere\b", rest, re.IGNORECASE):
            raise _bad("UPDATE 必须带 WHERE", "禁止全表更新")
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
        raise _bad("无法解析 DELETE", "形如 DELETE FROM t WHERE id=2")
    rest = match.group("rest")
    if not re.search(r"\bwhere\b", rest, re.IGNORECASE):
        raise _bad("DELETE 必须带 WHERE", "禁止全表删除")
    return WriteStatement(
        sql=body, op="delete", table=_unquote(match.group("table")), has_where=True, value_rows=1
    )


def _unquote(table: str) -> str:
    """``db.t`` / ``t`` / ``` t ``` → 表名（去掉库名与反引号）。"""
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
    """数 ``VALUES`` 后面的顶层括号组数量（一行 = 1 组）。"""
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
