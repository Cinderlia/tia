"""Remove the rows a run left in the target, whatever wrote them.

``db_undo`` can only revert rows this framework wrote through ``db_write``. A
payload row created by the application itself — the verification POST that lands
in a comment table, for example — is invisible to it. Every such row carries the
run's random tag, so the tag is the handle that covers both paths.
"""

from __future__ import annotations

import contextlib
from typing import Any

from tia.inf.runtime import get_runtime
from tia.orch.kernel import Kernel, ToolCallError

_TEXT_TYPES = {"char", "varchar", "tinytext", "text", "mediumtext", "longtext"}


async def cleanup_tagged_rows(
    kernel: Kernel,
    *,
    case_id: str,
    table: str,
    columns: list[str],
    tag: str,
) -> int:
    """Delete every row carrying ``tag``; return how many rows remain (-1 on error)."""
    columns = [column for column in columns if column]
    if not (case_id and table and columns and tag):
        return -1
    where = " OR ".join(f"`{column}` LIKE '%{tag}%'" for column in columns)
    with contextlib.suppress(ToolCallError):
        await kernel.call(
            "db_write",
            {
                "case_id": case_id,
                "sql": f"DELETE FROM `{table}` WHERE {where}",
                "allow_multi": True,
            },
        )
    try:
        again = await kernel.call(
            "db_read", {"sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE {where}"}
        )
    except ToolCallError:
        return -1
    rows = (again or {}).get("rows") or []
    return int(rows[0].get("n") or 0) if rows else 0


def _text_columns(schema: dict[str, Any]) -> list[str]:
    """Free-text columns of the single table a ``db_schema`` call describes."""
    tables = schema.get("tables") or []
    if not tables:
        return []
    names: list[str] = []
    for column in tables[0].get("columns") or []:
        kind = str(column.get("type") or "").lower().split("(")[0]
        if kind in _TEXT_TYPES and column.get("name"):
            names.append(str(column["name"]))
    return names


async def key_snapshot(kernel: Kernel, tables: list[str]) -> dict[str, dict[str, Any]]:
    """Record the highest key of every table before a request writes to it.

    Cleanup then only has to look at keys above the snapshot -- an indexed range
    instead of a LIKE over every text column of every table.
    """
    snapshots: dict[str, dict[str, Any]] = {}
    for table in dict.fromkeys(name for name in tables if name):
        try:
            schema = await kernel.call("db_schema", {"table": table})
        except ToolCallError:
            continue
        found = schema.get("tables") or []
        if not found:
            continue
        keys = found[0].get("primary_key") or []
        if not keys:
            continue
        column = str(keys[0])
        try:
            data = await kernel.call(
                "db_read", {"sql": f"SELECT MAX(`{column}`) AS n FROM `{table}`"}
            )
        except ToolCallError:
            continue
        rows = (data or {}).get("rows") or []
        value = rows[0].get("n") if rows else None
        snapshots[table] = {
            "column": column,
            "max": int(value) if value is not None else 0,
            "text": _text_columns(schema),
        }
    return snapshots


async def cleanup_new_rows(
    kernel: Kernel,
    *,
    case_id: str,
    snapshots: dict[str, dict[str, Any]],
    tag: str,
) -> int:
    """Delete the rows keyed above a snapshot; return how many still match."""
    remaining = 0
    for table, info in snapshots.items():
        column = str(info.get("column") or "")
        since = int(info.get("max") or 0)
        if not column:
            continue
        where = f"`{column}` > {since}"
        text = [str(name) for name in info.get("text") or [] if name]
        if text and tag:
            where += " AND (" + " OR ".join(f"`{name}` LIKE '%{tag}%'" for name in text) + ")"
        with contextlib.suppress(ToolCallError):
            await kernel.call(
                "db_write",
                {
                    "case_id": case_id,
                    "sql": f"DELETE FROM `{table}` WHERE {where}",
                    "allow_multi": True,
                },
            )
        try:
            again = await kernel.call(
                "db_read", {"sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE {where}"}
            )
        except ToolCallError:
            continue
        rows = (again or {}).get("rows") or []
        remaining += int(rows[0].get("n") or 0) if rows else 0
    return remaining


def parent_links(table: str) -> list[dict[str, str]]:
    """Foreign keys that point from ``table`` to the rows that own it."""
    try:
        result = get_runtime().mysql.select(
            "SELECT COLUMN_NAME AS column_name, REFERENCED_TABLE_NAME AS parent_table, "
            "REFERENCED_COLUMN_NAME AS parent_column FROM information_schema.KEY_COLUMN_USAGE "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s "
            "AND REFERENCED_TABLE_NAME IS NOT NULL",
            (table,),
        )
    except Exception:
        return []
    return [
        {
            "child_table": table,
            "child_column": str(row.get("column_name") or ""),
            "table": str(row.get("parent_table") or ""),
            "parent_column": str(row.get("parent_column") or ""),
        }
        for row in result.rows
        if row.get("column_name") and row.get("parent_table") and row.get("parent_column")
    ]


async def max_key(kernel: Kernel, table: str, column: str) -> int:
    """Current maximum key of a table; -1 when it cannot be read."""
    try:
        data = await kernel.call(
            "db_read", {"sql": f"SELECT MAX(`{column}`) AS n FROM `{table}`"}
        )
    except ToolCallError:
        return -1
    rows = (data or {}).get("rows") or []
    value = rows[0].get("n") if rows else None
    return int(value) if value is not None else -1


async def remove_orphan_parents(
    kernel: Kernel,
    *,
    case_id: str,
    links: list[dict[str, str]],
    snapshot: dict[str, int],
) -> int:
    """Delete parent rows created after ``snapshot`` that no child row references."""
    removed = 0
    for link in links:
        table = link.get("table") or ""
        column = link.get("parent_column") or ""
        child_table = link.get("child_table") or ""
        child_column = link.get("child_column") or ""
        since = int(snapshot.get(table, -1))
        if not (table and column and child_table and child_column) or since < 0:
            continue
        sql = (
            f"DELETE FROM `{table}` WHERE `{column}` > {since} AND `{column}` NOT IN "
            f"(SELECT `{child_column}` FROM `{child_table}`)"
        )
        with contextlib.suppress(ToolCallError):
            data = await kernel.call(
                "db_write", {"case_id": case_id, "sql": sql, "allow_multi": True}
            )
            removed += int((data.get("affected") if isinstance(data, dict) else 0) or 0)
    return removed
