"""Data and probe layer: db_schema / db_read / db_write / db_undo.

Three hard rules are enforced here:
- Target columns written only via the application are not writable by this tool (caller declares allowed columns via WriteTarget);
- Every write returns ``change_id`` + ``undo_sql`` and persists to the change table (H4);
- ``db_undo`` must provide ``residue``, which is referenced in agent reports.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.ad.mysql import MysqlAdapter, quote_ident
from tia.cap import policy
from tia.cap.registry import ToolOutput
from tia.cap.sqlparse import WriteStatement, parse_read, parse_write
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import ErrorCode, ToolError

MAX_LIMIT = 200


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameters: {exc.errors()[0]['msg']}") from exc


# ---------------------------------------------------------------------------
# db_schema
# ---------------------------------------------------------------------------


class DbSchemaInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str | None = None
    like: str | None = None
    include: list[str] = Field(default_factory=lambda: ["columns", "keys", "fks", "indexes"])


async def db_schema(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(DbSchemaInput, arguments)
    rt = get_runtime()
    adapter = rt.mysql

    tables: list[str]
    if params.table:
        tables = [params.table]
    elif params.like:
        rows = adapter.select(
            "SELECT TABLE_NAME FROM information_schema.TABLES"
            " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE %s ORDER BY TABLE_NAME",
            (params.like,),
        )
        tables = [str(r["TABLE_NAME"]) for r in rows.rows]
        if not tables:
            raise ToolError(ErrorCode.NOT_FOUND, f"No table matching {params.like!r}")
    else:
        raise _bad("At least one of table or like must be provided")

    schema = adapter.table_schema(tables)
    if not schema and params.table:
        raise ToolError(ErrorCode.NOT_FOUND, f"Table does not exist: {params.table}")
    for entry in schema:
        if "columns" not in params.include:
            entry.pop("columns", None)
        if "fks" not in params.include:
            entry.pop("fks", None)
        if "indexes" not in params.include:
            entry.pop("indexes", None)
    return ToolOutput(data={"tables": schema})


# ---------------------------------------------------------------------------
# db_read
# ---------------------------------------------------------------------------


class DbReadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str
    limit: int = Field(default=50, ge=1, le=MAX_LIMIT)
    max_bytes: int = Field(default=256 * 1024, ge=1024, le=1024 * 1024)
    case_id: str | None = None


def _with_limit(sql: str, limit: int) -> str:
    if re.search(r"\blimit\b", sql, re.IGNORECASE):
        return sql
    if sql.split(None, 1)[0].lower() in {"show", "explain", "describe", "desc"}:
        return sql
    return f"{sql} LIMIT {int(limit)}"


async def db_read(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(DbReadInput, arguments)
    sql = parse_read(params.sql)
    result = get_runtime().mysql.select(_with_limit(sql, params.limit))
    rows = result.rows
    truncated = False
    if len(rows) > params.limit:
        rows = rows[: params.limit]
        truncated = True
    encoded = len(str(rows).encode())
    if encoded > params.max_bytes:
        raise ToolError(
            ErrorCode.TRUNCATED,
            f"Result {encoded} bytes exceeds max_bytes={params.max_bytes}",
            retryable=True,
            hint="Reduce columns, add WHERE clause, or lower limit",
        )
    data = {
        "columns": result.columns,
        "rows": rows,
        "row_count": len(rows),
        "elapsed_ms": result.elapsed_ms,
        "truncated": truncated,
        "observed_at": now_iso(),
    }
    return ToolOutput(data=data)


# ---------------------------------------------------------------------------
# db_write
# ---------------------------------------------------------------------------


class DbWriteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str
    case_id: str = ""
    dry_run: bool = False
    expect_affected: int | None = None
    allow_multi: bool = False


@dataclass(slots=True)
class _WritePlan:
    statement: WriteStatement
    before: list[dict[str, Any]] = field(default_factory=list)


def _pk_where(pk: list[str], row: dict[str, Any]) -> str:
    return " AND ".join(f"{quote_ident(col)} = {_literal(row.get(col))}" for col in pk)


def _literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    text = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{text}'"


def _undo_sql_insert(table: str, pk: list[str], after: list[dict[str, Any]]) -> str:
    if not after:
        return ""
    if pk:
        return f"DELETE FROM {quote_ident(table)} WHERE {_pk_where(pk, after[0])}"
    keys = list(after[0].keys())
    parts = " AND ".join(f"{quote_ident(k)} = {_literal(after[0][k])}" for k in keys)
    return f"DELETE FROM {quote_ident(table)} WHERE {parts}"


def _undo_sql_update(table: str, pk: list[str], before: list[dict[str, Any]]) -> str:
    statements: list[str] = []
    for row in before:
        assignments = ", ".join(
            f"{quote_ident(k)} = {_literal(v)}" for k, v in row.items() if k not in pk
        )
        if not assignments:
            continue
        statements.append(
            f"UPDATE {quote_ident(table)} SET {assignments} WHERE {_pk_where(pk, row)}"
        )
    return ";\n".join(statements)


def _undo_sql_delete(table: str, before: list[dict[str, Any]]) -> str:
    statements: list[str] = []
    for row in before:
        cols = ", ".join(quote_ident(k) for k in row)
        values = ", ".join(_literal(v) for v in row.values())
        statements.append(f"INSERT INTO {quote_ident(table)} ({cols}) VALUES ({values})")
    return ";\n".join(statements)


def _where_clause(sql: str, op: str) -> str:
    match = re.search(r"\bwhere\b(.*)$", sql, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return match.group(1).strip()


def _select_where(adapter: MysqlAdapter, table: str, where: str, limit: int) -> list[dict[str, Any]]:
    sql = f"SELECT * FROM {quote_ident(table)}"
    if where:
        sql += f" WHERE {where}"
    sql += f" LIMIT {int(limit)}"
    return adapter.select(sql).rows


async def db_write(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(DbWriteInput, arguments)
    rt = get_runtime()
    adapter = rt.mysql
    statement = parse_write(params.sql)
    pk = adapter.primary_key(statement.table)

    where = _where_clause(statement.sql, statement.op) if statement.op != "insert" else ""
    before: list[dict[str, Any]] = []
    if statement.op in {"update", "delete"}:
        limit = max(rt.settings.profile.max_rows_per_write, 1) + 1 if not params.allow_multi else MAX_LIMIT
        before = _select_where(adapter, statement.table, where, limit)

    policy.check_write(
        profile=rt.settings.profile,
        store=rt.store,
        case_id=params.case_id,
        statement=statement,
        rows=len(before) if before else statement.value_rows,
        allow_multi=params.allow_multi,
    )

    if params.dry_run:
        return ToolOutput(
            data={
                "dry_run": True,
                "would_affect": len(before) if statement.op != "insert" else 1,
                "before_image": before,
                "table": statement.table,
                "op": statement.op,
            }
        )

    if statement.op in {"update", "delete"} and not pk:
        raise ToolError(
            ErrorCode.UNSUPPORTED,
            f"Table {statement.table} has no primary key; cannot generate verifiable undo",
            hint="Select a target table with a primary key, or use INSERT (rollback via auto-increment PK)",
        )

    conn = adapter.connect()
    try:
        with conn.cursor() as cur:
            cur.execute(statement.sql)
            affected = cur.rowcount
            insert_id = cur.lastrowid
            after: list[dict[str, Any]] = []
            if statement.op == "insert" and insert_id:
                if pk:
                    cur.execute(
                        f"SELECT * FROM {quote_ident(statement.table)}"
                        f" WHERE {quote_ident(pk[0])} = %s LIMIT 1",
                        (insert_id,),
                    )
                    after = [dict(r) for r in cur.fetchall()]
            elif statement.op == "update" and where:
                cur.execute(
                    f"SELECT * FROM {quote_ident(statement.table)} WHERE {where}"
                    f" LIMIT {int(rt.settings.profile.max_rows_per_write)}"
                )
                after = [dict(r) for r in cur.fetchall()]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if statement.op == "insert":
        undo_sql = _undo_sql_insert(statement.table, pk, after)
    elif statement.op == "update":
        undo_sql = _undo_sql_update(statement.table, pk, before)
    else:
        undo_sql = _undo_sql_delete(statement.table, before)

    change_id = f"ch-{uuid.uuid4().hex[:12]}"
    change = {
        "change_id": change_id,
        "agent": rt.settings.profile.name,
        "case_id": params.case_id,
        "table": statement.table,
        "op": statement.op,
        "affected": affected,
        "before_image": before,
        "after_image": after,
        "undo_sql": undo_sql,
        "ts": now_iso(),
        "sql": statement.sql,
    }
    rt.store.add_change(change)
    refs = [rt.store.add_evidence(params.case_id, "change", "db_write", change)]

    if params.expect_affected is not None and affected != params.expect_affected:
        raise ToolError(
            ErrorCode.CONFLICT,
            f"affected={affected} does not match expect_affected={params.expect_affected} (change_id={change_id} recorded)",
            retryable=False,
            hint="Change persisted; use db_undo to rollback by case",
        )
    if affected > 1 and not params.allow_multi:
        raise ToolError(
            ErrorCode.CONFLICT,
            f"affected={affected} > 1 (change_id={change_id} recorded)",
            retryable=False,
            hint="Multi-row impact requires explicit allow_multi; rollback still available via db_undo",
        )

    return ToolOutput(
        data={
            "change": {
                "change_id": change_id,
                "affected": affected,
                "before_image": before,
                "after_image": after,
                "undo_sql": undo_sql,
                "table": statement.table,
                "op": statement.op,
                "ts": change["ts"],
            },
            "observed_at": change["ts"],
        },
        evidence_refs=refs,
    )


# ---------------------------------------------------------------------------
# db_undo
# ---------------------------------------------------------------------------


class DbUndoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_id: str | None = None
    case_id: str | None = None
    order: Literal["reverse", "forward"] = "reverse"


def _load_change(change: dict[str, Any]) -> dict[str, Any]:
    """In sqlite, before/after images are stored as JSON text; deserialize before use."""
    out = dict(change)
    for key in ("before_image", "after_image"):
        value = out.get(key)
        if isinstance(value, str):
            out[key] = json.loads(value) if value else []
    return out


def _split_sql(script: str) -> list[str]:
    return [part.strip() for part in script.split(";\n") if part.strip()]


def _residue(adapter: MysqlAdapter, change: dict[str, Any]) -> int:
    """Number of rows still mismatching before_image after rollback."""
    table = str(change["table_name"])
    before = change["before_image"]
    after = change["after_image"]
    pk = adapter.primary_key(table)
    if not pk:
        return 0
    residue = 0
    if change["op"] == "insert":
        for row in after:
            found = _select_where(adapter, table, _pk_where(pk, row), 1)
            residue += len(found)
    elif change["op"] == "update":
        for row in before:
            found = _select_where(adapter, table, _pk_where(pk, row), 1)
            if not found or any(found[0].get(k) != v for k, v in row.items() if k in found[0]):
                residue += 1
    else:
        for row in before:
            found = _select_where(adapter, table, _pk_where(pk, row), 1)
            if not found:
                residue += 1
    return residue


async def db_undo(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(DbUndoInput, arguments)
    rt = get_runtime()
    if not params.change_id and not params.case_id:
        raise _bad("At least one of change_id or case_id must be provided")

    changes: list[dict[str, Any]] = []
    if params.change_id:
        change = rt.store.get_change(params.change_id)
        if change is None:
            raise ToolError(ErrorCode.NOT_FOUND, f"change not found: {params.change_id}")
        if change["agent"] != rt.settings.profile.name:
            raise ToolError(
                ErrorCode.POLICY_DENIED,
                "can only roll back changes within the current profile namespace",
                hint=f"this change belongs to {change['agent']}",
            )
        changes = [change]
    else:
        rows = rt.store.list_changes(params.case_id or "", pending_only=True)
        changes = rows if params.order == "forward" else list(reversed(rows))

    changes = [_load_change(c) for c in changes]
    adapter = rt.mysql
    reverted: list[dict[str, Any]] = []
    residue = 0
    for change in changes:
        if change["reverted"]:
            continue
        statements = _split_sql(str(change["undo_sql"]))
        ok = True
        rows_affected = 0
        try:
            conn = adapter.connect()
            try:
                with conn.cursor() as cur:
                    for statement in statements:
                        cur.execute(statement)
                        rows_affected += max(cur.rowcount, 0)
                conn.commit()
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 - rollback failures must be logged accurately, do not interrupt the entire finalization
            reverted.append({"change_id": change["id"], "ok": False, "error": str(exc)})
            continue
        if ok:
            rt.store.mark_change_reverted(change["id"])
        reverted.append({"change_id": change["id"], "ok": ok, "rows": rows_affected})

    for change in changes:
        if change["reverted"]:
            continue
        residue += _residue(adapter, change)

    refs: list[str] = []
    if params.case_id:
        refs.append(
            rt.store.add_evidence(
                params.case_id, "db", "db_undo", {"reverted": reverted, "residue": residue}
            )
        )
    return ToolOutput(
        data={
            "reverted": reverted,
            "residue": residue,
            "verified_by": "before_image",
            "observed_at": now_iso(),
        },
        evidence_refs=refs,
    )
