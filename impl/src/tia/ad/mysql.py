"""MySQL adapter.

Responsibility is limited to "sending SQL and reading results back", with no business logic.
Connection info comes from :class:`tia.inf.config.DbConfig`; the account is created by ``scripts/setup-db.sh``
using root, with only SELECT/INSERT/UPDATE/DELETE privileges on the target database.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from tia.inf.config import DbConfig
from tia.schemas.envelope import ErrorCode, ToolError


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: list[dict[str, Any]]
    rows: list[dict[str, Any]]
    elapsed_ms: int


class MysqlAdapter:
    def __init__(self, config: DbConfig) -> None:
        self.config = config

    # -- Connection -------------------------------------------------------------

    def connect(self) -> pymysql.connections.Connection:
        if not self.config.configured:
            raise ToolError(
                ErrorCode.ENV_ERROR,
                "Target database not configured",
                retryable=False,
                hint="Set TIA_DB_NAME (user-provided database name), or pass --db-name",
            )
        try:
            return pymysql.connect(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                password=self.config.password,
                database=self.config.name,
                charset=self.config.charset,
                cursorclass=DictCursor,
                autocommit=False,
                connect_timeout=5,
                read_timeout=30,
            )
        except pymysql.MySQLError as exc:
            raise ToolError(
                ErrorCode.ENV_ERROR,
                f"Cannot connect to target database: {exc}",
                retryable=True,
                hint="Ensure MariaDB is running in the container and the account has been created by scripts/setup-db.sh",
            ) from exc

    # -- Read ---------------------------------------------------------------

    def select(self, sql: str, params: tuple[Any, ...] | None = None) -> QueryResult:
        started = time.perf_counter()
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]
            columns = [
                {"name": str(d[0]), "type": _type_name(d[1])} for d in (cur.description or ())
            ]
        return QueryResult(columns=columns, rows=rows, elapsed_ms=_ms(started))

    def scalar(self, sql: str, params: tuple[Any, ...] | None = None) -> Any:
        result = self.select(sql, params)
        if not result.rows:
            return None
        return next(iter(result.rows[0].values()))

    # -- Table Schema -----------------------------------------------------------

    def table_schema(self, tables: list[str]) -> list[dict[str, Any]]:
        if not tables:
            return []
        placeholders = ",".join(["%s"] * len(tables))
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT,"
                " COLUMN_KEY, EXTRA, CHARACTER_MAXIMUM_LENGTH, NUMERIC_PRECISION"
                " FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()"
                f" AND TABLE_NAME IN ({placeholders}) ORDER BY TABLE_NAME, ORDINAL_POSITION",
                tuple(tables),
            )
            column_rows = [dict(r) for r in cur.fetchall()]
            cur.execute(
                "SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME"
                " FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE()"
                f" AND REFERENCED_TABLE_NAME IS NOT NULL AND TABLE_NAME IN ({placeholders})",
                tuple(tables),
            )
            fk_rows = [dict(r) for r in cur.fetchall()]
            cur.execute(
                "SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME, NON_UNIQUE"
                " FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()"
                f" AND TABLE_NAME IN ({placeholders}) ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
                tuple(tables),
            )
            index_rows = [dict(r) for r in cur.fetchall()]

        by_table: dict[str, dict[str, Any]] = {}
        for row in column_rows:
            entry = by_table.get(str(row["TABLE_NAME"]))
            if entry is None:
                entry = {
                    "name": row["TABLE_NAME"],
                    "columns": [],
                    "primary_key": [],
                    "fks": [],
                    "indexes": [],
                }
                by_table[str(row["TABLE_NAME"])] = entry
            length = row["CHARACTER_MAXIMUM_LENGTH"] or row["NUMERIC_PRECISION"]
            entry["columns"].append(
                {
                    "name": row["COLUMN_NAME"],
                    "type": str(row["DATA_TYPE"]),
                    "nullable": row["IS_NULLABLE"] == "YES",
                    "default": row["COLUMN_DEFAULT"],
                    "extra": row["EXTRA"] or "",
                    "length": int(length) if length is not None else None,
                }
            )
            if row["COLUMN_KEY"] == "PRI":
                entry["primary_key"].append(row["COLUMN_NAME"])
        for row in fk_rows:
            entry = by_table.get(str(row["TABLE_NAME"]))
            if entry is not None:
                entry["fks"].append(
                    {
                        "column": row["COLUMN_NAME"],
                        "ref_table": row["REFERENCED_TABLE_NAME"],
                        "ref_column": row["REFERENCED_COLUMN_NAME"],
                    }
                )
        for row in index_rows:
            entry = by_table.get(str(row["TABLE_NAME"]))
            if entry is None:
                continue
            index: dict[str, Any] | None = next(
                (i for i in entry["indexes"] if i["name"] == row["INDEX_NAME"]), None
            )
            if index is None:
                index = {
                    "name": row["INDEX_NAME"],
                    "columns": [],
                    "unique": not bool(row["NON_UNIQUE"]),
                }
                entry["indexes"].append(index)
            index["columns"].append(row["COLUMN_NAME"])

        result: list[dict[str, Any]] = []
        for name in tables:
            entry = by_table.get(name)
            if entry is None:
                continue
            entry["rows_estimate"] = self._row_estimate(name)
            result.append(entry)
        return result

    def _row_estimate(self, table: str) -> int | None:
        value = self.scalar(
            "SELECT TABLE_ROWS FROM information_schema.TABLES"
            " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
            (table,),
        )
        return int(value) if value is not None else None

    def primary_key(self, table: str) -> list[str]:
        rows = self.select(
            "SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE"
            " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND CONSTRAINT_NAME = 'PRIMARY'"
            " ORDER BY ORDINAL_POSITION",
            (table,),
        )
        return [str(r["COLUMN_NAME"]) for r in rows.rows]


def quote_ident(name: str) -> str:
    if not name or not all(ch.isalnum() or ch in "_$" for ch in name):
        raise ToolError(ErrorCode.BAD_ARGS, f"Invalid identifier: {name!r}")
    return f"`{name}`"


def _type_name(code: int) -> str:
    mapping = {
        0: "decimal", 1: "tinyint", 2: "smallint", 3: "int", 4: "float", 5: "double",
        7: "timestamp", 8: "bigint", 10: "date", 12: "datetime", 13: "year",
        15: "varchar", 16: "bit", 246: "decimal", 252: "blob", 253: "varchar", 254: "char",
    }
    return mapping.get(code, f"type{code}")


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
