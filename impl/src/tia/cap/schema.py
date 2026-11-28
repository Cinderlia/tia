"""Schema facts for building a legal row.

An INSERT is rejected when a required column has no value (NOT NULL without a
default), a foreign key has no parent row, an enum value is out of range or a
value is wider than the column. Those are facts about the table, not about the
attack, so they are collected once from ``information_schema`` and handed to the
planner as a short brief. This module is pure data shaping (unit-testable);
``db_prerequisites`` exposes it as a read-only tool and ``state_probe`` is its
heaviest consumer.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

MAX_TABLE = 64
_TABLE_NAME = re.compile(r"^[A-Za-z0-9_]+$")
_ENUM = re.compile(r"^enum\((.*)\)$", re.IGNORECASE)

#: Columns that must never be written from a planned state step.
DENY_COLUMN = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|hash|salt|credit|card)",
    re.IGNORECASE,
)
#: Column names that usually come from the logged-in identity.
CONTEXT_COLUMN = re.compile(
    r"(^|_)(user|customer|owner|member|session|account|author)(_id|_name)?$",
    re.IGNORECASE,
)

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class ColumnFact:
    name: str
    data_type: str = ""
    column_type: str = ""
    nullable: bool = True
    default: str | None = None
    extra: str = ""
    width: int | None = None
    key: str = ""

    @property
    def auto(self) -> bool:
        return bool(re.search(r"auto_increment|generated", self.extra, re.IGNORECASE))

    @property
    def enum(self) -> list[str]:
        match = _ENUM.match(self.column_type)
        if not match:
            return []
        return [item.strip().strip("'") for item in match.group(1).split(",")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.column_type or self.data_type,
            "nullable": self.nullable,
            "default": self.default,
            "auto": self.auto,
            "width": self.width,
            "key": self.key,
            "enum": self.enum,
        }


@dataclass(frozen=True, slots=True)
class ForeignKey:
    column: str
    parent_table: str
    parent_column: str
    delete_rule: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "column": self.column,
            "parent_table": self.parent_table,
            "parent_column": self.parent_column,
            "delete_rule": self.delete_rule,
        }


@dataclass(slots=True)
class SchemaBrief:
    table: str
    required: list[dict[str, Any]] = field(default_factory=list)
    optional: list[dict[str, Any]] = field(default_factory=list)
    defaults: dict[str, str] = field(default_factory=dict)
    enums: dict[str, list[str]] = field(default_factory=dict)
    widths: dict[str, int] = field(default_factory=dict)
    parents: list[ForeignKey] = field(default_factory=list)
    children: list[ForeignKey] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "required": self.required,
            "optional": self.optional,
            "defaults": self.defaults,
            "enums": self.enums,
            "widths": self.widths,
            "parents": [item.to_dict() for item in self.parents],
            "children": [item.to_dict() for item in self.children],
            "notes": self.notes,
        }


def valid_table(name: str) -> bool:
    return bool(name) and len(name) <= MAX_TABLE and bool(_TABLE_NAME.match(name))


def classify_columns(
    columns: Sequence[ColumnFact],
    parents: Iterable[ForeignKey] = (),
    *,
    payload_columns: Iterable[str] = (),
) -> dict[str, Any]:
    """Split columns into required (must be supplied) and optional facts."""

    payload = {str(item) for item in payload_columns}
    parent_of = {item.column: item for item in parents}
    required: list[dict[str, Any]] = []
    optional: list[dict[str, Any]] = []
    defaults: dict[str, str] = {}
    enums: dict[str, list[str]] = {}
    widths: dict[str, int] = {}
    for column in columns:
        if column.width:
            widths[column.name] = int(column.width)
        values = column.enum
        if values:
            enums[column.name] = values
        if column.default is not None:
            defaults[column.name] = str(column.default)
        fact = column.to_dict()
        if column.name in payload:
            fact["payload"] = True
            optional.append(fact)
            continue
        missing = not column.nullable and column.default is None and not column.auto
        if not missing:
            optional.append(fact)
            continue
        if column.name in parent_of:
            fact["prerequisite"] = "row"
            fact["parent"] = parent_of[column.name].parent_table
        elif values:
            fact["prerequisite"] = "constant"
            fact["choices"] = values
        elif CONTEXT_COLUMN.search(column.name):
            fact["prerequisite"] = "context"
        else:
            fact["prerequisite"] = "constant"
        required.append(fact)
    return {
        "required": required,
        "optional": optional,
        "defaults": defaults,
        "enums": enums,
        "widths": widths,
    }


def build_brief(
    table: str,
    columns: Sequence[ColumnFact],
    parents: Sequence[ForeignKey] = (),
    children: Sequence[ForeignKey] = (),
    *,
    payload_columns: Iterable[str] = (),
) -> SchemaBrief:
    shaped = classify_columns(columns, parents, payload_columns=payload_columns)
    notes: list[str] = []
    for item in shaped["required"]:
        if item.get("prerequisite") == "constant" and not item.get("choices"):
            notes.append(f"{item['name']}: no default; a safe constant is needed")
    return SchemaBrief(
        table=table,
        required=shaped["required"],
        optional=shaped["optional"],
        defaults=shaped["defaults"],
        enums=shaped["enums"],
        widths=shaped["widths"],
        parents=list(parents),
        children=list(children),
        notes=notes,
    )


def render_brief(brief: SchemaBrief | dict[str, Any] | None) -> str:
    """Short text block for a planning prompt (never a raw schema dump)."""

    if brief is None:
        return ""
    data = brief.to_dict() if isinstance(brief, SchemaBrief) else brief
    table = str(data.get("table") or "")
    required = data.get("required") or []
    parents = data.get("parents") or []
    if not required and not parents:
        return ""
    lines = [
        f"SCHEMA PREREQUISITES for `{table}` (an INSERT without these columns is "
        f"rejected by the database):"
    ]
    for item in required[:12]:
        name = str(item.get("name") or "")
        kind = str(item.get("prerequisite") or "constant")
        detail = f"type={item.get('type') or '?'}"
        if item.get("choices"):
            detail += f" values={item['choices'][:8]}"
        if item.get("parent"):
            detail += f" references {item['parent']}"
        if item.get("width"):
            detail += f" width={item['width']}"
        lines.append(f"- {name}: {kind} ({detail})")
    for parent in parents[:8]:
        if parent.get("column") in {item.get("name") for item in required}:
            continue
        lines.append(
            f"- optional parent: {parent['column']} -> "
            f"{parent['parent_table']}.{parent['parent_column']}"
        )
    return "\n".join(lines)


_COLUMN_SQL = """
SELECT COLUMN_NAME AS name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type,
       IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default,
       EXTRA AS extra, CHARACTER_MAXIMUM_LENGTH AS width, COLUMN_KEY AS column_key
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}'
 ORDER BY ORDINAL_POSITION
"""

_FK_SQL = """
SELECT k.COLUMN_NAME AS column_name, k.REFERENCED_TABLE_NAME AS parent_table,
       k.REFERENCED_COLUMN_NAME AS parent_column, r.DELETE_RULE AS delete_rule
  FROM information_schema.KEY_COLUMN_USAGE k
  LEFT JOIN information_schema.REFERENTIAL_CONSTRAINTS r
    ON r.CONSTRAINT_NAME = k.CONSTRAINT_NAME AND r.CONSTRAINT_SCHEMA = k.TABLE_SCHEMA
 WHERE k.TABLE_SCHEMA = DATABASE() AND k.TABLE_NAME = '{table}'
   AND k.REFERENCED_TABLE_NAME IS NOT NULL
"""

_CHILD_SQL = """
SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name,
       REFERENCED_COLUMN_NAME AS parent_column
  FROM information_schema.KEY_COLUMN_USAGE
 WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME = '{table}'
"""


def _bool(value: Any) -> bool:
    return str(value or "").strip().upper() in {"YES", "1", "TRUE"}


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def columns_from_rows(rows: Sequence[dict[str, Any]]) -> list[ColumnFact]:
    return [
        ColumnFact(
            name=str(row.get("name") or ""),
            data_type=str(row.get("data_type") or ""),
            column_type=str(row.get("column_type") or ""),
            nullable=_bool(row.get("is_nullable")),
            default=None if row.get("column_default") is None else str(row.get("column_default")),
            extra=str(row.get("extra") or ""),
            width=_int(row.get("width")),
            key=str(row.get("column_key") or ""),
        )
        for row in rows
        if str(row.get("name") or "")
    ]


def parents_from_rows(rows: Sequence[dict[str, Any]]) -> list[ForeignKey]:
    return [
        ForeignKey(
            column=str(row.get("column_name") or ""),
            parent_table=str(row.get("parent_table") or ""),
            parent_column=str(row.get("parent_column") or ""),
            delete_rule=str(row.get("delete_rule") or ""),
        )
        for row in rows
        if str(row.get("column_name") or "") and str(row.get("parent_table") or "")
    ]


async def fetch_brief(
    call: Call,
    table: str,
    *,
    payload_columns: Iterable[str] = (),
) -> SchemaBrief:
    """Collect the facts through ``db_schema`` (the read-only schema tool).

    ``information_schema`` is a system schema, so a raw ``db_read`` is rejected by
    the SQL policy; ``db_schema`` performs the same lookups in the adapter.
    """

    if not valid_table(table):
        raise ValueError(f"invalid table name: {table!r}")
    answer = await call("db_schema", {"table": table, "include": ["columns", "fks"]})
    tables = (answer or {}).get("tables") or []
    if not tables:
        raise ValueError(f"table not found: {table}")
    entry = tables[0]
    facts = [
        ColumnFact(
            name=str(item.get("name") or ""),
            data_type=str(item.get("type") or ""),
            column_type=str(item.get("column_type") or item.get("type") or ""),
            nullable=bool(item.get("nullable")),
            default=None if item.get("default") is None else str(item.get("default")),
            extra=str(item.get("extra") or ""),
            width=item.get("length"),
            key="PRI" if item.get("name") in (entry.get("primary_key") or []) else "",
        )
        for item in entry.get("columns") or []
    ]
    if not facts:
        raise ValueError(f"table not found or not readable: {table}")
    parents = [
        ForeignKey(
            column=str(item.get("column") or ""),
            parent_table=str(item.get("ref_table") or ""),
            parent_column=str(item.get("ref_column") or ""),
            delete_rule=str(item.get("delete_rule") or ""),
        )
        for item in entry.get("fks") or []
        if item.get("ref_table")
    ]
    return build_brief(table, facts, parents, [], payload_columns=payload_columns)
