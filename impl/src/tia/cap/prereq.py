"""Read-only schema prerequisites tool.

``db_prerequisites`` answers "what does this table need for an INSERT to be
legal": required columns, foreign-key parents, enum domains and widths. It never
returns sample rows and never writes, so every agent (including main) may call it
before constructing a row.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.cap.registry import ToolOutput
from tia.cap.schema import (
    _CHILD_SQL,
    _COLUMN_SQL,
    _FK_SQL,
    build_brief,
    columns_from_rows,
    parents_from_rows,
    valid_table,
)
from tia.inf.runtime import get_runtime
from tia.schemas.envelope import ErrorCode, ToolError


class DbPrerequisitesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    table: str
    payload_columns: list[str] = Field(default_factory=list)


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


async def db_prerequisites(arguments: dict[str, Any]) -> ToolOutput:
    """Return the SchemaBrief for one table (facts only)."""

    try:
        params = DbPrerequisitesInput.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"Invalid parameter: {exc.errors()[0]['msg']}") from exc
    if not valid_table(params.table):
        raise _bad(f"Invalid table name: {params.table!r}")
    rt = get_runtime()
    rows = rt.mysql.select(_COLUMN_SQL.format(table=params.table)).rows
    facts = columns_from_rows(rows)
    if not facts:
        raise ToolError(
            ErrorCode.NOT_FOUND,
            f"Table has no readable columns: {params.table}",
            hint="Check the table name and the database account's privileges",
        )
    parents = parents_from_rows(rt.mysql.select(_FK_SQL.format(table=params.table)).rows)
    child_rows = rt.mysql.select(_CHILD_SQL.format(table=params.table)).rows
    from tia.cap.schema import ForeignKey

    children = [
        ForeignKey(
            column=str(row.get("column_name") or ""),
            parent_table=str(row.get("table_name") or ""),
            parent_column=str(row.get("parent_column") or ""),
        )
        for row in child_rows
        if str(row.get("table_name") or "")
    ]
    brief = build_brief(
        params.table, facts, parents, children, payload_columns=params.payload_columns
    )
    return ToolOutput(
        data={
            "table": brief.table,
            "required": brief.required,
            "optional": brief.optional,
            "defaults": brief.defaults,
            "enums": brief.enums,
            "widths": brief.widths,
            "parents": [item.to_dict() for item in brief.parents],
            "children": [item.to_dict() for item in brief.children],
            "notes": brief.notes,
        }
    )
