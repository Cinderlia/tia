"""Let the model write the SQL that stores a payload, with a payload placeholder.

The harness never guesses which column or row the payload belongs in. It hands the
model the executed read statement (captured by the SQL probe), the rows that read
returned, the table schema and the payload format; the model replies with one
INSERT/UPDATE whose payload value is written as ``{{PAYLOAD}}``. The local side only
renders the placeholder, and checks the statement against the structural rules
(single statement, allowed table/columns, WHERE on UPDATE).
"""

from __future__ import annotations

import json
from typing import Any

from tia.cap.sqlparse import WriteStatement, parse_write
from tia.schemas.envelope import ErrorCode, ToolError

PAYLOAD_MARK = "{{PAYLOAD}}"
ROW_MARK = "{{ROW_ID}}"

MAX_ROWS = 8
MAX_SQL_CHARS = 4_000

WRITE_PROMPT = """\
You write one SQL statement that stores a marker payload so the page renders it at
the sink below. Reply with JSON only: {"sql": "...", "reason": "..."}.

Rules:
- Reply with the column that receives the payload in "column": the column the sink
  prints. It must be one of the table columns below.
- Put {{PAYLOAD}} exactly once, at the position where the payload value belongs.
  Never write the payload yourself: it changes between attempts.
- {{ROW_ID}} may be used at most once for a primary key; it is replaced by one of
  the RETURNED ROWS below. Prefer an UPDATE of a row the executed read returned,
  so the read path will show the change; use INSERT when no row is usable.
- UPDATE must have a WHERE clause. One statement only. No DDL, comments,
  semicolons inside the statement, or multiple statements.
- Write the payload into the column the sink expression prints.
"""


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text.upper() == "NOW()":
        return "NOW()"
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def render(template: str, *, payload: str, row_id: Any = None) -> str:
    """Substitute the markers with literals. The markers must occur once at most."""
    if template.count(PAYLOAD_MARK) != 1:
        raise _bad("the SQL template must contain {{PAYLOAD}} exactly once")
    if template.count(ROW_MARK) > 1:
        raise _bad("the SQL template may contain {{ROW_ID}} at most once")
    sql = template.replace(PAYLOAD_MARK, _literal(payload))
    if ROW_MARK in sql:
        if row_id is None:
            raise _bad("the SQL template needs {{ROW_ID}} but no row was returned")
        sql = sql.replace(ROW_MARK, _literal(row_id))
    return sql


def compile(
    template: str,
    *,
    table: str,
    columns: list[str],
    payload: str,
    row_id: Any = None,
) -> tuple[str, WriteStatement]:
    """Render and structurally check one write statement."""
    sql = render(template, payload=payload, row_id=row_id)
    statement = parse_write(sql)
    if statement.op not in ("insert", "update"):
        raise _bad("only INSERT and UPDATE are accepted here")
    if statement.table.lower() != table.lower():
        raise _bad(f"the statement writes {statement.table!r}, expected {table!r}")
    unknown = [name for name in statement.columns if name not in columns]
    if unknown:
        raise _bad(f"unknown columns: {', '.join(unknown)}")
    if statement.op == "update" and not statement.has_where:
        raise _bad("an UPDATE must have a WHERE clause")
    return sql, statement


def _rows_view(rows: list[dict[str, Any]], *, limit: int = MAX_ROWS) -> list[dict[str, Any]]:
    view: list[dict[str, Any]] = []
    for row in rows[:limit]:
        view.append({str(key): value for key, value in row.items()})
    return view


def _prompt(
    *,
    sink: str,
    table: str,
    schema: str,
    observed: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    payload: str,
    tag: str,
    error: str = "",
) -> str:
    lines = [
        f"SINK: {sink}",
        f"TABLE: `{table}`",
        f"SCHEMA: {schema}",
        f"PAYLOAD FORMAT: an HTML/JavaScript payload such as {payload!r}; "
        f"it always contains the four-character tag {tag!r}, which must survive verbatim. "
        "The exact payload varies between attempts and is supplied through {{PAYLOAD}}.",
    ]
    if observed:
        lines.append("EXECUTED READ (captured from the running application):")
        for index, item in enumerate(observed[:4], start=1):
            lines.append(f"{index}. line {item.get('line')}: {item.get('sql')}")
            sample = _rows_view(item.get("rows") or [])
            if sample:
                lines.append(f"   rows: {json.dumps(sample, ensure_ascii=False, default=str)[:1500]}")
    else:
        lines.append(
            "EXECUTED READ: none captured. Explore the schema and write an INSERT "
            "that satisfies every NOT NULL column and foreign key."
        )
    if rows:
        lines.append(f"RETURNED ROWS (for {{{{ROW_ID}}}}): {json.dumps(_rows_view(rows), ensure_ascii=False, default=str)[:2000]}")
    if error:
        lines.append(f"THE PREVIOUS ATTEMPT FAILED: {error[:800]}")
    return "\n".join(lines)


async def plan_write_sql(
    model: Any,
    *,
    sink: str,
    table: str,
    columns: list[str],
    schema: str,
    observed: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    payload: str,
    tag: str,
    error: str = "",
) -> dict[str, Any]:
    """Ask the model for one write statement with a payload placeholder."""
    if model is None:
        raise _bad("no model is configured for the write statement")
    prompt = _prompt(
        sink=sink,
        table=table,
        schema=schema,
        observed=observed,
        rows=rows,
        payload=payload,
        tag=tag,
        error=error,
    )
    reply = await model.complete_json(WRITE_PROMPT + "\n" + prompt, {})
    template = ""
    if isinstance(reply, dict):
        template = str(reply.get("sql") or "").strip()
    if not template:
        raise _bad("the model returned no SQL")
    if len(template) > MAX_SQL_CHARS:
        raise _bad("the SQL template is too long")
    column = str(reply.get("column") or "").strip() if isinstance(reply, dict) else ""
    if not column or column not in columns:
        raise _bad("the model did not name the column that receives the payload")
    if column not in template:
        raise _bad("the SQL does not write the declared payload column")
    row_values = [row.get("id") for row in rows if row.get("id") is not None]
    rendered, _ = compile(
        template,
        table=table,
        columns=columns,
        payload=payload,
        row_id=row_values[0] if row_values else None,
    )
    return {
        "template": template,
        "sql": rendered,
        "column": column,
        "row_id": row_values[0] if row_values else None,
        "reason": str(reply.get("reason") or "") if isinstance(reply, dict) else "",
    }
