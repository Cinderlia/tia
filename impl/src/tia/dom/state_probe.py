"""Insert prerequisites: what a row needs before the database accepts it.

``run_state_probe`` answers one question -- "which values make this INSERT legal?"
-- from facts, not guesses: required columns come from :mod:`tia.cap.schema`,
foreign keys are satisfied by *reusing* an existing parent row, enum domains pick
a valid member and everything else gets a type-appropriate constant. The result
is a :class:`StatePlan` the caller can merge into its own INSERT.

M2 scope: constants and existing parent rows only (both read-only). Creating a
missing parent row (application path first, controlled ``db_write`` second) is
M3, and that is where the plan starts carrying write steps with undo.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from tia.cap.schema import SchemaBrief, fetch_brief, valid_table

Call = Any


@dataclass(frozen=True, slots=True)
class StateProbeBudget:
    tables: int = 6
    depth: int = 2
    candidates: int = 3
    steps: int = 8
    llm: int = 2
    seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class StateProbeWriter:
    file: str = ""
    line: int = 0
    code: str = ""
    op: str = "insert"


@dataclass(slots=True)
class StateProbeRequest:
    case_id: str
    table: str
    payload_columns: list[str] = field(default_factory=list)
    failed_sql: str = ""
    error_text: str = ""
    writer: StateProbeWriter = field(default_factory=StateProbeWriter)
    read_sql: str = ""
    budget: StateProbeBudget = field(default_factory=StateProbeBudget)
    context_values: dict[str, str] = field(default_factory=dict)
    verify_insert: bool = False
    probe_tag: str = ""
    create_parents: bool = True
    register_targets: Any = None
    review: Any = None


@dataclass(slots=True)
class Prerequisite:
    kind: Literal["constant", "row", "context"]
    table: str
    column: str
    value: str | None = None
    source: Literal["existing", "inserted", "constant", "app", "session"] = "constant"
    confidence: int = 0
    depends_on: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "table": self.table,
            "column": self.column,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "depends_on": self.depends_on,
        }


@dataclass(slots=True)
class StateStep:
    action: Literal["db_write", "app_request", "reuse_row"]
    ref: str
    table: str
    sql: str = ""
    request: dict[str, Any] | None = None
    undo_ref: str | None = None
    verified: bool = False
    created: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ref": self.ref,
            "table": self.table,
            "sql": self.sql,
            "request": self.request,
            "undo_ref": self.undo_ref,
            "verified": self.verified,
            "created": self.created,
        }


@dataclass(slots=True)
class StateEvidence:
    kind: Literal["schema", "row", "probe", "db_after", "residue"]
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail}


@dataclass(slots=True)
class StatePlan:
    status: Literal["READY", "PARTIAL", "UNRESOLVED", "BRIEF_ONLY"]
    table: str
    schema_brief: SchemaBrief
    prerequisites: list[Prerequisite] = field(default_factory=list)
    steps: list[StateStep] = field(default_factory=list)
    evidence: list[StateEvidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stop_reason: str = ""
    values: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "table": self.table,
            "schema_brief": self.schema_brief.to_dict(),
            "prerequisites": [item.to_dict() for item in self.prerequisites],
            "steps": [item.to_dict() for item in self.steps],
            "evidence": [item.to_dict() for item in self.evidence],
            "notes": self.notes,
            "stop_reason": self.stop_reason,
            "values": self.values,
        }


_INT_TYPES = {"tinyint", "smallint", "mediumint", "int", "integer", "bigint"}
_FLOAT_TYPES = {"decimal", "numeric", "float", "double", "real"}
_DATE_TYPES = {"date", "datetime", "timestamp", "time", "year"}


def _safe_constant(fact: dict[str, Any]) -> tuple[str, int, bool]:
    """A value the database accepts, plus confidence and a review flag."""

    choices = fact.get("choices") or []
    if choices:
        return str(choices[0]), 40, False
    kind = str(fact.get("type") or "").lower()
    base = kind.split("(", 1)[0]
    if base in _INT_TYPES:
        return "1", 30, True
    if base in _FLOAT_TYPES:
        return "1", 30, True
    if base in _DATE_TYPES:
        return "NOW()", 30, True
    if base in {"enum", "set"}:
        return "", 20, True
    return "tia", 30, True


class _Unresolved(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


async def _pick_parent_row(
    call: Call, parent_table: str, parent_column: str, *, limit: int
) -> dict[str, Any] | None:
    try:
        result = await call(
            "db_read",
            {"sql": f"SELECT * FROM `{parent_table}` LIMIT {int(limit)}"},
        )
    except Exception:  # tool failures are expected for an unreadable parent
        return None
    rows = result.get("rows") if isinstance(result, dict) else None
    for row in rows or []:
        if isinstance(row, dict) and row.get(parent_column) is not None:
            return row
    return None


def _literal(value: str) -> str:
    if value == "NOW()":
        return "NOW()"
    if value.replace(".", "", 1).lstrip("-").isdigit():
        return value
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _insert_sql(table: str, values: dict[str, str]) -> str:
    columns = list(values)
    return (
        f"INSERT INTO `{table}` ({', '.join(f'`{c}`' for c in columns)}) "
        f"VALUES ({', '.join(_literal(values[c]) for c in columns)})"
    )


async def _insert_row(
    call: Call, table: str, values: dict[str, str], *, ref: str
) -> dict[str, Any]:
    """Insert one scaffold row and return its created key/values."""

    sql = _insert_sql(table, values)
    written = await call("db_write", {"sql": sql})
    change = written.get("change") if isinstance(written, dict) else None
    after = (change or {}).get("after_image") or []
    row = after[0] if after and isinstance(after[0], dict) else {}
    return {"sql": sql, "change_id": str((change or {}).get("change_id") or ""), "row": row}


async def _resolve_table(
    call: Call,
    table: str,
    payload_columns: list[str],
    plan: StatePlan,
    *,
    depth: int,
    visited: tuple[str, ...],
    tables: set[str],
    budget: StateProbeBudget,
    create_rows: bool,
    context: dict[str, str],
    register: Any = None,
) -> dict[str, str]:
    """Return the values this table's INSERT needs, creating parent rows if allowed."""

    if table in visited:
        raise _Unresolved("STATE_BUDGET", f"cycle: {' -> '.join([*visited, table])}")
    if depth < 0:
        raise _Unresolved("STATE_BUDGET", f"parent depth exceeded at {table}")
    if table not in tables and len(tables) >= budget.tables:
        raise _Unresolved("STATE_BUDGET", f"table budget {budget.tables} exhausted")
    tables.add(table)
    brief = await fetch_brief(call, table, payload_columns=payload_columns)
    parents = {item.column: item for item in brief.parents}
    values: dict[str, str] = {}
    for fact in brief.required:
        column = str(fact.get("name") or "")
        kind = str(fact.get("prerequisite") or "constant")
        if kind == "row":
            parent = parents.get(column)
            if parent is None:
                raise _Unresolved(
                    "STATE_PARENT_MISSING", f"{table}.{column}: foreign key metadata missing"
                )
            row = await _pick_parent_row(
                call, parent.parent_table, parent.parent_column, limit=budget.candidates
            )
            if row is not None:
                value = str(row[parent.parent_column])
                plan.prerequisites.append(
                    Prerequisite(
                        "row", parent.parent_table, parent.parent_column, value, "existing", 90
                    )
                )
                plan.evidence.append(
                    StateEvidence(
                        "row",
                        {
                            "table": parent.parent_table,
                            "column": parent.parent_column,
                            "value": value,
                            "reused": True,
                        },
                    )
                )
            elif not create_rows:
                raise _Unresolved(
                    "STATE_PARENT_MISSING",
                    f"{table}.{column}: no {parent.parent_table}.{parent.parent_column} row",
                )
            else:
                parent_values = await _resolve_table(
                    call,
                    parent.parent_table,
                    [],
                    plan,
                    depth=depth - 1,
                    visited=(*visited, table),
                    tables=tables,
                    budget=budget,
                    create_rows=create_rows,
                    context=context,
                    register=register,
                )
                if register is not None:
                    targets = [
                        {"table": parent.parent_table, "column": column_name, "mode": "insert"}
                        for column_name in parent_values
                    ] or [{"table": parent.parent_table, "mode": "insert"}]
                    register(targets)
                created = await _insert_row(
                    call, parent.parent_table, parent_values, ref=f"parent:{parent.parent_table}"
                )
                created_value = _created_value(created["row"], parent.parent_column)
                if created_value is None:
                    raise _Unresolved(
                        "STATE_WRITE_DENIED",
                        f"{parent.parent_table}: inserted row has no {parent.parent_column}",
                    )
                step = StateStep(
                    action="db_write",
                    ref=f"parent:{parent.parent_table}",
                    table=parent.parent_table,
                    sql=str(created["sql"]),
                    undo_ref=str(created["change_id"]) or None,
                    verified=True,
                    created={"column": parent.parent_column, "value": created_value},
                )
                plan.steps.append(step)
                plan.evidence.append(
                    StateEvidence(
                        "db_after",
                        {
                            "table": parent.parent_table,
                            "insert": created["sql"][:400],
                            "value": created_value,
                        },
                    )
                )
                plan.prerequisites.append(
                    Prerequisite(
                        "row",
                        parent.parent_table,
                        parent.parent_column,
                        created_value,
                        "inserted",
                        50,
                    )
                )
                value = created_value
            values[column] = value
        elif kind == "context":
            context_value = context.get(f"{table}.{column}") or context.get(column)
            if context_value is None:
                raise _Unresolved(
                    "STATE_REQUIRED_UNRESOLVED",
                    f"{table}.{column}: no session/account value available",
                )
            plan.prerequisites.append(
                Prerequisite("context", table, column, str(context_value), "session", 80)
            )
            values[column] = str(context_value)
        else:
            value, confidence, review = _safe_constant(fact)
            plan.prerequisites.append(
                Prerequisite("constant", table, column, value, "constant", confidence)
            )
            values[column] = value
            if review:
                plan.notes.append(f"{table}.{column}: safe constant {value!r} needs review")
    return values


def constant_review(model: Any | None = None) -> Any:
    """Build the optional model reviewer used for safe constants (None when no model)."""

    if model is None:
        try:
            from tia.ad.llm import LlmClient

            model = LlmClient.from_env()
        except Exception:  # noqa: BLE001 - the probe works without a model
            return None
    if model is None:
        return None

    async def review(prompt: str) -> dict[str, Any]:
        return await model.complete_json(
            "You choose safe database constants. Reply with JSON only.", prompt
        )

    return review


async def _review_constants(
    request: StateProbeRequest,
    brief: SchemaBrief,
    plan: StatePlan,
    values: dict[str, str],
) -> None:
    """Ask the model to review the safe defaults, once, then validate its answer."""

    review = request.review
    if review is None:
        return
    candidates = [
        item
        for item in plan.prerequisites
        if item.kind == "constant" and item.confidence < 50 and item.value is not None
    ]
    if not candidates:
        return
    facts = [
        {
            "column": item.column,
            "value": item.value,
            "type": next(
                (str(f.get("column_type") or f.get("type") or "") for f in brief.required
                 if str(f.get("name")) == item.column),
                "",
            ),
        }
        for item in candidates
    ]
    prompt = (
        "A PHP application INSERT failed. Choose a safe constant for each column below "
        "so the statement is accepted; keep the value short and free of quotes.\n"
        f"TABLE: {request.table}\n"
        f"FAILED SQL: {request.failed_sql[:600]}\n"
        f"ERROR: {request.error_text[:300]}\n"
        f"COLUMNS: {json.dumps(facts, ensure_ascii=False)}\n"
        'Reply as JSON: {"values": {"<column>": "<value>"}} and nothing else.'
    )
    try:
        answer = await review(prompt)
    except Exception as exc:  # noqa: BLE001 - the plan is still usable
        plan.notes.append(f"llm review failed: {str(exc)[:200]}")
        return
    data: Any = answer
    if isinstance(answer, str):
        text = answer.strip()
        if text.startswith("```"):
            text = text.strip("`")
            text = text.split("\n", 1)[1] if "\n" in text else text
        try:
            data = json.loads(text)
        except ValueError:
            plan.notes.append("llm review returned no JSON")
            return
    picked = data.get("values") if isinstance(data, dict) else None
    if not isinstance(picked, dict):
        plan.notes.append("llm review returned no values object")
        return
    allowed = {item.column for item in candidates}
    for column, value in picked.items():
        if str(column) not in allowed or not isinstance(value, (str, int)):
            continue
        text = str(value)
        if not text or len(text) > 200:
            continue
        for item in candidates:
            if item.column == str(column):
                item.value = text
                item.confidence = 70
                values[str(column)] = text
                plan.values[str(column)] = text
    plan.notes.append("llm reviewed the safe constants")


def _created_value(row: dict[str, Any], column: str) -> str | None:
    value = row.get(column)
    return None if value is None else str(value)


async def run_state_probe(call: Call, request: StateProbeRequest) -> StatePlan:
    """Resolve the values a legal INSERT needs (creating parent rows when allowed)."""

    started = time.monotonic()
    if not request.case_id:
        raise ValueError("state_probe requires an open case")
    if not valid_table(request.table):
        raise ValueError(f"invalid table name: {request.table!r}")
    brief = await fetch_brief(
        call, request.table, payload_columns=request.payload_columns
    )
    plan = StatePlan(
        status="READY",
        table=request.table,
        schema_brief=brief,
        evidence=[StateEvidence("schema", {"table": brief.table, "required": len(brief.required)})],
    )
    tables: set[str] = set()
    try:
        values = await _resolve_table(
            call,
            request.table,
            list(request.payload_columns),
            plan,
            depth=request.budget.depth,
            visited=(),
            tables=tables,
            budget=request.budget,
            create_rows=request.create_parents,
            context=request.context_values,
            register=request.register_targets,
        )
    except _Unresolved as exc:
        plan.status = "UNRESOLVED"
        plan.stop_reason = exc.code
        plan.notes.append(exc.detail)
        return plan
    plan.values.update(values)
    await _review_constants(request, brief, plan, values)

    if request.verify_insert:
        await _verify_insert(call, request, plan, brief)

    elapsed = time.monotonic() - started
    if elapsed > request.budget.seconds:
        plan.status = "PARTIAL"
        plan.stop_reason = "STATE_BUDGET"
        plan.notes.append(f"elapsed {elapsed:.2f}s exceeds the budget")
    return plan


async def _verify_insert(
    call: Call, request: StateProbeRequest, plan: StatePlan, brief: SchemaBrief
) -> None:
    """Prove the row is legal, then undo it (residue must be 0)."""

    sql, values = _insert_sql_for(request, plan)
    step = StateStep(action="db_write", ref="insert", table=request.table, sql=sql)
    plan.steps.append(step)
    try:
        written = await call("db_write", {"sql": sql})
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        plan.status = "UNRESOLVED"
        plan.stop_reason = "STATE_WRITE_DENIED"
        plan.notes.append(f"probe insert rejected: {str(exc)[:400]}")
        return
    change = written.get("change") if isinstance(written, dict) else None
    step.undo_ref = str((change or {}).get("change_id") or "") or None
    step.verified = True
    plan.evidence.append(StateEvidence("db_after", {"insert": sql[:400], "values": values}))
    try:
        undone = await call("db_undo", {"case_id": request.case_id})
    except Exception as exc:  # noqa: BLE001
        plan.status = "PARTIAL"
        plan.notes.append(f"undo failed: {str(exc)[:400]}")
        return
    residue = undone.get("residue") if isinstance(undone, dict) else None
    plan.evidence.append(StateEvidence("residue", {"residue": residue}))
    if residue not in (0, None):
        plan.status = "PARTIAL"
        plan.notes.append("RESIDUE_LEFT")


def _insert_sql_for(request: StateProbeRequest, plan: StatePlan) -> tuple[str, dict[str, str]]:
    values = dict(plan.values)
    for column in request.payload_columns:
        values[column] = request.probe_tag or "tia-probe"
    return _insert_sql(request.table, values), values
