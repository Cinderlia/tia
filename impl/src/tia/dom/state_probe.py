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

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ref": self.ref,
            "table": self.table,
            "sql": self.sql,
            "request": self.request,
            "undo_ref": self.undo_ref,
            "verified": self.verified,
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


async def run_state_probe(call: Call, request: StateProbeRequest) -> StatePlan:
    """Resolve the values a legal INSERT needs (read-only unless verify_insert)."""

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
    parents = {item.column: item for item in brief.parents}
    touched: set[str] = {request.table}
    unresolved: list[str] = []

    for fact in brief.required:
        column = str(fact.get("name") or "")
        kind = str(fact.get("prerequisite") or "constant")
        if kind == "row":
            parent = parents.get(column)
            if parent is None:
                unresolved.append(f"{column}: foreign key metadata missing")
                continue
            row = await _pick_parent_row(
                call,
                parent.parent_table,
                parent.parent_column,
                limit=request.budget.candidates,
            )
            if row is None:
                unresolved.append(
                    f"{column}: no {parent.parent_table}.{parent.parent_column} row to reuse"
                )
                plan.notes.append(
                    f"{parent.parent_table} has no reusable row; creating one is M3"
                )
                continue
            value = str(row[parent.parent_column])
            touched.add(parent.parent_table)
            plan.prerequisites.append(
                Prerequisite(
                    kind="row",
                    table=parent.parent_table,
                    column=parent.parent_column,
                    value=value,
                    source="existing",
                    confidence=90,
                )
            )
            plan.values[column] = value
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
        elif kind == "context":
            context_value = (
                request.context_values.get(f"{request.table}.{column}")
                or request.context_values.get(column)
            )
            if context_value is None:
                unresolved.append(f"{column}: no session/account value available")
                continue
            plan.prerequisites.append(
                Prerequisite("context", request.table, column, str(context_value), "session", 80)
            )
            plan.values[column] = str(context_value)
        else:
            value, confidence, review = _safe_constant(fact)
            plan.prerequisites.append(
                Prerequisite(
                    "constant",
                    request.table,
                    column,
                    value,
                    "constant",
                    confidence,
                )
            )
            plan.values[column] = value
            if review:
                plan.notes.append(f"{column}: safe constant {value!r} needs review")

    if len(touched) > request.budget.tables:
        plan.status = "PARTIAL"
        plan.stop_reason = "STATE_BUDGET"
        plan.notes.append(f"budget allows {request.budget.tables} tables, touched {len(touched)}")
    if unresolved:
        plan.status = "UNRESOLVED"
        plan.stop_reason = (
            "STATE_PARENT_MISSING"
            if any("no " in item and "row to reuse" in item for item in unresolved)
            else "STATE_REQUIRED_UNRESOLVED"
        )
        plan.notes.append("unresolved: " + "; ".join(unresolved))
        return plan

    if request.verify_insert:
        await _verify_insert(call, request, plan, brief)

    elapsed = time.monotonic() - started
    if elapsed > request.budget.seconds:
        plan.status = "PARTIAL"
        plan.stop_reason = "STATE_BUDGET"
        plan.notes.append(f"elapsed {elapsed:.2f}s exceeds the budget")
    return plan


def _insert_sql(request: StateProbeRequest, plan: StatePlan) -> tuple[str, dict[str, str]]:
    values = dict(plan.values)
    for column in request.payload_columns:
        values[column] = request.probe_tag or "tia-probe"
    columns = list(values)
    sql = (
        f"INSERT INTO `{request.table}` ({', '.join(f'`{c}`' for c in columns)}) "
        f"VALUES ({', '.join(_literal(values[c]) for c in columns)})"
    )
    return sql, values


def _literal(value: str) -> str:
    if value == "NOW()":
        return "NOW()"
    if value.replace(".", "", 1).lstrip("-").isdigit():
        return value
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


async def _verify_insert(
    call: Call, request: StateProbeRequest, plan: StatePlan, brief: SchemaBrief
) -> None:
    """Prove the row is legal, then undo it (residue must be 0)."""

    sql, values = _insert_sql(request, plan)
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
