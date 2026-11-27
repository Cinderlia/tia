"""Write gate: must pass this layer before any side effect.

Rules come from three sources:
1. profile yaml（``write_allow_tables`` / ``write_deny_columns`` / ``max_rows_per_write``）；
2. Write targets registered by the case (``write_targets`` of ``case_open``) — each case may only write to tables it declares;
3. SQL structure (guaranteed by :mod:`tia.cap.sqlparse`).

The verdict is either "allow" or ``POLICY_DENIED``; there is no gray area.
"""

from __future__ import annotations

from typing import Any

from tia.cap.sqlparse import WriteStatement
from tia.inf.config import ProfileConfig
from tia.inf.store import Store
from tia.schemas.envelope import ErrorCode, ToolError


def _deny(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.POLICY_DENIED, message, retryable=False, hint=hint)


def require_case(store: Store, case_id: str) -> dict[str, Any]:
    if not case_id:
        raise _deny("DB writes must be bound to a case_id", "Register write targets in the case before writing to the DB")
    case = store.get_case(case_id)
    if case is None:
        raise ToolError(ErrorCode.NOT_FOUND, f"case not found: {case_id}", hint="Call case_open first")
    return case


def check_write(
    *,
    profile: ProfileConfig,
    store: Store,
    case_id: str,
    statement: WriteStatement,
    rows: int,
    allow_multi: bool = False,
) -> None:
    """All checks before DB writes; raises ``ToolError`` directly if failed."""
    require_case(store, case_id)

    targets = store.write_targets(case_id)
    declared = {str(t.get("table")) for t in targets if t.get("table")}
    allowed = set(profile.write_allow_tables) | declared
    if statement.table not in allowed:
        raise _deny(
            f"Table {statement.table!r} is not in the writable list",
            "Register the table in case_open's write_targets, or allow it via the profile whitelist",
        )

    denied = set(profile.write_deny_columns)
    hit = denied.intersection(statement.columns)
    if hit:
        raise _deny(f"Columns {sorted(hit)!r} are in the write blacklist")

    # Only write columns declared by the case (for INSERT); table-level targets (empty column) have no column restrictions.
    declared_columns = {
        str(t.get("column")) for t in targets if t.get("table") == statement.table and t.get("column")
    }
    if statement.op == "insert" and declared_columns:
        outside = set(statement.columns) - declared_columns
        if outside:
            raise _deny(
                f"Columns {sorted(outside)!r} are not registered by the case",
                f"Columns allowed by the case: {sorted(declared_columns)}",
            )

    limit = profile.max_rows_per_write
    if rows > limit and not allow_multi:
        raise _deny(
            f"Writing {rows} rows in one go, exceeding the limit of {limit}",
            "Pass allow_multi when a cleanup is meant to remove every row carrying a tag",
        )
