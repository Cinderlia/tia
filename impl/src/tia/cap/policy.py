"""写闸门：任何副作用之前必须过这一层。

规则来自三处：
1. profile yaml（``write_allow_tables`` / ``write_deny_columns`` / ``max_rows_per_write``）；
2. case 登记的写目标（``case_open`` 的 ``write_targets``）——每个 case 只允许写它声明的表；
3. SQL 结构（由 :mod:`tia.cap.sqlparse` 保证）。

结论只有"放行"或 ``POLICY_DENIED``，没有灰色地带。
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
        raise _deny("写库必须绑定 case_id", "先在 case 中登记写目标，再写库")
    case = store.get_case(case_id)
    if case is None:
        raise ToolError(ErrorCode.NOT_FOUND, f"case 不存在: {case_id}", hint="先调用 case_open")
    return case


def check_write(
    *,
    profile: ProfileConfig,
    store: Store,
    case_id: str,
    statement: WriteStatement,
    rows: int,
) -> None:
    """写库前的全部检查；不通过直接抛 ``ToolError``。"""
    require_case(store, case_id)

    targets = store.write_targets(case_id)
    declared = {str(t.get("table")) for t in targets if t.get("table")}
    allowed = set(profile.write_allow_tables) | declared
    if statement.table not in allowed:
        raise _deny(
            f"表 {statement.table!r} 不在可写清单内",
            "在 case_open 的 write_targets 里登记该表，或由 profile 白名单放行",
        )

    denied = set(profile.write_deny_columns)
    hit = denied.intersection(statement.columns)
    if hit:
        raise _deny(f"列 {sorted(hit)!r} 在写法黑名单内")

    # 只写 case 声明过的列（INSERT 时）；表级目标（column 为空）不限列。
    declared_columns = {
        str(t.get("column")) for t in targets if t.get("table") == statement.table and t.get("column")
    }
    if statement.op == "insert" and declared_columns:
        outside = set(statement.columns) - declared_columns
        if outside:
            raise _deny(
                f"列 {sorted(outside)!r} 未被 case 登记",
                f"case 允许的列: {sorted(declared_columns)}",
            )

    limit = profile.max_rows_per_write
    if rows > limit:
        raise _deny(
            f"一次写 {rows} 行，超过上限 {limit}",
            "多行写入需要 allow_multi 并在 case 里登记；当前实现一律拒绝",
        )
