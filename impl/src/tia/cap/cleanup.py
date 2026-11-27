"""Remove the rows a run left in the target, whatever wrote them.

``db_undo`` can only revert rows this framework wrote through ``db_write``. A
payload row created by the application itself — the verification POST that lands
in a comment table, for example — is invisible to it. Every such row carries the
run's random tag, so the tag is the handle that covers both paths.
"""

from __future__ import annotations

import contextlib

from tia.orch.kernel import Kernel, ToolCallError


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
