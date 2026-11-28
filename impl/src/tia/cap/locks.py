"""A table-level lease: one agent writes and verifies a table at a time."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from tia.schemas.envelope import ErrorCode, ToolError

POLL_SECONDS = 0.25
LOCK_TTL_SECONDS = 600.0


class TableLocks:
    """Hold leases on the given tables; wait (bounded) for another owner."""

    def __init__(
        self,
        store: Any,
        *,
        owner: str,
        tables: list[str],
        timeout_sec: float = 120.0,
        ttl_sec: float = LOCK_TTL_SECONDS,
    ) -> None:
        self.store = store
        self.owner = owner
        self.tables = sorted({table for table in tables if table})
        self.timeout_sec = timeout_sec
        self.ttl_sec = ttl_sec
        self.held: list[str] = []

    async def acquire(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.timeout_sec
        while True:
            pending = [table for table in self.tables if table not in self.held]
            for table in pending:
                if self.store.acquire_table_lock(
                    table, owner=self.owner, ttl_sec=self.ttl_sec
                ):
                    self.held.append(table)
                else:
                    break
            if len(self.held) == len(self.tables):
                return
            if asyncio.get_running_loop().time() >= deadline:
                self.release()
                raise ToolError(
                    ErrorCode.CONFLICT,
                    "timed out waiting for a table another agent is using",
                    retryable=True,
                    hint="the other agent should undo and release; retry the slice later",
                )
            await asyncio.sleep(POLL_SECONDS)

    def refresh(self) -> None:
        for table in self.held:
            with contextlib.suppress(Exception):
                self.store.refresh_table_lock(table, owner=self.owner, ttl_sec=self.ttl_sec)

    def release(self) -> None:
        for table in list(self.held):
            with contextlib.suppress(Exception):
                self.store.release_table_lock(table, owner=self.owner)
        self.held.clear()
