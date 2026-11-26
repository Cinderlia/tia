"""Slice queue tools: the main agent's read/archive/skip interface (M0, M5).

The queue lives in the local store; these handlers never touch the target
application or its database, they only move slice state.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, ValidationError

from tia.cap.registry import ToolOutput
from tia.inf.runtime import get_runtime
from tia.orch.learning import hints_for
from tia.schemas.envelope import ErrorCode, ToolError


class SliceNextInput(BaseModel):
    run_id: str | None = None
    ttl_minutes: int = Field(default=30, ge=1, le=1440)
    peek: bool = False
    limit: int = Field(default=5, ge=1, le=50)
    slice_id: str | None = None


class SliceArchiveInput(BaseModel):
    slice_id: str
    verdict: str = Field(min_length=1, max_length=64)
    case_id: str | None = None
    notes: str | None = Field(default=None, max_length=2000)


class SliceSkipInput(BaseModel):
    slice_id: str
    reason: str = Field(min_length=1, max_length=500)
    status: str = Field(default="skipped", pattern="^(skipped|blocked)$")


def _bad_args(exc: ValidationError) -> ToolError:
    return ToolError(
        code=ErrorCode.BAD_ARGS,
        message=f"invalid arguments: {exc.errors()[0]['msg']}",
        hint="Check the tool input schema",
    )


def _slice_public(item: dict[str, Any]) -> dict[str, Any]:
    """Keep the queue row small: the raw slice travels as ``slice``."""
    payload = item.get("slice")
    return {
        "slice_id": item["id"],
        "run_id": item["run_id"],
        "kind": item["kind"],
        "sink_file": item["sink_file"],
        "sink_line": item["sink_line"],
        "attempts": item["attempts"],
        "order_mode": item.get("order_mode", "second"),
        "score": item.get("score", 0),
        "digest": item.get("digest", {}),
        "slice": payload,
    }


async def slice_next(arguments: dict[str, Any]) -> ToolOutput:
    try:
        params = SliceNextInput.model_validate(arguments)
    except ValidationError as exc:
        raise _bad_args(exc) from exc
    store = get_runtime().store
    if params.peek:
        # Planner view: ranked digests, nothing leased.
        candidates = store.peek_slices(params.limit, run_id=params.run_id)
        for candidate in candidates:
            # Recent attempts for the same slice: summaries only, never raw returns.
            candidate["experience"] = store.slice_experience(str(candidate["slice_id"]), limit=6)
            # Cross-family prior: both the direct and the second-order agents
            # write here, so the planner sees one shared history per site.
            candidate["learning"] = hints_for(store, candidate.get("slice") or {})
        return ToolOutput(
            data={
                "found": bool(candidates),
                "candidates": candidates,
                "total_pending": len(store.list_slices(status="pending", limit=200)),
            }
        )
    if params.slice_id:
        # Planner choice: lease exactly the slice it asked for.
        leased = store.lease_slice(params.slice_id)
        if leased is None:
            raise ToolError(
                code=ErrorCode.CONFLICT,
                message=f"slice {params.slice_id!r} is not pending",
                hint="Call slice_next with peek=true to see pending slices",
            )
        return ToolOutput(data={"found": True, **_slice_public(leased)})
    while True:
        item = store.next_slice(ttl_minutes=params.ttl_minutes, run_id=params.run_id)
        if item is None:
            return ToolOutput(
                data={"found": False, "slice": None, "queue": store.list_slices(status="pending", limit=5)}
            )
        if params.run_id and item["run_id"] != params.run_id:
            store.skip_slice(str(item["id"]), f"run mismatch: {item['run_id']}", status="pending")
            continue
        return ToolOutput(data={"found": True, **_slice_public(item)})


async def slice_archive(arguments: dict[str, Any]) -> ToolOutput:
    try:
        params = SliceArchiveInput.model_validate(arguments)
    except ValidationError as exc:
        raise _bad_args(exc) from exc
    store = get_runtime().store
    if not store.archive_slice(
        params.slice_id, params.verdict, case_id=params.case_id or "", notes=params.notes or ""
    ):
        raise ToolError(
            code=ErrorCode.NOT_FOUND,
            message=f"slice {params.slice_id!r} not found",
            hint="Call slice_next first; ids come from the queue",
        )
    return ToolOutput(
        data={
            "slice_id": params.slice_id,
            "verdict": params.verdict,
            "case_id": params.case_id,
            "archived": True,
        }
    )


async def slice_skip(arguments: dict[str, Any]) -> ToolOutput:
    try:
        params = SliceSkipInput.model_validate(arguments)
    except ValidationError as exc:
        raise _bad_args(exc) from exc
    store = get_runtime().store
    if not store.skip_slice(params.slice_id, params.reason, status=params.status):
        raise ToolError(
            code=ErrorCode.NOT_FOUND,
            message=f"slice {params.slice_id!r} not found",
            hint="Call slice_next first; ids come from the queue",
        )
    return ToolOutput(
        data={"slice_id": params.slice_id, "status": params.status, "reason": params.reason}
    )
