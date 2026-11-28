"""Stage graph for failure-driven rollback.

A case is a sequence of stages.  A stage declares the stages it depends on and
a coroutine that (re)produces its result into a shared context.  When the final
check fails, the analysis picks the stage that should be redone; only that
stage and the stages that depend on it are executed again, once.

The graph is deliberately small: dependencies express "this stage consumed the
previous stage's output", not a fixed pipeline.  Callers can therefore add,
remove or reorder stages without changing the rollback code.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Stage:
    """One re-runnable unit of a case."""

    id: str
    depends_on: tuple[str, ...] = ()
    run: Callable[[dict[str, Any]], Awaitable[None]] | None = None


@dataclass(slots=True)
class Rollback:
    """What a rollback did, so the case notes can explain it."""

    target: str
    rerun: list[str] = field(default_factory=list)
    reason: str = ""
    attempt: int = 1


def _index(stages: Sequence[Stage]) -> dict[str, Stage]:
    return {stage.id: stage for stage in stages}


def rerun_closure(stages: Sequence[Stage], target: str) -> list[str]:
    """``target`` plus every stage that transitively depends on it, in order."""
    index = _index(stages)
    if target not in index:
        raise KeyError(f"unknown stage: {target}")
    selected = {target}
    changed = True
    while changed:
        changed = False
        for stage in stages:
            if stage.id in selected:
                continue
            if any(dependency in selected for dependency in stage.depends_on):
                selected.add(stage.id)
                changed = True
    return [stage.id for stage in stages if stage.id in selected]


async def run_stages(stages: Sequence[Stage], context: dict[str, Any]) -> list[str]:
    """Run every stage in declaration order."""
    for stage in stages:
        if stage.run is None:
            continue
        await stage.run(context)
    return [stage.id for stage in stages]


async def rollback(
    stages: Sequence[Stage],
    context: dict[str, Any],
    target: str,
    *,
    reason: str = "",
    attempt: int = 1,
) -> Rollback:
    """Re-run ``target`` and its dependants, once, in declaration order."""
    rerun = rerun_closure(stages, target)
    index = _index(stages)
    for stage_id in rerun:
        stage = index[stage_id]
        if stage.run is None:
            continue
        await stage.run(context)
    return Rollback(target=target, rerun=rerun, reason=reason, attempt=attempt)
