"""Stage graph: rollback re-runs the target and its dependants, once."""

from __future__ import annotations

import pytest

from tia.dom.stages import Stage, rerun_closure, rollback, run_stages


def _graph() -> list[Stage]:
    return [
        Stage("trigger", (), None),
        Stage("pair", ("trigger",), None),
        Stage("inject", ("pair",), None),
    ]


def test_rerun_closure_is_the_target_and_its_dependants() -> None:
    stages = _graph()
    assert rerun_closure(stages, "inject") == ["inject"]
    assert rerun_closure(stages, "pair") == ["pair", "inject"]
    assert rerun_closure(stages, "trigger") == ["trigger", "pair", "inject"]


def test_unknown_stage_is_rejected() -> None:
    with pytest.raises(KeyError):
        rerun_closure(_graph(), "missing")


@pytest.mark.asyncio
async def test_rollback_runs_only_the_selected_prefix() -> None:
    executed: list[str] = []
    stages = _graph()

    async def inject(_ctx: dict[str, object]) -> None:
        executed.append("inject")

    stages[-1] = Stage("inject", ("pair",), inject)
    done = await rollback(stages, {}, "inject", reason="payload shape")
    assert done.rerun == ["inject"]
    assert executed == ["inject"]

    executed.clear()
    done = await rollback(stages, {}, "pair", reason="write path")
    assert done.rerun == ["pair", "inject"]
    assert executed == ["inject"]


@pytest.mark.asyncio
async def test_run_stages_keeps_declaration_order() -> None:
    executed: list[str] = []
    stages = _graph()
    for index, stage in enumerate(stages):
        name = stage.id

        async def run(_ctx: dict[str, object], name: str = name) -> None:
            executed.append(name)

        stages[index] = Stage(name, stage.depends_on, run)
    await run_stages(stages, {})
    assert executed == ["trigger", "pair", "inject"]
