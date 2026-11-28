"""state_probe M2: resolve constants and reuse an existing parent row."""

from __future__ import annotations

from typing import Any

from tia.dom.state_probe import StateProbeRequest, run_state_probe
from tia.orch.kernel import ToolCallError
from tia.schemas.envelope import Envelope, ErrorBody, ErrorCode

SCHEMA = {
    "tables": [
        {
            "name": "child",
            "primary_key": ["id"],
            "columns": [
                {
                    "name": "id",
                    "type": "int",
                    "column_type": "int(11)",
                    "nullable": False,
                    "default": None,
                    "extra": "auto_increment",
                    "length": None,
                },
                {
                    "name": "parent_id",
                    "type": "int",
                    "column_type": "int(11)",
                    "nullable": False,
                    "default": None,
                    "extra": "",
                    "length": None,
                },
                {
                    "name": "kind",
                    "type": "enum",
                    "column_type": "enum('first','second')",
                    "nullable": False,
                    "default": None,
                    "extra": "",
                    "length": 6,
                },
                {
                    "name": "body",
                    "type": "text",
                    "column_type": "text",
                    "nullable": False,
                    "default": None,
                    "extra": "",
                    "length": 65535,
                },
            ],
            "fks": [
                {
                    "column": "parent_id",
                    "ref_table": "parent",
                    "ref_column": "id",
                    "delete_rule": "CASCADE",
                }
            ],
        }
    ]
}


class FakeCall:
    def __init__(self, parent_rows: list[dict[str, Any]]) -> None:
        self.parent_rows = parent_rows
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, args))
        sql = str(args.get("sql") or "")
        if tool == "db_schema":
            return SCHEMA
        if tool == "db_read" and sql.startswith("SELECT * FROM `parent`"):
            return {"rows": self.parent_rows}
        if tool == "db_write":
            return {"change": {"change_id": "ch-1", "undo_sql": "DELETE FROM child WHERE 1=0"}}
        if tool == "db_undo":
            return {"residue": 0}
        raise AssertionError(f"unexpected call {tool} {sql[:120]}")


async def test_ready_plan_reuses_parent_row_and_fills_constants() -> None:
    call = FakeCall([{"id": 7, "kind": "first"}])
    plan = await run_state_probe(
        call,
        StateProbeRequest(
            case_id="case-1", table="child", payload_columns=["body"]
        ),
    )
    assert plan.status == "READY"
    assert plan.values == {"parent_id": "7", "kind": "first"}
    assert [item.kind for item in plan.prerequisites] == ["row", "constant"]
    assert plan.prerequisites[0].source == "existing"
    assert plan.prerequisites[0].confidence == 90
    assert {tool for tool, _ in call.calls} == {"db_schema", "db_read"}


async def test_missing_parent_row_is_unresolved() -> None:
    call = FakeCall([])
    plan = await run_state_probe(
        call, StateProbeRequest(case_id="case-1", table="child", payload_columns=["body"])
    )
    assert plan.status == "UNRESOLVED"
    assert plan.stop_reason == "STATE_PARENT_MISSING"
    assert "parent_id" in plan.notes[-1]
    assert plan.values == {"kind": "first"}


async def test_verify_insert_writes_then_undoes() -> None:
    call = FakeCall([{"id": 3}])
    plan = await run_state_probe(
        call,
        StateProbeRequest(
            case_id="case-1",
            table="child",
            payload_columns=["body"],
            verify_insert=True,
            probe_tag="tia0001",
        ),
    )
    assert plan.status == "READY"
    assert plan.steps and plan.steps[0].action == "db_write"
    assert plan.steps[0].undo_ref == "ch-1"
    assert plan.steps[0].verified is True
    assert any(item.kind == "residue" for item in plan.evidence)
    sqls = [args["sql"] for tool, args in call.calls if tool == "db_write"]
    assert sqls[0].startswith("INSERT INTO `child` (")
    assert "'tia0001'" in sqls[0]


async def test_context_value_taken_from_request() -> None:
    call = FakeCall([{"id": 3}])
    plan = await run_state_probe(
        call,
        StateProbeRequest(
            case_id="case-1",
            table="child",
            payload_columns=["body"],
            context_values={"parent_id": "9"},
        ),
    )
    # The FK column is still a row prerequisite, so the context value is unused.
    assert plan.values["parent_id"] == "3"


async def test_trigger_retry_merges_resolved_values() -> None:
    from tia.dom.trigger import _retry_insert_with_state

    class Kernel:
        case_id = "case-1"
        calls: list[tuple[str, dict[str, Any]]] = []

        async def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
            self.calls.append((tool, args))
            if tool == "db_schema":
                return SCHEMA
            if tool == "db_read":
                return {"rows": [{"id": 5}]}
            if tool == "db_write":
                return {"change": {"change_id": "ch-9"}}
            raise AssertionError(tool)

    kernel = Kernel()
    exc = ToolCallError(
        "db_write",
        Envelope.failure(
            tool="db_write",
            profile="trigger",
            error=ErrorBody(
                code=ErrorCode.ENV_ERROR, message="Column 'parent_id' cannot be null"
            ),
            cost_ms=0,
        ),
    )
    notes: dict[str, Any] = {}
    result = await _retry_insert_with_state(
        kernel,  # type: ignore[arg-type]
        "case-1",
        "child",
        ["parent_id", "body"],
        ["tia-xxxx", "<script>alert(1)</script>tia"],
        "INSERT INTO `child` (`parent_id`, `body`) VALUES ('tia-xxxx', '...')",
        exc,
        notes,
        payload_column="body",
    )
    assert result is not None
    written, sql = result
    assert written["change"]["change_id"] == "ch-9"
    assert sql == (
        "INSERT INTO `child` (`parent_id`, `body`, `kind`) "
        "VALUES (5, '<script>alert(1)</script>tia', 'first')"
    )
    assert notes["state_plan"]["status"] == "READY"
    assert notes["state_plan_retry"] is True


async def test_trigger_retry_gives_up_when_the_plan_is_unresolved() -> None:
    from tia.dom.trigger import _retry_insert_with_state

    class Kernel:
        case_id = "case-1"

        async def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
            if tool == "db_schema":
                return SCHEMA
            return {"rows": []}

    kernel = Kernel()
    exc = ToolCallError(
        "db_write",
        Envelope.failure(
            tool="db_write",
            profile="trigger",
            error=ErrorBody(code=ErrorCode.ENV_ERROR, message="fk fails"),
            cost_ms=0,
        ),
    )
    notes: dict[str, Any] = {}
    result = await _retry_insert_with_state(
        kernel,  # type: ignore[arg-type]
        "case-1",
        "child",
        ["body"],
        ["x"],
        "INSERT INTO `child` (`body`) VALUES ('x')",
        exc,
        notes,
        payload_column="body",
    )
    assert result is None
    assert notes["state_plan"]["status"] == "UNRESOLVED"
