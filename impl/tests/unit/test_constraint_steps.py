"""Constraint steps: a read predicate is replayed through the action that sets it."""

from __future__ import annotations

from typing import Any

import pytest

from tia.dom.constraint_steps import build_steps, replay

pytestmark = pytest.mark.asyncio

READ_SRC = (
    "SELECT t.testimonials_id, t.date_added, td.testimonials_text FROM testimonials t "
    "LEFT JOIN testimonials_description td ON t.testimonials_id = td.testimonials_id "
    "WHERE t.testimonials_status = 1 ORDER BY t.date_added DESC"
)
WRITE_SRC = (
    "if (isset($_GET['tID'], $_GET['flag'])) {\n"
    "  $db->query(\"UPDATE testimonials SET testimonials_status = \" . (int)$_GET['flag']"
    " . \" WHERE testimonials_id = \" . (int)$_GET['tID']);\n"
    "}"
)


class FakeCall:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.status = "0"

    async def __call__(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        if name == "source_grep":
            return {"hits": [{"file": "includes/modules/content/testimonials/cm_t_list.php", "line": 26}]}
        if name == "source_read":
            if "set_flag" in str(arguments.get("file")):
                return {
                    "lines": [
                        {"n": 12 + offset, "text": line}
                        for offset, line in enumerate(WRITE_SRC.splitlines())
                    ]
                }
            return {"lines": [{"n": 26, "text": READ_SRC}]}
        if name == "db_read":
            return {
                "rows": [
                    {
                        "testimonials_id": 7,
                        "testimonials_text": "ab12",
                        "testimonials_status": self.status,
                        "v": self.status,
                    }
                ]
            }
        if name == "probe_run":
            self.status = "1"
            return {"http": {"status": 302, "html": ""}, "queries": [{"affected_rows": 1}]}
        if name == "probe_arm":
            return {"armed": True}
        return {}


FLOW = {"table_name": "testimonials", "table": "testimonials"}
WRITERS = [
    (
        "w1",
        {"sinkFile": "admin/includes/actions/testimonials/set_flag.php", "sinkLine": 13},
    )
]


def url_for(raw: dict[str, Any]) -> str:
    return "http://app.test/PhoenixCart/admin/includes/actions/testimonials/"


async def test_build_steps_pairs_the_read_condition_with_the_writer() -> None:
    plan = await build_steps(
        FakeCall(),
        FLOW,
        WRITERS,
        "http://app.test/PhoenixCart/testimonials.php",
        url_for,
        [{"label": "admin", "roles": ["administrator"], "description": "can approve"}],
    )
    assert len(plan["constraints"]) == 1
    step = plan["constraints"][0]
    assert step["column"] == "testimonials_status"
    assert step["value"] == "1"
    assert step["write_slice_id"] == "w1"
    assert step["account"] == "admin"
    assert step["value_params"] == ["flag"]
    assert step["key_params"] == ["tID"]
    assert plan["steps"][0] == {"kind": "constraint", "ref": step["constraint_id"]}


async def test_replay_sets_the_value_through_the_action() -> None:
    call = FakeCall()
    plan = await build_steps(
        call, FLOW, WRITERS, "http://app.test/PhoenixCart/testimonials.php", url_for, []
    )
    step = plan["constraints"][0]
    result = await replay(
        call,
        case_id="case-1",
        step=step,
        payload_column="testimonials_text",
        tag="ab12",
    )
    assert result["confirmed"] is True
    assert result["observed"] == "1"
    run = next(args for name, args in call.calls if name == "probe_run")
    assert run["params"] == {"flag": "1", "tID": 7}
