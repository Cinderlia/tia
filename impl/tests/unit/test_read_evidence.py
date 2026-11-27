"""Read evidence: trace the read path, then take the statement from the probe."""

from __future__ import annotations

from typing import Any

import pytest

from tia.cap.read_evidence import collect_read_sql

MODULE = "includes/modules/content/testimonials/cm_t_list.php"
TEMPLATE = "includes/modules/content/testimonials/templates/tpl_cm_t_list.php"


class FakeCall:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        args = dict(arguments or {})
        self.calls.append((name, args))
        if name == "source_grep":
            return {"hits": [{"file": MODULE, "line": 1}]}
        if name == "trace_run":
            return {
                "trace_id": "tr-read",
                "entries": [
                    {"file": "/app/PhoenixCart/" + MODULE, "line": 31, "op": "ZEND_DO_FCALL"},
                    {"file": "/app/PhoenixCart/" + TEMPLATE, "line": 13, "op": "ZEND_ECHO"},
                ],
            }
        if name == "source_read":
            return {
                "lines": [
                    {"n": 22, "text": '$sql = "SELECT t.* FROM testimonials t";'},
                    {"n": 31, "text": "$GLOBALS['db']->query($sql);"},
                ]
            }
        if name == "probe_arm":
            return {"probe_id": "probe-1"}
        if name == "probe_run":
            return {
                "http": {"status": 200},
                "queries": [
                    {
                        "sql": (
                            "SELECT t.*, td.* FROM testimonials t, testimonials_description td "
                            "WHERE t.testimonials_id = td.testimonials_id "
                            "AND t.testimonials_status = 1"
                        )
                    }
                ],
            }
        if name == "probe_disarm":
            return {}
        raise AssertionError(f"unexpected tool {name}")


@pytest.mark.asyncio
async def test_collect_read_sql_uses_the_executed_query_line() -> None:
    call = FakeCall()
    result = await collect_read_sql(
        call,
        case_id="case-1",
        url="http://127.0.0.1/PhoenixCart/testimonials.php",
        sink_file=TEMPLATE,
        sink_line=13,
    )
    assert result["trace_id"] == "tr-read"
    assert result["statements"][0].endswith("AND t.testimonials_status = 1")
    probe = result["probes"][0]
    assert probe["file"] == MODULE
    assert probe["line"] == 31
    names = [name for name, _ in call.calls]
    assert names[0] == "source_grep"
    assert "trace_run" in names and "probe_arm" in names and "probe_disarm" in names


@pytest.mark.asyncio
async def test_collect_read_sql_stops_when_no_query_line_executed() -> None:
    class NoQuery(FakeCall):
        async def __call__(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if name == "trace_run":
                return {"trace_id": "tr-empty", "entries": []}
            return await super().__call__(name, arguments)

    result = await collect_read_sql(
        NoQuery(), case_id="case-2", url="http://127.0.0.1/x.php", sink_file=TEMPLATE
    )
    assert result["statements"] == []
    assert result["probes"] == []
