"""The directed trace reaches the planner as a bounded, frame-aware slice."""

from __future__ import annotations

import pytest

from tia.cap.delivery import deliver
from tia.cap.forms import FormField, PageForm
from tia.cap.trace import TraceEntry
from tia.cap.trace_view import make_trace_probe, render_trace, slice_trace


def _entry(file: str, line: int, depth: int, func: str, op: str = "ECHO") -> TraceEntry:
    return TraceEntry(
        file=file,
        line=line,
        op=op,
        pc=None,
        depth=depth,
        func=func,
        raw=f"{file}:{line} | op={op} | depth={depth} | func={func}",
    )


def _entries_dicts() -> list[dict]:
    return [{"file": item.file, "line": item.line} for item in _entries()]


def _entries() -> list[TraceEntry]:
    rows: list[TraceEntry] = []
    for _ in range(3):
        rows.append(_entry("/app/index.php", 10, 0, "main"))
        rows.append(_entry("/app/module/list.php", 22, 1, "execute"))
        rows.append(_entry("/app/module/list.php", 31, 1, "execute", "INIT_METHOD_CALL"))
        rows.append(_entry("/app/templates/list.php", 13, 2, "render"))
    return rows


def test_slice_keeps_call_sites_and_the_sink() -> None:
    view = slice_trace(
        _entries(),
        sink_file="templates/list.php",
        sink_line=13,
        limit=20,
    )
    files = [row["file"] for row in view["entries"]]
    assert any(item.endswith("templates/list.php") for item in files)
    assert any(item.endswith("module/list.php") or item.endswith("index.php") for item in files)
    assert view["total"] == 12
    assert view["kept"] <= 12
    assert set(files) <= set(row["file"] for row in _entries_dicts())


def test_slice_marks_repeated_cycles_and_renders_depths() -> None:
    view = slice_trace(_entries(), sink_file="templates/list.php", sink_line=13, limit=20)
    text = render_trace(view)
    assert "d0 main" in text
    assert "templates/list.php:13" in text
    assert "x3" in text


def test_slice_of_empty_trace_is_empty() -> None:
    view = slice_trace([], sink_file="a.php", sink_line=1)
    assert view["entries"] == []
    assert render_trace(view) == ""


@pytest.mark.asyncio
async def test_trace_probe_bounds_the_trace_to_the_sink() -> None:
    calls: list[tuple[str, dict]] = []

    async def call(tool: str, arguments: dict) -> dict:
        calls.append((tool, arguments))
        return {"trace_id": "tr-1", "entries": [item.to_dict() for item in _entries()]}

    class Attempt:
        url = "http://app.test/list.php"
        method = "POST"
        values = {"item": "abc"}
        account = ""

    probe = make_trace_probe(call, case_id="case-1", file="templates/list.php", line=13)
    result = await probe(Attempt())
    tool, arguments = calls[0]
    assert tool == "trace_run"
    assert arguments["case_id"] == "case-1"
    assert arguments["targets"] == [
        {"file": "templates/list.php", "line_from": 11, "line_to": 15}
    ]
    assert "body" in arguments and "item=abc" in arguments["body"]
    assert result["slice"]["entries"]
    assert result["trace_id"] == "tr-1"


class FakeLlm:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def complete_json(self, system: str, user: str) -> dict[str, object]:
        self.prompts.append(user)
        return {
            "url": "http://app.test/action",
            "method": "POST",
            "fields": {"entry": "tia<ab12>"},
            "payload_field": "entry",
            "reason": "submit",
        }


def _form() -> PageForm:
    return PageForm(
        action="http://app.test/action",
        method="post",
        fields=[FormField(name="entry"), FormField(name="submit")],
    )


@pytest.mark.asyncio
async def test_failed_attempt_adds_the_trace_and_its_diff_to_the_next_plan() -> None:
    llm = FakeLlm()
    rounds = {"n": 0}

    async def send(
        method: str,
        values: dict[str, str],
        files: dict[str, str],
        account: str,
        url: str = "",
        headers: dict[str, str] | None = None,
    ) -> dict:
        return {
            "status": 200,
            "body": "<html>nothing</html>",
            "content_type": "text/html",
            "probe_hit": False,
        }

    async def accept(attempt, page) -> bool:  # type: ignore[no-untyped-def]
        return False

    async def trace_probe(attempt) -> dict:  # type: ignore[no-untyped-def]
        rounds["n"] += 1
        return {
            "slice": slice_trace(
                _entries(), sink_file="templates/list.php", sink_line=13
            ),
            "raw": _entries(),
        }

    await deliver(
        client=llm,  # type: ignore[arg-type]
        goal="reach the sink",
        page_url="http://app.test/action",
        forms=[_form()],
        tag="ab12",
        payload="<script>ab12</script>",
        max_rounds=2,
        send=send,
        accept=accept,
        trace_probe=trace_probe,
    )
    assert rounds["n"] == 2
    assert len(llm.prompts) == 2
    assert "EXECUTED TRACE" in llm.prompts[1]
    assert "d1 execute" in llm.prompts[1]
