"""Unit tests for the directed trace tools (trace_run / trace_diff)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tia.ad.http import HttpResult
from tia.cap import trace as trace_mod
from tia.cap.trace import (
    TraceEntry,
    dedupe_adjacent,
    diff_entries,
    parse_trace,
    trace_diff,
    trace_run,
)
from tia.inf.config import Settings
from tia.inf.runtime import configure, get_runtime, reset_runtime
from tia.schemas.envelope import ErrorCode, ToolError

SOURCE = """<?php
$search = $_POST['search'];
$result = $conn->query("select * from caffaine where itemname like '%$search%'");
while ($row = $result->fetch_assoc()) {
    echo $row['itemname'];
}
"""


def trace_line(line: int, op: str, pc: int = 0, func: str = "", depth: int = 0) -> str:
    suffix = f" | func={func}" if func else ""
    return f"/app/home.php:{line} | op={op} | pc={pc} | depth={depth}{suffix} | o1=CV:x"


class FakeHttp:
    """Stands in for HttpClient and emulates the tracer writing its output."""

    calls: list[dict[str, Any]] = []
    lines: list[str] = []
    configs: list[dict[str, Any]] = []
    emit = True

    def fetch(self, method: str, url: str, **kwargs: Any) -> HttpResult:
        FakeHttp.calls.append({"method": method, "url": url, **kwargs})
        if FakeHttp.emit:
            config = json.loads(Path(trace_mod.OpcodeTraceAdapter().config_path).read_text())
            FakeHttp.configs.append(config)
            output = Path(trace_mod.OpcodeTraceAdapter().output_dir) / config["output"]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("\n".join(FakeHttp.lines) + "\n", encoding="utf-8")
        return HttpResult(
            status=200,
            final_url=url,
            content_type="text/html",
            headers={},
            redirect_chain=[],
            body_bytes=64,
            body="<html><body>ok</body></html>",
            truncated=False,
        )


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "home.php").write_text(SOURCE, encoding="utf-8")
    store_path = tmp_path / "tia.db"
    configure(
        Settings.load(
            "trigger",
            db_name="xvwa",
            app_root=str(app_root),
            store_path=store_path,
        )
    )
    rt = get_runtime()
    case_id = rt.store.open_case("trigger", {"kind": "Xss"}, [])
    monkeypatch.setenv("TIA_TRACE_CONFIG", str(tmp_path / "trace_query.json"))
    monkeypatch.setenv("TIA_TRACE_DIR", str(tmp_path / "trace"))
    monkeypatch.setattr(trace_mod, "HttpClient", FakeHttp)
    FakeHttp.calls.clear()
    FakeHttp.configs.clear()
    FakeHttp.emit = True
    FakeHttp.lines = [
        trace_line(3, "ZEND_POST_INC", pc=1),
        trace_line(3, "ZEND_POST_INC", pc=1),
        trace_line(3, "ZEND_ASSIGN", pc=2),
        trace_line(4, "ZEND_ECHO", pc=3, func="show"),
    ]
    yield {"app_root": app_root, "case_id": case_id, "tmp": tmp_path}
    monkeypatch.undo()
    reset_runtime()


async def _run(env: dict[str, Any], **overrides: Any) -> Any:
    args = {
        "case_id": env["case_id"],
        "url": "http://127.0.0.1/xvwa/home.php",
        "file": "home.php",
        "line_from": 3,
        "line_to": 4,
    }
    args.update(overrides)
    return await trace_run(args)


async def test_run_arms_directed_config_and_dedupes(env: dict[str, Any]) -> None:
    out = await _run(env)
    config = FakeHttp.configs[-1]
    assert len(config["targets"]) == 1
    assert config["targets"][0]["file"].endswith("home.php")
    assert config["targets"][0]["line_from"] == 3
    assert config["targets"][0]["line_to"] == 4
    assert config["max_lines"] == 20000
    # two identical adjacent entries collapse into one
    assert out.data["total_lines"] == 3
    assert [entry["op"] for entry in out.data["entries"]] == [
        "ZEND_POST_INC",
        "ZEND_ASSIGN",
        "ZEND_ECHO",
    ]
    assert out.data["summary"]["functions"] == {"show": 1}
    assert out.data["trace_id"].startswith("tr-")
    assert FakeHttp.calls[0]["method"] == "GET"


async def test_run_can_skip_dedupe(env: dict[str, Any]) -> None:
    out = await _run(env, dedupe=False)
    assert out.data["total_lines"] == 4


async def test_run_posts_with_params_when_asked(env: dict[str, Any]) -> None:
    out = await _run(env, method="POST", params={"search": "tia"})
    assert out.data["method"] == "POST"
    call = FakeHttp.calls[0]
    assert not call["params"]
    assert call["body"] == "search=tia"
    assert call["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


async def test_run_requires_trace_output(env: dict[str, Any]) -> None:
    FakeHttp.emit = False
    with pytest.raises(ToolError) as excinfo:
        await _run(env)
    assert excinfo.value.code is ErrorCode.NOT_FOUND


async def test_run_rejects_file_outside_app_root(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await _run(env, file="/etc/passwd")
    assert excinfo.value.code is ErrorCode.POLICY_DENIED


async def test_run_rejects_traversal_in_output(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await _run(env, output="../x.log")
    assert excinfo.value.code is ErrorCode.BAD_ARGS


async def test_diff_reports_added_and_removed_regions(env: dict[str, Any]) -> None:
    first = await _run(env)
    FakeHttp.lines = [
        trace_line(3, "ZEND_POST_INC", pc=1),
        trace_line(4, "ZEND_ECHO", pc=3, func="show"),
        trace_line(5, "ZEND_RETURN", pc=9),
    ]
    second = await _run(env, output="second.log")
    out = await trace_diff(
        {
            "case_id": env["case_id"],
            "trace_a": first.data["trace_id"],
            "trace_b": second.data["trace_id"],
        }
    )
    kinds = {region["kind"] for region in out.data["regions"]}
    assert kinds <= {"replace", "insert", "delete"}
    assert out.data["counts"]["before_total"] == 3
    assert out.data["counts"]["after_total"] == 3
    assert out.data["counts"]["only_before"] == 1
    assert out.data["counts"]["only_after"] == 1


async def test_diff_rejects_unknown_trace(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await trace_diff(
            {"case_id": env["case_id"], "trace_a": "tr-missing", "trace_b": "tr-missing2"}
        )
    assert excinfo.value.code is ErrorCode.NOT_FOUND


def test_dedupe_adjacent_keeps_first_of_each_run() -> None:
    entries = [
        TraceEntry("/a.php", 1, "OP_A", 0, 0, None, "a"),
        TraceEntry("/a.php", 1, "OP_A", 5, 0, None, "a"),
        TraceEntry("/a.php", 1, "OP_B", 6, 0, None, "b"),
    ]
    assert [entry.op for entry in dedupe_adjacent(entries)] == ["OP_A", "OP_B"]


def test_parse_trace_reads_markers_and_fields() -> None:
    text = "\n".join(
        [
            "/app/home.php:12 | op=ZEND_ECHO | pc=4 | depth=1 | func=render | o1=CV:row",
            "#truncated max_lines=20",
            "junk line",
        ]
    )
    entries, markers = parse_trace(text)
    assert len(entries) == 1
    assert entries[0].func == "render"
    assert entries[0].depth == 1
    assert markers == ["#truncated max_lines=20"]


def test_diff_entries_counts_shared_prefix() -> None:
    a = [TraceEntry("/a.php", i, "OP", i, 0, None, "x") for i in range(4)]
    b = [TraceEntry("/a.php", i, "OP", i, 0, None, "x") for i in range(2)] + [
        TraceEntry("/a.php", 9, "OP", 9, 0, None, "y")
    ]
    diff = diff_entries(a, b, max_regions=5)
    assert diff["counts"]["only_before"] == 2
    assert diff["counts"]["only_after"] == 1
    assert diff["regions"][0]["kind"] == "replace"


async def test_run_accepts_several_targets(env: dict[str, Any]) -> None:
    (env["app_root"] / "second.php").write_text(SOURCE, encoding="utf-8")
    out = await trace_run(
        {
            "case_id": env["case_id"],
            "url": "http://127.0.0.1/xvwa/home.php",
            "targets": [
                {"file": "home.php", "line_from": 3, "line_to": 4},
                {"file": "second.php", "line_from": 1, "line_to": 9},
            ],
        }
    )
    config = FakeHttp.configs[-1]
    assert len(config["targets"]) == 2
    assert config["targets"][1]["file"].endswith("second.php")
    assert out.data["target_count"] == 2
    assert len(out.data["targets"]) == 2


async def test_diff_reports_operands_as_reference(env: dict[str, Any]) -> None:
    first = await _run(env)
    FakeHttp.lines = [
        trace_line(3, "ZEND_POST_INC", pc=1),
        trace_line(4, "ZEND_ECHO", pc=3, func="show"),
    ]
    second = await _run(env, output="second.log")
    out = await trace_diff(
        {
            "case_id": env["case_id"],
            "trace_a": first.data["trace_id"],
            "trace_b": second.data["trace_id"],
        }
    )
    assert "operands" in out.data["operands_note"].lower()
    region = out.data["regions"][0]
    assert region["a_operands"][0]["op"].startswith("ZEND_")
    assert region["a_operands"][0]["o1"] == "CV:x"
    assert "a_operands" not in out.data["counts"]


def test_parse_trace_reads_target_index() -> None:
    text = "/app/a.php:7 | op=ZEND_ECHO | pc=1 | depth=0 | target=2 | o1=CV:x"
    entries, _markers = parse_trace(text)
    assert entries[0].target == 2
