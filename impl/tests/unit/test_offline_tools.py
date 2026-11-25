"""离线工具（form_parse/context_classify/budget_solve/trace_diff/flow_lookup/artifact_save）。

这些工具不碰网络、不碰目标库，测试也完全离线；同时覆盖"输入是数据不是命令"的边界。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tia.cap.offline import (
    artifact_save,
    budget_solve,
    context_classify,
    flow_lookup,
    form_parse,
    trace_diff,
)
from tia.inf.config import Settings
from tia.inf.runtime import configure, reset_runtime
from tia.schemas.envelope import ErrorCode, ToolError

FORM_HTML = """
<html><body>
<form action="/xvwa/post" method="post" enctype="application/x-www-form-urlencoded">
  <input type="text" name="name" maxlength="30" required>
  <textarea name="msg" maxlength="100"></textarea>
  <input type="hidden" name="csrf_token" value="abc">
  <input type="submit" value="go">
</form>
</body></html>
"""


@pytest.fixture()
def runtime(tmp_path: Path):
    configure(Settings.load("inject", db_name="xvwa", store_path=tmp_path / "tia.db"))
    yield tmp_path
    reset_runtime()


async def test_form_parse_fields_and_constraints() -> None:
    out = await form_parse({"html": FORM_HTML, "base_url": "http://127.0.0.1/xvwa/"})
    forms = out.data["forms"]
    assert out.data["form_count"] == 1
    form = forms[0]
    assert form["method"] == "post"
    assert form["action"] == "http://127.0.0.1/xvwa/post"
    names = form["field_names"]
    assert names == ["name", "msg", "csrf_token"]
    assert form["csrf_candidates"] == ["csrf_token"]
    name_field = form["fields"][0]
    assert name_field["maxlength"] == 30
    assert name_field["required"] is True


async def test_form_parse_without_forms() -> None:
    out = await form_parse({"html": "<html><body><p>hi</p></body></html>"})
    assert out.data["form_count"] == 0


async def test_context_classify_script_string() -> None:
    html = '<html><body><script>var a = "abcd";</script></body></html>'
    out = await context_classify({"html": html, "tag": "abcd"})
    assert out.data["found"] is True
    assert out.data["best"]["context_kind"] == "script_string"


async def test_context_classify_script_block() -> None:
    html = "<html><body><script>abcd</script></body></html>"
    out = await context_classify({"html": html, "tag": "abcd"})
    assert out.data["best"]["context_kind"] == "script_block"


async def test_context_classify_plain_text() -> None:
    html = "<html><body><p>abcd</p></body></html>"
    out = await context_classify({"html": html, "tag": "abcd"})
    assert out.data["best"]["context_kind"] == "html_text"


async def test_budget_solve_takes_min_limit() -> None:
    out = await budget_solve(
        {"column_length": 100, "maxlength": 30, "prefix": "pp-", "tag_len": 4, "validation_limit": 64}
    )
    assert out.data["limiting_factor"] == "maxlength"
    assert out.data["limit"] == 30
    assert out.data["max_payload_len"] == 30 - 3 - 4
    assert out.data["fits"] is True


async def test_budget_solve_overflow() -> None:
    out = await budget_solve({"column_length": 8, "prefix": "xxxxx", "tag_len": 4})
    assert out.data["fits"] is False
    assert "LENGTH_EXCEEDED" in out.warnings


async def test_budget_solve_requires_a_limit() -> None:
    with pytest.raises(ToolError) as exc:
        await budget_solve({})
    assert exc.value.code is ErrorCode.BAD_ARGS


async def test_trace_diff_reports_three_ways() -> None:
    before = [{"at": "a", "v": 1}, {"at": "b", "v": 2}]
    after = [{"at": "b", "v": 3}, {"at": "c", "v": 4}]
    out = await trace_diff({"before": before, "after": after})
    assert out.data["added_count"] == 1
    assert out.data["removed_count"] == 1
    assert out.data["changed"][0]["key"] == "b"
    assert out.data["changed"][0]["fields"] == ["v"]


async def test_flow_lookup_empty(runtime: Path) -> None:
    out = await flow_lookup({})
    assert out.data["count"] == 0
    assert "FLOWS_EMPTY" in out.warnings


async def test_flow_lookup_returns_added_flow(runtime: Path) -> None:
    from tia.inf.runtime import get_runtime

    store = get_runtime().store
    case_id = store.open_case("inject", {"sink": "a.php:1"}, [])
    store.add_flow(case_id, "form", {"base_url": "http://x/", "steps": [{"method": "POST"}]})
    out = await flow_lookup({"kind": "form"})
    assert out.data["count"] == 1
    assert out.data["flows"][0]["steps"][0]["method"] == "POST"


async def test_artifact_save_writes_under_case_dir(runtime: Path) -> None:
    from tia.inf.runtime import get_runtime

    case_id = get_runtime().store.open_case("inject", {"sink": "a.php:1"}, [])
    out = await artifact_save(
        {"case_id": case_id, "name": "report.md", "content": "# hi", "content_type": "text/markdown"}
    )
    path = Path(out.data["path"])
    assert path.is_file()
    assert path.parent.name == case_id
    assert out.data["sha256"]


@pytest.mark.parametrize(
    "name",
    ["../escape.txt", "/etc/passwd", "..", ".hidden", "a b.txt", "x;rm -rf /.txt"],
)
async def test_artifact_save_rejects_bad_names(runtime: Path, name: str) -> None:
    from tia.inf.runtime import get_runtime

    case_id = get_runtime().store.open_case("inject", {"sink": "a.php:1"}, [])
    with pytest.raises(ToolError) as exc:
        await artifact_save({"case_id": case_id, "name": name, "content": "x"})
    assert exc.value.code is ErrorCode.BAD_ARGS


async def test_artifact_save_rejects_unknown_case(runtime: Path) -> None:
    with pytest.raises(ToolError) as exc:
        await artifact_save({"case_id": "case-nope", "name": "a.txt", "content": "x"})
    assert exc.value.code is ErrorCode.NOT_FOUND


async def test_artifact_save_rejects_oversize(runtime: Path) -> None:
    from tia.inf.runtime import get_runtime

    case_id = get_runtime().store.open_case("inject", {"sink": "a.php:1"}, [])
    with pytest.raises(ToolError):
        await artifact_save({"case_id": case_id, "name": "big.txt", "content": "x" * 1_048_577})
