"""Offline analysis tools: filter_analyze / guard_harvest / endpoint_search / includer_trace."""

from __future__ import annotations

import pytest

from tia.cap.analysis import (
    endpoint_search,
    filter_analyze,
    guard_harvest,
    includer_trace,
)
from tia.schemas.envelope import ErrorCode, ToolError


async def test_filter_analyze_reversible_chain() -> None:
    code = "$x = htmlspecialchars(addslashes($_POST['msg']));\necho $x;"
    out = await filter_analyze({"code": code})
    names = [f["name"] for f in out.data["filters"]]
    assert names == ["htmlspecialchars", "addslashes"]
    assert out.data["reversible"] is True
    assert out.data["out_filter"] == "reversible"


async def test_filter_analyze_lossy() -> None:
    code = "$id = intval($_GET['id']);\n$s = substr($msg, 0, 10);"
    out = await filter_analyze({"code": code})
    assert out.data["out_filter"] == "lossy"
    assert out.data["reversible"] is False
    catalog = {f["name"]: f["reversible"] for f in out.data["filters"]}
    assert catalog["intval"] is False
    assert catalog["substr"] is False


async def test_filter_analyze_no_filter() -> None:
    out = await filter_analyze({"code": "echo $_POST['msg'];"})
    assert out.data["filter_count"] == 0
    assert out.data["out_filter"] == "none"
    assert out.data["reversible"] is False


async def test_filter_analyze_cast_and_variable() -> None:
    code = "$a = (int) $_GET['a'];\n$b = htmlspecialchars($msg);"
    out = await filter_analyze({"code": code, "variable": "$msg"})
    assert [f["name"] for f in out.data["filters"]] == ["htmlspecialchars"]


async def test_guard_harvest_csp_meta_blocks() -> None:
    html = (
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'self\'; script-src \'self\'">'
    )
    out = await guard_harvest({"html": html})
    assert out.data["blocked"] is True
    assert out.data["blocking_kinds"] == ["csp"]


async def test_guard_harvest_csp_unsafe_inline_allows() -> None:
    headers = {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}
    out = await guard_harvest({"headers": headers})
    assert out.data["guards"][0]["blocking"] is False


async def test_guard_harvest_sandbox_and_limits() -> None:
    html = (
        '<iframe sandbox src="/x"></iframe>'
        '<input name="msg" maxlength="100" pattern="[a-z]+">'
    )
    source = "$v = htmlspecialchars($_POST['msg']);"
    out = await guard_harvest({"html": html, "source": source})
    kinds = {g["kind"] for g in out.data["guards"]}
    assert {"sandbox", "length_limit", "validation", "sanitizer"} <= kinds
    assert out.data["blocked"] is True


async def test_guard_harvest_requires_input() -> None:
    with pytest.raises(ToolError) as exc:
        await guard_harvest({})
    assert exc.value.code is ErrorCode.BAD_ARGS


async def test_endpoint_search_filters() -> None:
    index = [
        {"path": "/xvwa/login.php", "method": "POST", "params": ["username", "password"]},
        {"path": "/xvwa/post.php", "method": "POST", "params": ["msg"]},
        {"path": "/xvwa/index.php", "method": "GET"},
    ]
    out = await endpoint_search({"index": index, "query": "post", "method": "post"})
    assert out.data["hit_count"] == 1
    assert out.data["hits"][0]["path"] == "/xvwa/post.php"


async def test_endpoint_search_limit_and_no_match() -> None:
    index = [{"path": f"/p{i}.php", "method": "GET"} for i in range(10)]
    out = await endpoint_search({"index": index, "limit": 3})
    assert out.data["hit_count"] == 3
    empty = await endpoint_search({"index": index, "query": "nope"})
    assert empty.data["found"] if False else empty.data["hit_count"] == 0


async def test_includer_trace_finds_path() -> None:
    edges = [
        {"from": "index.php", "to": "lib/db.php", "kind": "require"},
        {"from": "lib/db.php", "to": "lib/render.php", "kind": "include"},
        {"from": "lib/render.php", "to": "views/post.php"},
    ]
    out = await includer_trace({"edges": edges, "entry": "index.php", "target": "views/post.php"})
    assert out.data["found"] is True
    assert out.data["paths"][0]["files"] == ["index.php", "lib/db.php", "lib/render.php", "views/post.php"]
    assert out.data["paths"][0]["length"] == 3


async def test_includer_trace_no_path_and_cycle() -> None:
    edges = [
        {"from": "a.php", "to": "b.php"},
        {"from": "b.php", "to": "a.php"},
    ]
    out = await includer_trace({"edges": edges, "entry": "a.php", "target": "c.php"})
    assert out.data["found"] is False

    loops = await includer_trace({"edges": edges, "entry": "a.php", "target": "b.php"})
    assert loops.data["found"] is True


async def test_includer_trace_max_depth() -> None:
    edges = [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}, {"from": "c", "to": "d"}]
    out = await includer_trace({"edges": edges, "entry": "a", "target": "d", "max_depth": 2})
    assert out.data["found"] is False
