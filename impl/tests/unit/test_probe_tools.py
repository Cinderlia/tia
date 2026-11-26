"""Unit tests for the probe tools (probe_arm / probe_run / probe_disarm)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tia.ad.http import HttpResult
from tia.cap import probe as probe_mod
from tia.cap.probe import probe_arm, probe_disarm, probe_run
from tia.inf.config import Settings
from tia.inf.runtime import configure, get_runtime, reset_runtime
from tia.schemas.envelope import ErrorCode, ToolError

SOURCE = """<?php
$stmt = $conn1->prepare("select user,comment,date from comments");
$stmt->execute();
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    echo $row['comment'];
}
"""

CAPTURE = {
    "target_file": "/app/xvwa/vulnerabilities/stored_xss/home.php",
    "target_line": 2,
    "query_count": 1,
    "queries": [
        {
            "call_index": 1,
            "sql": "select user,comment,date from comments",
            "kind": "prepared",
            "matched_at_prepare": True,
            "matched_at_origin": False,
            "matched_at_fetch": False,
            "row_count": 2,
            "affected_rows": 0,
            "execute_time_ms": 0.42,
            "fields": [
                {"name": "user", "table": "comments", "type": 253, "length": 120},
                {"name": "comment", "table": "comments", "type": 253, "length": 400},
                {"name": "date", "table": "comments", "type": 253, "length": 120},
            ],
            "rows": [["admin", "hello", "10 Aug 2015"], ["bob", "hi", "11 Aug 2015"]],
        }
    ],
}


class FakeHttp:
    """Stands in for HttpClient; records the call and returns a fixed page."""

    calls: list[dict[str, Any]] = []
    status = 200

    def fetch(self, method: str, url: str, **kwargs: Any) -> HttpResult:
        FakeHttp.calls.append({"method": method, "url": url, **kwargs})
        return HttpResult(
            status=FakeHttp.status,
            final_url=url,
            content_type="text/html",
            headers={},
            redirect_chain=[],
            body_bytes=128,
            body="<html><body>ok</body></html>",
            truncated=False,
        )


@pytest.fixture()
def env(tmp_path: Path) -> Any:
    app_root = tmp_path / "app"
    app_root.mkdir()
    (app_root / "home.php").write_text(SOURCE, encoding="utf-8")
    probe_base = tmp_path / "probe"
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
    case_id = rt.store.open_case("trigger", {"kind": "SQL"}, [])
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("TIA_PROBE_BASE", str(probe_base))
    monkeypatch.setattr(probe_mod, "HttpClient", FakeHttp)
    FakeHttp.calls.clear()
    yield {"app_root": app_root, "probe_base": probe_base, "case_id": case_id}
    monkeypatch.undo()
    reset_runtime()


async def _arm(env: dict[str, Any], **overrides: Any) -> Any:
    args = {"case_id": env["case_id"], "file": "home.php", "line": 2}
    args.update(overrides)
    return await probe_arm(args)


async def test_arm_writes_config_and_records_probe(env: dict[str, Any]) -> None:
    out = await _arm(env)
    config = json.loads((env["probe_base"] / "sql_query.json").read_text())
    assert len(config["targets"]) == 1
    assert config["targets"][0]["line"] == 2
    assert config["targets"][0]["file"].endswith("home.php")
    assert config["output"] == f"{env['case_id']}-2.json"
    assert out.data["probe_id"] == f"probe-{env['case_id']}-2"
    assert out.data["target"]["match"] == "line"


async def test_arm_warns_when_slot_is_reused(env: dict[str, Any]) -> None:
    await _arm(env)
    out = await _arm(env, line=4, output="second.json")
    assert "PROBE_SLOT_REUSED" in out.warnings
    assert (env["probe_base"] / "sql_query.json").exists()


async def test_arm_rejects_path_outside_app_root(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await _arm(env, file="/etc/passwd")
    assert excinfo.value.code is ErrorCode.POLICY_DENIED


async def test_arm_rejects_traversal_in_output_name(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await _arm(env, output="../escape.json")
    assert excinfo.value.code is ErrorCode.BAD_ARGS


async def test_arm_respects_basename_only_output(env: dict[str, Any]) -> None:
    out = await _arm(env, output="result.json")
    assert out.data["output"] == "result.json"


async def test_run_requires_armed_probe(env: dict[str, Any]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/"})
    assert excinfo.value.code is ErrorCode.CONFLICT


async def test_run_reads_capture_and_normalizes_rows(env: dict[str, Any]) -> None:
    await _arm(env)
    output_dir = env["probe_base"] / "sql"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{env['case_id']}-2.json").write_text(json.dumps(CAPTURE), encoding="utf-8")
    (output_dir / "sqlquery_debug.log").write_text("matched_queries=1\n", encoding="utf-8")

    out = await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/home.php"})

    assert out.data["hit"] is True
    assert out.data["mode"] == "read"
    query = out.data["queries"][0]
    assert query["sql"].startswith("select user")
    assert query["matched_at"] == "prepare"
    assert query["row_count"] == 2
    assert query["rows"][1] == {"user": "bob", "comment": "hi", "date": "11 Aug 2015"}
    assert out.data["http"]["status"] == 200
    assert FakeHttp.calls[0]["url"].endswith("/xvwa/home.php")


async def test_run_without_capture_reports_not_found(env: dict[str, Any]) -> None:
    await _arm(env)
    with pytest.raises(ToolError) as excinfo:
        await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/"})
    assert excinfo.value.code is ErrorCode.NOT_FOUND


async def test_run_marks_missing_debug_match(env: dict[str, Any]) -> None:
    await _arm(env)
    output_dir = env["probe_base"] / "sql"
    output_dir.mkdir(parents=True, exist_ok=True)
    empty = dict(CAPTURE, query_count=0, queries=[])
    (output_dir / f"{env['case_id']}-2.json").write_text(json.dumps(empty), encoding="utf-8")
    (output_dir / "sqlquery_debug.log").write_text("matched_queries=0\n", encoding="utf-8")
    out = await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/"})
    assert out.data["hit"] is False
    assert "PROBE_NO_MATCH" in out.warnings


async def test_write_capture_sets_write_mode(env: dict[str, Any]) -> None:
    await _arm(env, line=3)
    write_capture = {
        "target_file": "/app/home.php",
        "target_line": 3,
        "query_count": 1,
        "queries": [
            {
                "call_index": 1,
                "sql": "insert into comments (user, comment) values (?, ?)",
                "kind": "prepared",
                "affected_rows": 1,
                "last_insert_id": 7,
                "row_count": 0,
                "fields": [],
                "rows": [],
                "write": {
                    "operation": "INSERT",
                    "table": "comments",
                    "columns": ["user", "comment"],
                    "parameters": ["alice", "hello"],
                },
            }
        ],
    }
    output_dir = env["probe_base"] / "sql"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{env['case_id']}-3.json").write_text(json.dumps(write_capture), encoding="utf-8")
    out = await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/"})
    assert out.data["mode"] == "write"
    query = out.data["queries"][0]
    assert query["bindings"] == ["alice", "hello"]
    assert query["affected_rows"] == 1
    assert query["last_insert_id"] == 7


async def test_disarm_removes_config_and_output(env: dict[str, Any]) -> None:
    await _arm(env)
    output_dir = env["probe_base"] / "sql"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{env['case_id']}-2.json").write_text("{}", encoding="utf-8")
    out = await probe_disarm({})
    assert out.data["disarmed"] is True
    assert out.data["removed_output"] is True
    assert not (env["probe_base"] / "sql_query.json").exists()


async def test_disarm_with_nothing_armed(env: dict[str, Any]) -> None:
    out = await probe_disarm({"case_id": env["case_id"]})
    assert out.data["disarmed"] is False


async def test_arm_accepts_several_targets(env: dict[str, Any]) -> None:
    out = await probe_arm(
        {
            "case_id": env["case_id"],
            "targets": [
                {"file": "home.php", "line": 2},
                {"file": "home.php", "line": 5},
            ],
        }
    )
    config = json.loads((env["probe_base"] / "sql_query.json").read_text())
    assert [item["line"] for item in config["targets"]] == [2, 5]
    assert len(out.data["targets"]) == 2
    assert out.data["probe_id"].endswith("-2")


async def test_run_reports_by_target_and_unmatched_targets(env: dict[str, Any]) -> None:
    await probe_arm(
        {
            "case_id": env["case_id"],
            "targets": [
                {"file": "home.php", "line": 2},
                {"file": "home.php", "line": 5},
            ],
        }
    )
    output_dir = env["probe_base"] / "sql"
    output_dir.mkdir(parents=True, exist_ok=True)
    capture = json.loads(json.dumps(CAPTURE))
    capture["queries"][0]["target_index"] = 0
    capture["queries"][0]["target_file"] = "/app/home.php"
    capture["queries"][0]["target_line"] = 2
    (output_dir / f"{env['case_id']}-2.json").write_text(json.dumps(capture), encoding="utf-8")
    (output_dir / "sqlquery_debug.log").write_text("matched_queries=1\n", encoding="utf-8")
    out = await probe_run({"case_id": env["case_id"], "url": "http://127.0.0.1/xvwa/home.php"})
    assert out.data["queries"][0]["target_index"] == 0
    assert out.data["by_target"][0]["target_line"] == 2
    assert "PROBE_TARGET_UNMATCHED" in out.warnings
