from __future__ import annotations

from pathlib import Path

import pytest

from tia.inf.calllog import case_scope, log_call, log_path


@pytest.fixture(autouse=True)
def _log_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TIA_TOOL_LOG", str(tmp_path / "logs"))


def test_each_case_gets_its_own_file(tmp_path: Path) -> None:
    log_call(agent="trigger", tool="source_read", ok=True, arguments={"file": "a.php"},
             data={"text": "x" * 100})
    assert log_path().name == "no-case.log"
    with case_scope("case-1"):
        log_call(agent="trigger", tool="source_read", ok=True, arguments={"file": "a.php"},
                 data={"text": "x" * 100})
    with case_scope("case-2"):
        log_call(agent="inject", tool="http_request", ok=False, arguments={"url": "u"},
                 error={"code": "ENV_ERROR", "message": "boom"})

    first = (tmp_path / "logs" / "case-1.log").read_text(encoding="utf-8")
    second = (tmp_path / "logs" / "case-2.log").read_text(encoding="utf-8")
    assert "agent=trigger tool=source_read ok=true" in first
    assert 'args={"file": "a.php"}' in first
    assert "result=" in first
    assert len(first.split("result=", 1)[1].splitlines()[0]) == 40
    assert "agent=inject tool=http_request ok=false" in second
    assert "ENV_ERROR" in second


def test_switch_off_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIA_TOOL_LOG", "off")
    assert log_path() is None
    assert log_call(agent="trigger", tool="case_open", ok=True, arguments={}) is None
    assert not (tmp_path / "logs").exists()
