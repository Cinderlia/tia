from __future__ import annotations

import json
from pathlib import Path

from tia.inf.reports import RunReports, reports_root, write_case_report
from tia.inf.store import Store


def _case(store: Store) -> str:
    return store.open_case("trigger", {"sinkFile": "app/x.php", "sinkLine": 1}, [])


def test_write_case_report_uses_stored_markdown(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(store)
    assert write_case_report(store, case_id) is None  # no report yet

    store.set_case_report(case_id, "# Case\n\nbody\n")
    path = write_case_report(store, case_id)
    assert path is not None
    assert path.read_text(encoding="utf-8") == "# Case\n\nbody\n"
    assert reports_root(store) == tmp_path / "reports"


def test_run_reports_index_links_each_case(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    first = _case(store)
    second = _case(store)
    store.set_case_report(first, "# first\n")
    store.set_case_report(second, "# second\n")

    run = RunReports(store, "run-1")
    run.add(first, "trigger", "EXECUTED", "app/x.php:1")
    run.add(second, "inject", "EXECUTABLE", "comments.comment")
    index = run.finish("DONE", rounds=2, outcomes=2)

    text = index.read_text(encoding="utf-8")
    assert "TIA run report: run-1" in text
    assert f"[{first}](cases/{first}.md)" in text
    assert f"[{second}](cases/{second}.md)" in text
    assert "- Stop reason: DONE" in text
    assert "| EXECUTED | 1 |" in text
    assert "| EXECUTABLE | 1 |" in text
    written = (index.parent / "cases" / f"{first}.md").read_text(encoding="utf-8")
    assert written == "# first\n"


def test_run_reports_handles_cases_without_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(store)
    run = RunReports(store, "run-2")
    assert run.add(case_id, "trigger", "ERROR", "?") is None
    index = run.finish("EXHAUSTED", rounds=1, outcomes=1)
    assert f"| trigger | {case_id} |" in index.read_text(encoding="utf-8")


def test_reports_root_defaults_next_to_store(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("TIA_REPORTS", raising=False)
    store = Store(tmp_path / "nested" / "tia.db")
    assert reports_root(store) == tmp_path / "nested" / "reports"
    assert json.dumps({"ok": True})
