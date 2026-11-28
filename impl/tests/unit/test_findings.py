from __future__ import annotations

import os
from pathlib import Path

import pytest

from tia.inf.findings import finding_db_only, finding_first_order, finding_second_order
from tia.inf.store import Store


@pytest.fixture(autouse=True)
def _fixed_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tia.inf.reports.peek_settings", lambda: None)
    monkeypatch.delenv("TIA_APP_ROOT", raising=False)
    monkeypatch.setenv("TIA_REPORTS_TARGET", "default")


def _case(store: Store, notes: dict) -> str:
    case_id = store.open_case("inject", {"sinkFile": "vulnerabilities/stored_xss/home.php"}, [])
    store.merge_case_notes(case_id, notes)
    return case_id


SECOND = {
    "sink": "vulnerabilities/stored_xss/home.php:61",
    "sink_code": 'echo ucfirst($row["user"]);',
    "entry": {
        "url": "http://127.0.0.1/xvwa/vulnerabilities/stored_xss/",
        "method": "post",
        "field": "msg",
    },
    "payload": "<script>alert(1)</script><tia-r074>",
    "target": {"table": "comments", "column": "comment", "columns": ["user", "comment"]},
    "probe": {"sql": "insert into comments (user,comment,date) values('a','b','c')"},
    "tag": "r074",
    "tag_in_db": True,
    "read_target": {"file": "vulnerabilities/stored_xss/home.php", "line": 55},
    "account": "bwapp-admin",
}


def test_second_order_finding_is_written(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(store, SECOND)
    path = finding_second_order(store, case_id)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "Confirmed second-order XSS" in text
    assert "vulnerabilities/stored_xss/home.php:61" in text
    assert "field `msg`" in text
    assert "`comments`.`comment`" in text
    assert "insert into comments" in text
    assert "bwapp-admin" in text
    index = (tmp_path / "reports" / "default" / "findings.md").read_text(encoding="utf-8")
    assert "Confirmed second-order XSS" in index
    assert path.name in index


def test_finding_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(store, SECOND)
    first = finding_second_order(store, case_id)
    second = finding_second_order(store, case_id)
    assert first == second
    index = (tmp_path / "reports" / "default" / "findings.md").read_text(encoding="utf-8")
    assert index.count("Confirmed second-order XSS") == 1  # one index row, no duplicate


def test_reconfirmation_refreshes_the_same_finding_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    first = finding_second_order(store, _case(store, SECOND))
    changed = dict(SECOND, tag="n3w1", payload="<script>alert(1)</script>n3w1")
    second = finding_second_order(store, _case(store, changed))
    assert first == second
    text = second.read_text(encoding="utf-8")
    assert "n3w1" in text and "r074" not in text
    index = (tmp_path / "reports" / "default" / "findings.md").read_text(encoding="utf-8")
    assert index.count("Confirmed second-order XSS") == 1


def test_db_only_finding_names_the_sql(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(
        store,
        {
            "sink": "vulnerabilities/stored_xss/home.php:62",
            "insert_sql": "INSERT INTO `comments` (`comment`) VALUES ('<script>x</script>')",
            "table": "comments",
            "payload_constraints": {"column": "comment"},
            "payload": "<script>x</script>",
            "base_url": "http://127.0.0.1/xvwa/vulnerabilities/stored_xss/",
            "read_target": {"file": "vulnerabilities/stored_xss/home.php", "line": 55},
        },
    )
    path = finding_db_only(store, case_id)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "database path only" in text
    assert "INSERT INTO `comments`" in text
    assert "no HTTP request was confirmed" in text
    assert "anonymous (no login)" in text


def test_first_order_finding(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(
        store,
        {
            "sink": "vulnerabilities/reflected_xss/home.php:32",
            "sink_code": 'echo $_GET["item"];',
            "entry": {
                "url": "http://127.0.0.1/xvwa/vulnerabilities/reflected_xss/",
                "method": "get",
                "field": "item",
            },
            "payload": '<img src=x onerror="alert(1)">',
            "account": "anonymous (no login)",
        },
    )
    path = finding_first_order(store, case_id)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "Confirmed first-order XSS" in text
    assert "GET http://127.0.0.1/xvwa/vulnerabilities/reflected_xss/" in text
    assert os.environ["TIA_REPORTS"] in str(path)


def test_second_order_finding_lists_constraint_prerequisites(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    notes = dict(SECOND)
    notes["constraints"] = [
        {
            "constraint_id": "dc-1",
            "table": "posts",
            "column": "status",
            "value": "publish",
            "predicate": "page lists the post only when it is published",
            "replay": "app_request",
        }
    ]
    case_id = _case(store, notes)
    path = finding_second_order(store, case_id)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "## Additional SQL requirements" in text
    assert "`posts`.`status` must equal `publish`" in text
    assert "not replayed through the application" in text


def test_second_order_finding_lists_extra_sql_requirements(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    monkeypatch.setenv("TIA_REPORTS_TARGET", "PhoenixCart")
    store = Store(tmp_path / "tia.db")
    notes = dict(SECOND)
    notes["payload"] = "<script>alert(1)</script>pd2c"
    notes["execution"] = {
        "final_url": "http://127.0.0.1/PhoenixCart/testimonials.php",
        "dialogs": [{"type": "alert", "message": "1"}],
    }
    notes["constraint_steps"] = [
        {
            "constraint_id": "dc-1",
            "table": "testimonials",
            "column": "testimonials_status",
            "value": "1",
            "predicate": "t.testimonials_status = 1 ORDER BY t.testimonials_id DESC",
            "account": "admin",
            "replay": {
                "url": "http://127.0.0.1/PhoenixCart/admin/testimonials.php?action=set_flag",
                "observed": 1,
                "confirmed": True,
                "attempts": [
                    {
                        "params": {"flag": "1", "tID": 30, "formid": "a" * 64},
                        "status": 302,
                        "queries": 1,
                    }
                ],
            },
        }
    ]
    case_id = _case(store, notes)
    path = finding_second_order(store, case_id)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "## Additional SQL requirements" in text
    assert "`testimonials`.`testimonials_status` must equal `1`" in text
    assert "action=set_flag" in text
    assert "account `admin`" in text
    assert "probe matched 1 executed statement(s)" in text
    assert "GET http://127.0.0.1/PhoenixCart/testimonials.php" in text
    assert "formid=<session token>" in text
    assert "tID=<id of the row you created>" in text
    index = (tmp_path / "reports" / "PhoenixCart" / "findings.md").read_text(encoding="utf-8")
    assert path.name in index
