from __future__ import annotations

import os
from pathlib import Path

from tia.inf.findings import finding_db_only, finding_first_order, finding_second_order
from tia.inf.store import Store


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
    index = (tmp_path / "reports" / "findings.md").read_text(encoding="utf-8")
    assert "Confirmed second-order XSS" in index
    assert path.name in index


def test_finding_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TIA_REPORTS", str(tmp_path / "reports"))
    store = Store(tmp_path / "tia.db")
    case_id = _case(store, SECOND)
    first = finding_second_order(store, case_id)
    second = finding_second_order(store, case_id)
    assert first == second
    index = (tmp_path / "reports" / "findings.md").read_text(encoding="utf-8")
    assert index.count("Confirmed second-order XSS") == 1  # one index row, no duplicate


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
