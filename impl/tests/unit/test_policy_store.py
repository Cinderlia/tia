"""Unit tests for the write gate and local storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from tia.cap.policy import check_write
from tia.cap.sqlparse import parse_write
from tia.inf.config import ProfileConfig
from tia.inf.store import Store
from tia.schemas.envelope import ErrorCode, ToolError


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "tia.db")


def _profile(**overrides: object) -> ProfileConfig:
    data = {"write_allow_tables": frozenset(), "write_deny_columns": frozenset(), "max_rows_per_write": 1}
    data.update(overrides)
    return ProfileConfig(name="trigger", **data)  # type: ignore[arg-type]


def _statement(sql: str) -> object:
    return parse_write(sql)


def test_write_requires_case(store: Store) -> None:
    with pytest.raises(ToolError) as exc:
        check_write(
            profile=_profile(),
            store=store,
            case_id="",
            statement=_statement("INSERT INTO comments (comment) VALUES ('x')"),
            rows=1,
        )
    assert exc.value.code is ErrorCode.POLICY_DENIED


def test_write_requires_declared_table(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [{"table": "other"}])
    with pytest.raises(ToolError) as exc:
        check_write(
            profile=_profile(),
            store=store,
            case_id=case_id,
            statement=_statement("INSERT INTO comments (comment) VALUES ('x')"),
            rows=1,
        )
    assert exc.value.code is ErrorCode.POLICY_DENIED


def test_write_allows_declared_table_and_column(store: Store) -> None:
    case_id = store.open_case(
        "trigger", {"sink": "a.php:1"}, [{"table": "comments", "column": "comment", "mode": "insert"}]
    )
    check_write(
        profile=_profile(),
        store=store,
        case_id=case_id,
        statement=_statement("INSERT INTO comments (comment) VALUES ('x')"),
        rows=1,
    )


def test_write_rejects_undeclared_column(store: Store) -> None:
    case_id = store.open_case(
        "trigger", {"sink": "a.php:1"}, [{"table": "comments", "column": "comment", "mode": "insert"}]
    )
    with pytest.raises(ToolError) as exc:
        check_write(
            profile=_profile(),
            store=store,
            case_id=case_id,
            statement=_statement("INSERT INTO comments (comment, user) VALUES ('x', 'y')"),
            rows=1,
        )
    assert exc.value.code is ErrorCode.POLICY_DENIED


def test_write_rejects_deny_column(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [{"table": "users"}])
    with pytest.raises(ToolError) as exc:
        check_write(
            profile=_profile(write_deny_columns=frozenset({"password"})),
            store=store,
            case_id=case_id,
            statement=_statement("INSERT INTO users (password) VALUES ('x')"),
            rows=1,
        )
    assert exc.value.code is ErrorCode.POLICY_DENIED


def test_write_rejects_multi_row(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [{"table": "comments"}])
    with pytest.raises(ToolError) as exc:
        check_write(
            profile=_profile(),
            store=store,
            case_id=case_id,
            statement=_statement("INSERT INTO comments (comment) VALUES ('a'), ('b')"),
            rows=2,
        )
    assert exc.value.code is ErrorCode.POLICY_DENIED


def test_store_evidence_refs_are_sequential(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [])
    first = store.add_evidence(case_id, "source", "source_read", {"a": 1})
    second = store.add_evidence(case_id, "source", "source_read", {"a": 2})
    assert first.endswith("/1")
    assert second.endswith("/2")
    assert [row["ref"] for row in store.list_evidence(case_id)] == [first, second]


def test_store_write_targets_roundtrip(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [])
    targets = [{"table": "comments", "column": "comment", "mode": "insert"}]
    store.set_write_targets(case_id, targets)
    assert store.write_targets(case_id) == targets


def test_store_change_roundtrip(store: Store) -> None:
    case_id = store.open_case("trigger", {"sink": "a.php:1"}, [])
    store.add_change(
        {
            "change_id": "ch-1",
            "case_id": case_id,
            "agent": "trigger",
            "table": "comments",
            "op": "insert",
            "sql": "INSERT INTO comments (comment) VALUES ('x')",
            "undo_sql": "DELETE FROM comments WHERE id = 1",
            "affected": 1,
            "before_image": [],
            "after_image": [{"id": 1}],
            "ts": "2026-01-01T00:00:00",
        }
    )
    changes = store.list_changes(case_id)
    assert len(changes) == 1
    assert changes[0]["id"] == "ch-1"
    assert changes[0]["reverted"] == 0
    store.mark_change_reverted("ch-1")
    assert store.list_changes(case_id, pending_only=True) == []
