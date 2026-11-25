"""SQL 语法闸门的单元测试（安全边界，任何放松都要先改这里）。"""

from __future__ import annotations

import pytest

from tia.cap.sqlparse import parse_read, parse_write
from tia.schemas.envelope import ErrorCode, ToolError


def test_insert_single_row() -> None:
    statement = parse_write("INSERT INTO `comments` (`user`, `comment`) VALUES ('a', 'b')")
    assert statement.op == "insert"
    assert statement.table == "comments"
    assert statement.columns == ["user", "comment"]
    assert statement.value_rows == 1


def test_insert_two_rows_detected() -> None:
    statement = parse_write("INSERT INTO t (a) VALUES (1), (2)")
    assert statement.value_rows == 2


def test_update_requires_where() -> None:
    with pytest.raises(ToolError) as exc:
        parse_write("UPDATE t SET a = 1")
    assert exc.value.code is ErrorCode.BAD_ARGS


def test_delete_requires_where() -> None:
    with pytest.raises(ToolError) as exc:
        parse_write("DELETE FROM t")
    assert exc.value.code is ErrorCode.BAD_ARGS


def test_multi_statement_rejected() -> None:
    with pytest.raises(ToolError):
        parse_write("DELETE FROM t WHERE id = 1; DELETE FROM t WHERE id = 2")


def test_comment_bypass_rejected() -> None:
    with pytest.raises(ToolError):
        parse_write("UPDATE t SET a = 1 WHERE id = 2 -- and more")
    with pytest.raises(ToolError):
        parse_write("SELECT 1 /* sneaky */")


def test_ddl_rejected() -> None:
    for sql in ("DROP TABLE t", "CREATE TABLE t (a INT)", "TRUNCATE TABLE t"):
        with pytest.raises(ToolError):
            parse_write(sql)


def test_system_schema_rejected() -> None:
    with pytest.raises(ToolError):
        parse_read("SELECT * FROM information_schema.tables")
    with pytest.raises(ToolError):
        parse_read("SELECT * FROM mysql.user")


def test_read_accepts_select_show_explain() -> None:
    assert parse_read("SELECT 1") == "SELECT 1"
    assert parse_read("SHOW TABLES") == "SHOW TABLES"
    assert parse_read("EXPLAIN SELECT 1") == "EXPLAIN SELECT 1"


def test_read_rejects_write() -> None:
    with pytest.raises(ToolError):
        parse_read("DELETE FROM t WHERE id = 1")


def test_insert_into_outfile_rejected() -> None:
    with pytest.raises(ToolError):
        parse_write("INSERT INTO t (a) VALUES (1) INTO OUTFILE '/tmp/x'")
