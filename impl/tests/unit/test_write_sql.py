"""The model writes the SQL; local code only renders the payload marker."""

from __future__ import annotations

import pytest

from tia.cap import write_sql
from tia.schemas.envelope import ToolError


class FakeModel:
    def __init__(self, reply: dict[str, object]) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    async def complete_json(self, prompt: str, payload: object) -> dict[str, object]:
        self.prompts.append(prompt)
        return self.reply


def test_compile_renders_the_payload_and_checks_the_statement() -> None:
    sql, statement = write_sql.compile(
        "UPDATE `comments` SET `comment` = {{PAYLOAD}} WHERE `id` = {{ROW_ID}}",
        table="comments",
        columns=["id", "comment"],
        payload="<script>alert(1)</script>ab12",
        row_id=44,
    )
    assert statement.op == "update"
    assert statement.has_where
    assert "ab12" in sql
    assert "id` = 44" in sql


def test_compile_rejects_an_update_without_where() -> None:
    with pytest.raises(ToolError):
        write_sql.compile(
            "UPDATE `comments` SET `comment` = {{PAYLOAD}}",
            table="comments",
            columns=["id", "comment"],
            payload="x",
        )


def test_compile_rejects_unknown_columns_and_other_tables() -> None:
    with pytest.raises(ToolError):
        write_sql.compile(
            "UPDATE `comments` SET `body` = {{PAYLOAD}} WHERE `id` = 1",
            table="comments",
            columns=["id", "comment"],
            payload="x",
        )
    with pytest.raises(ToolError):
        write_sql.compile(
            "UPDATE `users` SET `comment` = {{PAYLOAD}} WHERE `id` = 1",
            table="comments",
            columns=["id", "comment"],
            payload="x",
        )


def test_compile_requires_the_payload_marker_exactly_once() -> None:
    with pytest.raises(ToolError):
        write_sql.compile(
            "UPDATE `comments` SET `comment` = 'fixed' WHERE `id` = 1",
            table="comments",
            columns=["id", "comment"],
            payload="x",
        )


async def test_plan_write_sql_feeds_the_executed_read_to_the_model() -> None:
    model = FakeModel(
        {
            "sql": "UPDATE `comments` SET `date` = {{PAYLOAD}} WHERE `id` = {{ROW_ID}}",
            "column": "date",
            "reason": "the sink prints the third column",
        }
    )
    plan = await write_sql.plan_write_sql(
        model,
        sink="home.php:14\n$rows[2]",
        table="comments",
        columns=["id", "user", "comment", "date"],
        schema="SCHEMA PREREQUISITES for `comments`",
        observed=[
            {
                "sql": "select user,comment,date from comments",
                "line": 5,
                "rows": [{"id": 44, "user": "a", "comment": "b", "date": "c"}],
            }
        ],
        rows=[{"id": 44}],
        payload="<script>alert(1)</script>ab12",
        tag="ab12",
    )
    assert plan["column"] == "date"
    assert "id` = 44" in str(plan["sql"])
    prompt = model.prompts[0]
    assert "select user,comment,date from comments" in prompt
    assert "ab12" in prompt
    assert "{{PAYLOAD}}" in prompt


async def test_plan_write_sql_requires_a_known_column() -> None:
    model = FakeModel({"sql": "UPDATE `comments` SET `comment` = {{PAYLOAD}} WHERE `id` = 1"})
    with pytest.raises(ToolError):
        await write_sql.plan_write_sql(
            model,
            sink="home.php:14",
            table="comments",
            columns=["id", "comment"],
            schema="",
            observed=[],
            rows=[],
            payload="x",
            tag="ab12",
        )


def test_column_order_follows_the_executed_select_list() -> None:
    observed = [{"sql": "select t.user, `comment`, date from comments t"}]
    assert write_sql.column_order(observed, []) == ["user", "comment", "date"]


def test_column_order_falls_back_to_the_row_keys() -> None:
    observed = [{"sql": "select * from comments"}]
    rows = [{"user": "a", "comment": "b", "date": "c"}]
    assert write_sql.column_order(observed, rows) == ["user", "comment", "date"]


async def test_plan_write_sql_numbers_the_read_columns() -> None:
    model = FakeModel(
        {
            "sql": "UPDATE `comments` SET `date` = {{PAYLOAD}} WHERE `id` = 44",
            "column": "date",
        }
    )
    await write_sql.plan_write_sql(
        model,
        sink='<span class="pull-right">".$rows[2]."</span>',
        table="comments",
        columns=["id", "user", "comment", "date"],
        schema="",
        observed=[
            {
                "sql": "select user,comment,date from comments",
                "line": 5,
                "rows": [{"user": "a", "comment": "b", "date": "c"}],
            }
        ],
        rows=[{"user": "a", "comment": "b", "date": "c"}],
        payload="<script>alert(1)</script>ab12",
        tag="ab12",
    )
    prompt = model.prompts[0]
    assert "0: user" in prompt
    assert "1: comment" in prompt
    assert "2: date" in prompt
