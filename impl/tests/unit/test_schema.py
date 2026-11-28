"""Schema prerequisites: required columns, parents, enums and prompt rendering."""

from __future__ import annotations

from typing import Any

from tia.cap.schema import (
    ColumnFact,
    ForeignKey,
    SchemaBrief,
    build_brief,
    classify_columns,
    columns_from_rows,
    fetch_brief,
    render_brief,
    valid_table,
)


def _column(name: str, **kwargs: Any) -> ColumnFact:
    return ColumnFact(name=name, **kwargs)


def test_required_columns_are_those_without_default() -> None:
    columns = [
        _column("testimonials_id", column_type="int(11)", nullable=False, key="PRI", extra="auto_increment"),
        _column("languages_id", column_type="int(11)", nullable=False),
        _column("testimonials_text", column_type="text", nullable=True, width=64),
        _column("taken", column_type="varchar(8)", nullable=False, default="0"),
    ]
    shaped = classify_columns(columns)
    names = [item["name"] for item in shaped["required"]]
    assert names == ["languages_id"]
    assert shaped["widths"]["testimonials_text"] == 64
    assert shaped["defaults"]["taken"] == "0"


def test_payload_columns_are_excluded_from_requirements() -> None:
    columns = [
        _column("body", column_type="text", nullable=False),
        _column("title", column_type="varchar(10)", nullable=False),
    ]
    shaped = classify_columns(columns, payload_columns=["body"])
    assert [item["name"] for item in shaped["required"]] == ["title"]
    assert shaped["optional"][0]["name"] == "body"
    assert shaped["optional"][0]["payload"] is True


def test_foreign_key_marks_row_requirement_and_parent() -> None:
    columns = [_column("parent_id", column_type="int(11)", nullable=False)]
    parents = [ForeignKey("parent_id", "parent", "id", "CASCADE")]
    shaped = classify_columns(columns, parents)
    fact = shaped["required"][0]
    assert fact["prerequisite"] == "row"
    assert fact["parent"] == "parent"


def test_enum_is_a_constant_with_choices() -> None:
    columns = [_column("status", column_type="enum('on','off')", nullable=False)]
    shaped = classify_columns(columns)
    fact = shaped["required"][0]
    assert fact["prerequisite"] == "constant"
    assert fact["choices"] == ["on", "off"]
    assert shaped["enums"]["status"] == ["on", "off"]


def test_context_column_is_marked_context() -> None:
    columns = [_column("customer_id", column_type="int(11)", nullable=False)]
    shaped = classify_columns(columns)
    assert shaped["required"][0]["prerequisite"] == "context"


def test_brief_notes_missing_defaults_and_render_is_short() -> None:
    brief = build_brief(
        "testimonials_description",
        [
            _column("testimonials_id", column_type="int(11)", nullable=False),
            _column("languages_id", column_type="int(11)", nullable=False, default="1"),
            _column("testimonials_text", column_type="text", nullable=True),
        ],
        [ForeignKey("testimonials_id", "testimonials", "testimonials_id", "CASCADE")],
        payload_columns=["testimonials_text"],
    )
    assert isinstance(brief, SchemaBrief)
    text = render_brief(brief)
    assert "SCHEMA PREREQUISITES for `testimonials_description`" in text
    assert "testimonials_id: row" in text
    assert "languages_id" not in text.split("\n")[1]


def test_render_brief_tolerates_empty() -> None:
    assert render_brief(None) == ""
    assert render_brief({"table": "t", "required": [], "parents": []}) == ""


def test_valid_table_rejects_quotes() -> None:
    assert valid_table("testimonials")
    assert not valid_table("testimonials; drop")
    assert not valid_table("")


def test_columns_from_rows_converts_mysql_types() -> None:
    facts = columns_from_rows(
        [
            {
                "name": "id",
                "data_type": "int",
                "column_type": "int(11)",
                "is_nullable": "NO",
                "column_default": None,
                "extra": "auto_increment",
                "width": None,
                "column_key": "PRI",
            },
            {
                "name": "status",
                "column_type": "enum('a','b')",
                "is_nullable": "YES",
                "column_default": "a",
                "width": "1",
            },
        ]
    )
    assert facts[0].auto and not facts[0].nullable
    assert facts[0].enum == []
    assert facts[1].enum == ["a", "b"]
    assert facts[1].width == 1


async def test_fetch_brief_uses_the_schema_tool() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
        calls.append((name, args))
        return {
            "tables": [
                {
                    "name": "child",
                    "primary_key": ["id"],
                    "columns": [
                        {
                            "name": "id",
                            "type": "int",
                            "column_type": "int(11)",
                            "nullable": False,
                            "default": None,
                            "extra": "auto_increment",
                            "length": None,
                        },
                        {
                            "name": "parent_id",
                            "type": "int",
                            "column_type": "int(11)",
                            "nullable": False,
                            "default": None,
                            "extra": "",
                            "length": None,
                        },
                    ],
                    "fks": [
                        {
                            "column": "parent_id",
                            "ref_table": "parent",
                            "ref_column": "id",
                            "delete_rule": "CASCADE",
                        }
                    ],
                }
            ]
        }

    brief = await fetch_brief(call, "child")
    assert [item["name"] for item in brief.required] == ["parent_id"]
    assert brief.required[0]["prerequisite"] == "row"
    assert brief.parents[0].parent_table == "parent"
    assert {name for name, _ in calls} == {"db_schema"}
