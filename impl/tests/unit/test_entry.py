"""Unit tests for read-page entry derivation (second-order XSS read side)."""

from __future__ import annotations

from typing import Any

import pytest

from tia.cap.entry import (
    EntryField,
    derive_payload_constraints,
    entry_candidates,
    entry_field,
    infer_entry,
    infer_read_entry,
    resolve_values,
    resolve_values_with_guess,
)

READ_WITH_FILTER = """
$search = $_POST['search'];
$stmt = $conn->prepare("select * from caffaine where itemcode like '%$search%'");
echo $rows['itemcode'];
"""

READ_WITHOUT_FILTER = """
$user = $_POST['name'];
$comment = $_POST['msg'];
$stmt = $conn->prepare("select user,comment,date from comments");
"""

READ_WITH_NUMERIC = """
$id = intval($_GET['id']);
$stmt = $conn->prepare("select title from articles where id = $id");
"""


def test_where_less_read_has_no_entry_fields() -> None:
    method, fields = infer_read_entry(READ_WITHOUT_FILTER)
    assert method == "GET"
    assert fields == [], "a read without WHERE would turn its form into a write"


def test_like_field_is_contains() -> None:
    method, fields = infer_read_entry(READ_WITH_FILTER)
    assert method == "POST"
    assert [field.name for field in fields] == ["search"]
    assert fields[0].usage == "contains"


def test_get_field_and_numeric_cast() -> None:
    method, fields = infer_read_entry(READ_WITH_NUMERIC)
    assert method == "GET"
    assert [field.name for field in fields] == ["id"]
    assert fields[0].numeric is True
    assert fields[0].usage == "exact"


def test_resolve_uses_tag_for_contains_and_primary_key_for_exact() -> None:
    fields = [
        EntryField(name="search", usage="contains"),
        EntryField(name="id", usage="exact"),
    ]
    values = resolve_values(fields, tag="abcd", row={"id": 7}, pk_columns=["id"])
    assert values == {"search": "abcd", "id": "7"}


def test_entry_field_normalises_unknown_usage() -> None:
    field = entry_field({"name": "q", "usage": "bogus", "numeric": 1})
    assert field.usage == "unknown"
    assert field.numeric is True


class _FakeLlm:
    def __init__(self, reply: dict[str, Any]) -> None:
        self.reply = reply
        self.prompts: list[tuple[str, str]] = []

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.prompts.append((system, user))
        return self.reply


@pytest.mark.asyncio
async def test_guess_fills_only_fallback_fields() -> None:
    fields = [
        EntryField(name="search", usage="contains"),
        EntryField(name="page", usage="unknown"),
    ]
    llm = _FakeLlm({"values": {"page": "3"}})
    values, basis = await resolve_values_with_guess(
        fields, tag="abcd", row={"id": 1}, pk_columns=["id"], context="", client=llm
    )
    assert values == {"search": "abcd", "page": "3"}
    assert basis == {"search": "tag", "page": "guessed"}
    assert len(llm.prompts) == 1


@pytest.mark.asyncio
async def test_guess_failure_falls_back_to_tag() -> None:
    fields = [EntryField(name="page", usage="unknown")]
    llm = _FakeLlm({})
    values, basis = await resolve_values_with_guess(
        fields, tag="abcd", row=None, pk_columns=[], context="", client=llm
    )
    assert values == {"page": "abcd"}
    assert basis == {"page": "fallback"}


@pytest.mark.asyncio
async def test_no_client_means_no_guess() -> None:
    fields = [EntryField(name="page", usage="unknown")]
    values, _ = await resolve_values_with_guess(
        fields, tag="abcd", row=None, pk_columns=[], context="", client=None
    )
    assert values == {"page": "abcd"}


def test_entry_plan_marks_filter_and_mutating() -> None:
    plan = entry_plan = infer_entry(
        "$q = $_POST['search'];\n$r = $conn->query(\"select * from t where name like '%$q%'\");"
    )
    assert entry_plan.has_filter is True
    assert entry_plan.mutating is False
    assert [f.name for f in plan.fields] == ["search"]


def test_entry_plan_mutating_page_without_filter() -> None:
    plan = infer_entry("$name = $_POST['name'];\nINSERT INTO comments (user) VALUES (:name);")
    assert plan.has_filter is False
    assert plan.mutating is True


@pytest.mark.asyncio
async def test_candidates_without_filter_issue_a_bare_get() -> None:
    plan = infer_entry("insert into comments (user) values (:user);")
    candidates = await entry_candidates(plan, tag="abcd", row=None, pk_columns=[])
    assert [(c.method, c.values) for c in candidates] == [("GET", {})]


@pytest.mark.asyncio
async def test_candidates_rank_evidence_first() -> None:
    plan = infer_entry("$search = $_POST['search'];\nselect * from t where search like '%$search%';")
    candidates = await entry_candidates(
        plan, tag="abcd", row={"id": 7}, pk_columns=["id"], limit=3
    )
    assert candidates[0].values == {"search": "abcd"}
    assert candidates[0].confidence >= candidates[-1].confidence


@pytest.mark.asyncio
async def test_candidates_on_mutating_page_prefer_get() -> None:
    plan = infer_entry(
        "$s = $_POST['search'];\nselect * from t where name like '%$s%';\n"
        "insert into t (name) values (:search);"
    )
    candidates = await entry_candidates(plan, tag="abcd", row=None, pk_columns=[])
    assert candidates[0].method == "GET"


def test_payload_constraints_carry_output_context() -> None:
    verify = {
        "best": {
            "context_kind": "html_text",
            "quoting": None,
            "executable": True,
            "executable_reason": "HTML_EXECUTABLE",
            "match_kind": "literal",
            "node_path": "html>body>p",
        }
    }
    constraints = derive_payload_constraints(
        verify, column="comment", column_length=100, payload="<script>alert(1)</script>abcd"
    )
    assert constraints["context_kind"] == "html_text"
    assert constraints["max_length"] == 100
    assert constraints["payload_length"] == 29
    assert constraints["requires_breakout"] is False
