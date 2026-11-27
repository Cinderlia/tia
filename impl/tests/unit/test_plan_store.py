"""Models and storage for the database-constraint plan."""

from __future__ import annotations

from pathlib import Path

import pytest

from tia.inf.store import Store
from tia.schemas.plan import ConstraintPlan, ConstraintWrite, PayloadPlan, Step


def test_payload_plan_round_trip() -> None:
    plan = PayloadPlan(
        table="posts",
        column="content",
        payload="<script>alert(1)</script>ab12",
        tag="ab12",
        context_kind="html_text",
        out_filter="none",
        length_budget=64,
    )
    dumped = plan.model_dump()
    assert PayloadPlan.model_validate(dumped) == plan


def test_constraint_write_bounds() -> None:
    item = ConstraintWrite(
        constraint_id="dc-1",
        table="posts",
        column="post_status",
        value="publish",
        predicate="if ($post->post_status !== 'publish')",
        at="wp-admin/post.php:41",
    )
    assert item.op == "set"
    assert item.replay == "app_request"
    with pytest.raises(ValueError):
        ConstraintWrite(
            constraint_id="dc-2", table="posts", column="x", confidence=101
        )


def test_plan_orders_payload_after_constraint() -> None:
    plan = ConstraintPlan(
        steps=[
            Step(kind="constraint", ref="dc-1"),
            Step(kind="payload", ref="payload"),
            Step(kind="constraint", ref="dc-2"),
        ],
        payload=PayloadPlan(
            table="posts", column="content", payload="p", tag="ab12"
        ),
        constraints=[
            ConstraintWrite(constraint_id="dc-1", table="posts", column="post_status"),
            ConstraintWrite(constraint_id="dc-2", table="posts", column="post_status"),
        ],
    )
    assert [step.ref for step in plan.ordered_steps()] == [
        "dc-1",
        "payload",
        "dc-2",
    ]
    assert plan.constraint("dc-2") is not None
    assert plan.constraint("missing") is None


def test_pair_request_round_trip(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    request_id = store.add_pair_request(
        run_id="run-1",
        read_slice_id="slice-1",
        table="posts",
        column="post_status",
        op="set",
        value="publish",
    )
    row = store.get_pair_request(request_id)
    assert row is not None
    assert row["status"] == "pending"
    assert row["value"] == "publish"
    assert row["candidates"] == []

    assert store.respond_pair_request(
        request_id,
        candidates=[{"write_slice_id": "w-1", "confidence": 80}],
        reason="same table and column",
    )
    answered = store.get_pair_request(request_id)
    assert answered is not None
    assert answered["status"] == "answered"
    assert answered["candidates"][0]["write_slice_id"] == "w-1"
    assert answered["reason"] == "same table and column"

    # only one answer is accepted
    assert not store.respond_pair_request(request_id, candidates=[])


def test_pair_request_filters_and_no_path(tmp_path: Path) -> None:
    store = Store(tmp_path / "tia.db")
    first = store.add_pair_request(run_id="run-a", read_slice_id="s1", table="t")
    second = store.add_pair_request(run_id="run-b", read_slice_id="s2", table="u")
    store.respond_pair_request(second, candidates=[], reason="no write path", status="no_path")

    assert [row["request_id"] for row in store.list_pair_requests(run_id="run-a")] == [first]
    assert [row["request_id"] for row in store.list_pair_requests(status="no_path")] == [
        second
    ]
    assert store.get_pair_request("missing") is None
