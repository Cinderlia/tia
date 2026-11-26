"""Cross-family learning: one prior per site, shared by both slice families."""

from __future__ import annotations

from pathlib import Path

from tia.inf.store import Store
from tia.orch.learning import (
    hints_for,
    order_shapes,
    preferred_payload_shape,
    record_case,
    score_delta,
    site_keys,
)

DIRECT = {
    "kind": "Xss",
    "sinkFile": "vulnerabilities/sqli/home.php",
    "sinkLine": 71,
    "sinkCode": 'echo $row["title"];',
}
SECOND = {
    "kind": "Xss",
    "sinkFile": "vulnerabilities/sqli/home.php",
    "sinkLine": 55,
    "sinkCode": "select title from caffaine",
}


def test_site_keys_are_family_agnostic() -> None:
    assert site_keys(DIRECT) == site_keys(SECOND) == (
        "vulnerabilities/sqli/home.php",
        "vulnerabilities/sqli",
    )


def test_direct_success_is_visible_to_second_order_slice(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    record_case(
        store,
        DIRECT,
        "EXECUTED",
        {
            "attempts": [
                {"shape": "img_onerror", "executable": True, "context_kind": "attr"},
                {"shape": "script_tag", "executable": False},
            ],
            "entry": {"fields": ["search", "submit"]},
        },
    )
    hints = hints_for(store, SECOND)
    assert hints["preferred_shapes"] == ["img_onerror"]
    assert hints["contexts"] == ["attr"]
    assert "search" in hints["entry_fields"]
    assert hints["successes"] == 1


def test_second_order_failure_depresses_the_same_site(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    for _ in range(3):
        record_case(store, SECOND, "READ_NOT_REFLECTED", {"entry": {"fields": ["search"]}})
    hints = hints_for(store, DIRECT)
    delta, reasons = score_delta(hints)
    assert delta == -10
    assert reasons and "cross-family prior" in reasons[0]


def test_score_delta_needs_two_observations(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    record_case(store, DIRECT, "EXECUTED", {})
    assert score_delta(hints_for(store, DIRECT)) == (0, [])


def test_shape_order_prefers_learned_and_pushes_avoided_last() -> None:
    hints = {"preferred_shapes": ["img_onerror"], "avoid_shapes": ["script_tag"]}
    ordered = order_shapes(["script_tag", "img_onerror", "attr_breakout"], hints)
    assert ordered == ["img_onerror", "attr_breakout", "script_tag"]


def test_preferred_payload_shape_respects_context() -> None:
    hints = {"preferred_shapes": ["script_tag", "attr_breakout"]}
    assert preferred_payload_shape(hints, "attr") == "attr_breakout"
    assert preferred_payload_shape(hints, "html_text") == "script_tag"
    assert preferred_payload_shape({}, "html_text") is None


def test_seed_queue_uses_cross_family_prior(tmp_path: Path) -> None:
    store = Store(tmp_path / "t.db")
    record_case(store, DIRECT, "EXECUTED", {"attempts": [{"shape": "tag", "executable": True}]})
    record_case(store, DIRECT, "EXECUTED", {"attempts": [{"shape": "tag", "executable": True}]})

    from tia.dom.main import seed_queue

    seed_queue(store, "run-a", [DIRECT], order_mode="direct")
    ids = seed_queue(store, "run-b", [SECOND], order_mode="second")
    rows = store.list_slice_rows(run_id="run-b", limit=10)
    assert ids and rows
    row = rows[0]
    reasons = row["reasons"]
    text = reasons if isinstance(reasons, str) else " ".join(reasons)
    assert "cross-family prior" in text
