"""Query handling for requests whose URL already carries action parameters."""

from __future__ import annotations

from tia.ad.http import merge_query


def test_merge_keeps_the_action_in_the_url() -> None:
    url = "http://127.0.0.1/admin/testimonials.php?action=set_flag"
    merged = merge_query(url, {"flag": "1", "tID": 28})
    assert merged == (
        "http://127.0.0.1/admin/testimonials.php?action=set_flag&flag=1&tID=28"
    )


def test_merge_overrides_the_same_parameter_once() -> None:
    url = "http://127.0.0.1/list.php?page=1&sort=name"
    merged = merge_query(url, {"page": 3})
    assert merged == "http://127.0.0.1/list.php?sort=name&page=3"


def test_merge_without_parameters_returns_the_url() -> None:
    url = "http://127.0.0.1/list.php?page=1"
    assert merge_query(url, None) == url
    assert merge_query(url, {}) == url
