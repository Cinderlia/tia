"""Read-side SQL predicates become plain conditions."""

from __future__ import annotations

from tia.cap.conditions import conditions_in, where_conditions


def test_equality_in_where_becomes_a_condition() -> None:
    sql = (
        "SELECT t.testimonials_id, td.testimonials_text FROM testimonials t "
        "LEFT JOIN testimonials_description td ON t.testimonials_id = td.testimonials_id "
        "WHERE t.testimonials_status = 1 ORDER BY t.date_added DESC"
    )
    found = where_conditions(sql, "testimonials")
    assert [(item.column, item.value) for item in found] == [("testimonials_status", "1")]


def test_like_and_other_tables_are_not_constraints() -> None:
    sql = "SELECT * FROM caffaine WHERE itemname LIKE '%x%' OR itemdesc LIKE '%y%'"
    assert where_conditions(sql, "caffaine") == []
    sql = "SELECT * FROM blog WHERE owner = 'admin'"
    assert where_conditions(sql, "comments") == []


def test_conditions_in_window_keep_their_location() -> None:
    text = "WHERE p.status = 0 AND p.deleted = 1"
    found = conditions_in(text, "post.php:41", "p")
    assert found == []
    found = conditions_in("SELECT * FROM posts p WHERE p.status = 0", "post.php:41", "posts")
    assert found[0].at == "post.php:41"
    assert found[0].value == "0"
