"""A second-order sink without its own SQL still has a database identity."""

from __future__ import annotations

from types import SimpleNamespace

from tia.dom.flow_main import _columns_in_code, _read_identity_from_code


def test_columns_are_read_from_array_and_property_access() -> None:
    code = "echo nl2br($testimonials['testimonials_text']) . $row->id;"
    assert _columns_in_code(code) == ["testimonials_text", "id"]


def test_inference_picks_the_table_carrying_the_most_columns(monkeypatch) -> None:
    rows = [
        {"table_name": "testimonials_description", "column_name": "testimonials_text"},
        {"table_name": "testimonials_description", "column_name": "testimonials_id"},
        {"table_name": "testimonials", "column_name": "testimonials_id"},
        {"table_name": "customers", "column_name": "customers_name"},
    ]

    class _Mysql:
        def select(self, sql: str) -> SimpleNamespace:
            return SimpleNamespace(rows=rows)

    monkeypatch.setattr(
        "tia.dom.flow_main.get_runtime",
        lambda: SimpleNamespace(mysql=_Mysql()),
    )
    raw = {"sinkCode": "echo $testimonials['testimonials_text'];"}
    assert _read_identity_from_code(raw) == ("testimonials_description", ("testimonials_text",))


def test_inference_without_a_schema_match_stays_empty(monkeypatch) -> None:
    class _Mysql:
        def select(self, sql: str) -> SimpleNamespace:
            return SimpleNamespace(rows=[])

    monkeypatch.setattr(
        "tia.dom.flow_main.get_runtime",
        lambda: SimpleNamespace(mysql=_Mysql()),
    )
    assert _read_identity_from_code({"sinkCode": "echo $x['nothing'];"}) == ("", ())
