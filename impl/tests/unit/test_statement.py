"""Unit tests for statement origin resolution and request-carrier inference."""

from __future__ import annotations

from tia.cap.statement import request_carriers, statement_origin

SOURCE = """\
<?php
$title = "Blog";
if (isset($_POST["submit"])) {
    $entry = clean($_POST["entry"]);
    $owner = $_SESSION["login"];
    $sql = "INSERT INTO posts (title, body, owner) VALUES ('x','" . $entry . "','" . $owner . "')";
    $result = $link->query($sql);
}
$rows = $link->query("SELECT * FROM posts WHERE id = " . $_GET["id"]);
"""


def _lines() -> list[tuple[int, str]]:
    return list(enumerate(SOURCE.splitlines(), start=1))


def test_statement_origin_follows_the_assigned_variable() -> None:
    text, line = statement_origin(_lines(), 7, '$result = $link->query($sql);')

    assert line == 6
    assert "INSERT INTO posts" in text
    assert '" . $entry . "' in text


def test_statement_origin_keeps_the_call_when_nothing_is_built() -> None:
    text, line = statement_origin(_lines(), 10, '$rows = $link->query("SELECT 1");')

    assert line == 10
    assert text == '$rows = $link->query("SELECT 1");'


def test_statement_origin_accumulates_appends() -> None:
    lines = [
        (1, '$sql  = "SELECT * FROM t";'),
        (2, "$sql .= \" WHERE a = '\" . $a . \"'\";"),
        (3, "$res = $db->query($sql);"),
    ]

    text, line = statement_origin(lines, 3, "$res = $db->query($sql);")

    assert line == 1
    assert "SELECT * FROM t" in text
    assert "WHERE a = '" in text


def test_request_carriers_prefer_the_field_the_statement_consumes() -> None:
    statement = "INSERT INTO posts (body, owner) VALUES ('x', $entry, $owner)"

    carriers = request_carriers(SOURCE, statement, ["entry", "login", "submit"])

    assert carriers == ["entry"]


def test_request_carriers_follow_a_local_alias() -> None:
    source = '$body = trim($_POST["body"]);\n$sql = "UPDATE t SET b = " . $body;'
    statement = "UPDATE t SET b = $body"

    assert request_carriers(source, statement, ["body", "other"]) == ["body"]


def test_request_carriers_ignores_fields_the_statement_never_uses() -> None:
    assert request_carriers(SOURCE, "SELECT 1", ["entry", "login"]) == []
