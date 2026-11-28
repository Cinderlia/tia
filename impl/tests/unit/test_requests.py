"""Tests for request-shape discovery (forms, links, scripts and source hints)."""

from __future__ import annotations

from tia.cap.requests import (
    NonceSource,
    endpoints_from_html,
    endpoints_from_source,
    extract_token,
    merge_nonce_values,
)


def test_reads_a_hidden_token_whatever_the_attribute_order() -> None:
    html = (
        '<form method="post" action="/save.php">'
        '<input type="hidden" name="_wpnonce" value="abc123">'
        '<input value="other" name="token" type="hidden">'
        "</form>"
    )
    assert extract_token(html, NonceSource(name="_wpnonce")) == "abc123"
    assert extract_token(html, NonceSource(name="token")) == "other"


def test_reads_a_token_from_an_inline_script() -> None:
    html = '<script>var pd_ajax = {"nonce":"n-42","url":"/x.php"};</script>'
    assert extract_token(html, NonceSource(kind="js_var", name="nonce")) == "n-42"


def test_collects_query_links_as_get_templates() -> None:
    html = (
        '<a href="/post.php?id=7">one</a>'
        '<a href="/post.php?id=8">two</a>'
        '<a href="/style.css">asset</a>'
        '<a href="https://other.example/x.php?id=1">offsite</a>'
    )
    templates = endpoints_from_html(html, "http://app.test/index.php")
    gets = [item for item in templates if item.method == "GET"]
    assert len(gets) == 1, gets
    assert gets[0].names == {"id"}
    assert gets[0].url.endswith("/post.php?id=7")


def test_collects_a_script_post_with_its_object_keys() -> None:
    html = (
        "<script>$.post('/ajax/duplicate.php', {post_id: 1, title: 'x'}, done);</script>"
    )
    templates = endpoints_from_html(html, "http://app.test/wp-admin/edit.php")
    posts = [item for item in templates if item.origin == "script"]
    assert posts and posts[0].method == "POST"
    assert set(posts[0].fields) == {"post_id", "title"}


def test_source_actions_map_to_the_wordpress_ajax_router() -> None:
    source = (
        "$(document).on('click', function(){ $.post(ajaxurl, {action: 'mtphr_duplicate'}); });"
        "if (isset($_GET['action'])) { }"
    )
    templates = endpoints_from_source(
        source,
        "http://app.test/wp-admin/admin.php?page=post-duplicator",
        base_url="http://app.test/wp-admin/admin.php?page=post-duplicator",
    )
    actions = [item for item in templates if "action=" in item.url]
    assert actions, templates
    assert any("wp-admin/admin-ajax.php" in item.url for item in actions)


def test_nonce_sources_are_attached_to_forms_and_merged_into_values() -> None:
    html = (
        '<form method="post" action="/save.php">'
        '<input type="hidden" name="csrf_token" value="t-1">'
        '<input name="title">'
        "</form>"
    )
    template = endpoints_from_html(html, "http://app.test/settings.php")[0]
    assert [item.name for item in template.nonces] == ["csrf_token"]
    values = merge_nonce_values(template, {"csrf_token": "t-1"})
    assert values["csrf_token"] == "t-1"
