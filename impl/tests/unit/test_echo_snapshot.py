from tia.cap.domscan import echo_snapshot


def test_text_keeps_only_the_wrapping_chain() -> None:
    html = "<a><b>noise</b><c><d>payload(dssp) here</d></c></a>"
    snapshot = echo_snapshot(html, "dssp")
    assert "payload(dssp)" in snapshot
    assert "noise" not in snapshot
    assert snapshot.startswith("<a><c><d>")
    assert snapshot.endswith("</d></c></a>")


def test_attribute_value_keeps_the_quote() -> None:
    html = '<div class="x"><input value="prefix-dssp" name="q"></div>'
    snapshot = echo_snapshot(html, "dssp")
    assert snapshot.startswith("<input")
    assert 'value="prefix-dssp"' in snapshot


def test_comment_is_reported_as_a_comment() -> None:
    snapshot = echo_snapshot("<div><!-- dssp --></div>", "dssp")
    assert snapshot.startswith("<!--")
    assert snapshot.endswith("-->")


def test_script_body_keeps_the_script_tag() -> None:
    snapshot = echo_snapshot("<script>var x = 'dssp';</script>", "dssp")
    assert "<script>" in snapshot
    assert "closing sequence" in snapshot


def test_missing_tag_returns_empty() -> None:
    assert echo_snapshot("<p>nothing</p>", "dssp") == ""
