from tia.cap.domscan import echo_snapshot


def test_layout_wrappers_are_dropped() -> None:
    html = "<a><b>noise</b><c><d>payload(dssp) here</d></c></a>"
    snapshot = echo_snapshot(html, "dssp")
    assert "payload(dssp)" in snapshot
    assert "noise" not in snapshot


def test_script_wrapper_is_kept() -> None:
    snapshot = echo_snapshot("<script>var x = 'dssp';</script>", "dssp")
    assert snapshot.startswith("<script>")
    assert "closing sequence" in snapshot


def test_textarea_and_style_are_kept() -> None:
    assert echo_snapshot("<textarea>dssp</textarea>", "dssp").startswith("<textarea>")
    assert echo_snapshot("<style>a{content:'dssp'}</style>", "dssp").startswith("<style>")


def test_attribute_keeps_only_the_payload_attribute() -> None:
    html = '<div class="x"><input value="prefix-dssp" name="q" onclick="go()"></div>'
    snapshot = echo_snapshot(html, "dssp")
    assert snapshot == '<input value="prefix-dssp">'


def test_comment_is_reported_as_a_comment() -> None:
    snapshot = echo_snapshot("<div><!-- dssp --></div>", "dssp")
    assert snapshot.startswith("<!--")
    assert snapshot.endswith("-->")


def test_unknown_wrapper_is_kept() -> None:
    snapshot = echo_snapshot("<custom-box><span>dssp</span></custom-box>", "dssp")
    assert "<custom-box>" in snapshot
    assert "<span>" not in snapshot


def test_missing_tag_returns_empty() -> None:
    assert echo_snapshot("<p>nothing</p>", "dssp") == ""
