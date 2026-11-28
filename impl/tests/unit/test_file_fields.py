"""Uploaded parts: a filename is enough, or the model can ship real bytes."""

from __future__ import annotations

import base64

import pytest

from tia.cap.http import MAX_UPLOAD_BYTES, _file_fields
from tia.schemas.envelope import ToolError


def test_filename_only_uses_a_small_valid_upload() -> None:
    parts = _file_fields({"image": "tia-upload.png"})
    assert parts is not None
    filename, content, content_type = parts["image"]
    assert filename == "tia-upload.png"
    assert content == b"tia-upload"
    assert content_type == "application/octet-stream"


def test_full_spec_decodes_the_payload_bytes() -> None:
    payload = b"<script>alert(1)</script>ab12"
    parts = _file_fields(
        {
            "image": {
                "filename": "tia.html",
                "content_base64": base64.b64encode(payload).decode(),
                "content_type": "text/html",
            }
        }
    )
    assert parts is not None
    filename, content, content_type = parts["image"]
    assert (filename, content, content_type) == ("tia.html", payload, "text/html")


def test_invalid_base64_is_rejected() -> None:
    with pytest.raises(ToolError):
        _file_fields({"image": {"filename": "tia.png", "content_base64": "!!"}})


def test_oversized_upload_is_rejected() -> None:
    big = base64.b64encode(b"x" * (MAX_UPLOAD_BYTES + 1)).decode()
    with pytest.raises(ToolError):
        _file_fields({"image": {"filename": "tia.png", "content_base64": big}})


def test_unsafe_filename_is_rejected() -> None:
    with pytest.raises(ToolError):
        _file_fields({"image": "../tia.php"})
