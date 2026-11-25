"""`verify_tag` handler layer: parameter errors must return a BAD_ARGS envelope, while the main profile remains invisible."""

from __future__ import annotations

import pytest

from tia.cap import registry
from tia.cap.verify import verify_tag
from tia.schemas.envelope import ErrorCode, ToolError


async def test_offline_call_returns_envelope_data() -> None:
    output = await verify_tag({"html": "<p>a1b2</p>", "tag": "a1b2"})
    data = output.data
    assert isinstance(data, dict)
    assert data["found"] is True
    assert data["occurrence_count"] == 1
    assert data["verdict_ceiling"] == "EXECUTABLE"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"tag": "a1b2"},
        {"html": "<p>a1b2</p>", "tag": "a1b2", "url": "http://example.com/"},
        {"html": "<p>a1b2</p>", "tag": "a b"},
        {"html": "<p>a1b2</p>", "tag": ""},
        {"html": "<p>a1b2</p>", "tag": "a1b2", "max_occurrences": 0},
    ],
)
async def test_bad_arguments(arguments: dict[str, object]) -> None:
    with pytest.raises(ToolError) as excinfo:
        await verify_tag(arguments)
    assert excinfo.value.code is ErrorCode.BAD_ARGS


async def test_registry_wraps_verify_tag_success() -> None:
    envelope = await registry.dispatch("trigger", "verify_tag", {"html": "<p>a1b2</p>", "tag": "a1b2"})
    assert envelope.ok is True
    assert envelope.tool == "verify_tag"
    assert envelope.profile == "trigger"
    assert envelope.cost_ms >= 0


async def test_registry_wraps_bad_args_as_failure_envelope() -> None:
    envelope = await registry.dispatch("trigger", "verify_tag", {"tag": "a1b2"})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.BAD_ARGS
    assert envelope.error.retryable is False


async def test_main_profile_cannot_call_verify_tag() -> None:
    envelope = await registry.dispatch("main", "verify_tag", {"html": "<p>a1b2</p>", "tag": "a1b2"})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.NOT_FOUND
