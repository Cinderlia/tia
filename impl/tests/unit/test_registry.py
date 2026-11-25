"""注册表不变量：工具数量、profile 过滤、dispatch 的错误收敛。"""

from __future__ import annotations

import pytest

from tia.cap import registry
from tia.schemas.envelope import Envelope, ErrorCode


def test_has_36_unique_tools() -> None:
    names = [spec.name for spec in registry.TOOLS]
    assert len(names) == 36
    assert len(set(names)) == 36
    assert tuple(names) == registry.tool_names("trigger")


def test_main_profile_hides_exactly_22_tools() -> None:
    visible = registry.tool_names("main")
    all_names = registry.tool_names("trigger")
    assert len(visible) == 14
    assert len(registry.MAIN_EXCLUDED) == 22
    assert set(visible) == set(all_names) - registry.MAIN_EXCLUDED
    assert "verify_tag" not in visible
    assert "db_write" not in visible


@pytest.mark.parametrize("profile", ["trigger", "inject"])
def test_trigger_and_inject_see_all_tools(profile: str) -> None:
    assert len(registry.tool_names(profile)) == 36


def test_unknown_profile_rejected() -> None:
    with pytest.raises(ValueError):
        registry.tools_for_profile("admin")


async def test_unknown_tool_returns_not_found() -> None:
    envelope = await registry.dispatch("trigger", "no_such_tool", {})
    assert isinstance(envelope, Envelope)
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.NOT_FOUND
    assert envelope.tool == "no_such_tool"


async def test_main_profile_tool_is_not_found_even_if_known() -> None:
    envelope = await registry.dispatch("main", "verify_tag", {"tag": "abcd"})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.NOT_FOUND


async def test_unimplemented_tool_returns_unsupported() -> None:
    envelope = await registry.dispatch("trigger", "source_read", {"path": "home.php"})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.UNSUPPORTED


async def test_dispatch_envelope_is_json_serializable() -> None:
    envelope = await registry.dispatch("trigger", "source_read", {})
    payload = envelope.model_dump_json()
    assert '"ok":false' in payload
    assert '"code":"UNSUPPORTED"' in payload
