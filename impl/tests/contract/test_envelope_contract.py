"""契约层：每个 profile 下每个工具都必须回统一信封。

这一层不关心工具做什么，只钉住《工具接口文档》§1 的字段与错误码闭集：
无论成功、参数错、还是 profile 不可见，调用方拿到的形状都一样（H9）。
"""

from __future__ import annotations

import pytest

from tia.cap import registry
from tia.schemas.envelope import Envelope, ErrorCode

ENVELOPE_KEYS = {
    "ok",
    "tool",
    "data",
    "evidence_refs",
    "cost_ms",
    "profile",
    "warnings",
    "error",
}


def _all_cases() -> list[tuple[str, str]]:
    return [
        (profile, name)
        for profile in registry.PROFILES
        for name in registry.tool_names(profile)
    ]


@pytest.mark.parametrize(("profile", "name"), _all_cases())
async def test_every_tool_returns_envelope(profile: str, name: str) -> None:
    envelope = await registry.dispatch(profile, name, {})
    assert isinstance(envelope, Envelope)
    assert set(envelope.model_dump(mode="json")) == ENVELOPE_KEYS
    assert envelope.tool == name
    assert envelope.profile == profile
    assert envelope.cost_ms >= 0
    assert isinstance(envelope.warnings, list)


@pytest.mark.parametrize(("profile", "name"), _all_cases())
async def test_failure_uses_closed_error_codes(profile: str, name: str) -> None:
    envelope = await registry.dispatch(profile, name, {})
    if envelope.ok:
        assert envelope.error is None
        return
    assert envelope.error is not None
    assert envelope.error.code in set(ErrorCode)
    assert envelope.error.message
    assert envelope.data is None


@pytest.mark.parametrize("name", sorted(registry.MAIN_EXCLUDED))
async def test_main_excluded_tools_are_not_found(name: str) -> None:
    envelope = await registry.dispatch("main", name, {})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.NOT_FOUND


@pytest.mark.parametrize("name", ["", "None", "VERIFY_TAG", "verify-tag"])
async def test_unknown_names_are_not_found(name: str) -> None:
    envelope = await registry.dispatch("trigger", name, {})
    assert envelope.ok is False
    assert envelope.error is not None
    assert envelope.error.code is ErrorCode.NOT_FOUND
