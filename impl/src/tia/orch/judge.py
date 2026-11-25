"""judge：把工具返回的事实翻成 agent 判定。

纯规则、无 IO、可单测。``verify_tag`` 只给事实（found/best/verdict_ceiling），
判定在这里做——这是 H5 的落点。
"""

from __future__ import annotations

from typing import Any

from tia.schemas.verdict import TriggerVerdict


def judge_trigger(
    *,
    verify: dict[str, Any] | None,
    written: bool,
    db_error: str | None = None,
) -> tuple[TriggerVerdict, str]:
    """触发 agent 的判定（从"payload 有没有到 sink 并执行"出发）。"""
    if db_error:
        return TriggerVerdict.SQL_ERROR, f"写库阶段失败: {db_error}"
    if not written:
        return TriggerVerdict.NOT_EXECUTED, "payload 没有写入目标表，流程未走到读点"
    if verify is None:
        return TriggerVerdict.NOT_EXECUTED, "没有 verify_tag 结果"

    if not verify.get("found"):
        return TriggerVerdict.READ_NOT_REFLECTED, "tag 已写入但页面里找不到，读路径没有回显"
    best = verify.get("best") or {}
    if best.get("executable"):
        return TriggerVerdict.EXECUTED, f"命中 {best.get('context_kind')}，可执行（{best.get('executable_reason')}）"

    reason = str(best.get("executable_reason", ""))
    if reason == "ENCODED_ONLY":
        return TriggerVerdict.REFLECTED_ENCODED, "命中被编码，无法还原为可执行标记"
    if reason in {"CSP_BLOCKED", "SANDBOXED"}:
        return TriggerVerdict.BLOCKED_CSP, f"上下文可达但被阻断: {reason}"
    if reason in {"NO_CARRIER", "NEEDS_RUNTIME", "INERT_PAYLOAD", "NEEDS_EXECUTABLE_PAYLOAD"}:
        return TriggerVerdict.REFLECTED_INERT, f"命中但上下文不可执行: {reason}"
    return TriggerVerdict.REFLECTED_INERT, f"命中但未判为可执行: {reason}"


def judge_inject(
    tag_in_db: bool, tag_in_page: bool, executable: bool
) -> tuple[str, str]:
    """三态矩阵 (库里有 / 页面有 / 可执行) → inject verdict。"""
    if not tag_in_db and not tag_in_page:
        return "WRITE_NOT_REACHED", "库里和页面上都没有 tag：写路径没走到"
    if tag_in_db and not tag_in_page:
        return "WRITTEN_NOT_VISIBLE", "写入成功但页面读不到：读选择器或会话问题"
    if tag_in_db and tag_in_page and not executable:
        return "NOT_EXECUTABLE", "写入并回显，但上下文不可执行"
    return "EXECUTABLE", "库里有、页面有、上下文可执行"
