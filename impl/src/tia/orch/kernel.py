"""编排内核：工具调用、证据落库、预算与 trace。

agent 不直接 import handler；它只通过 ``LocalToolClient`` 按 profile 调用工具，
与真实 MCP stdio 路径共用同一套 ``registry.dispatch`` 语义（含 G1 不注册即不可见）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from tia.cap.registry import dispatch
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import Envelope, ErrorCode

#: 工具 → 证据种类（evidence_ref 的 kind 段）。
EVIDENCE_KIND = {
    "source_read": "source",
    "source_grep": "source",
    "taint_trace": "source",
    "form_parse": "source",
    "endpoint_search": "source",
    "includer_trace": "source",
    "filter_analyze": "source",
    "db_schema": "db",
    "db_read": "db",
    "db_write": "change",
    "db_undo": "db",
    "probe_arm": "probe",
    "probe_run": "probe",
    "probe_disarm": "probe",
    "write_probe": "probe",
    "http_request": "http",
    "form_fill": "http",
    "http_replay": "http",
    "verify_tag": "verify",
    "context_classify": "verify",
    "canary_calibrate": "verify",
    "budget_solve": "verify",
    "trace_run": "trace",
    "trace_diff": "trace",
    "guard_harvest": "trace",
}

#: 不占预算的工具（§1.6 主 agent 预算口径，对 trigger/inject 同样适用）。
UNCOUNTED = frozenset({"case_open", "case_note", "case_report", "slice_next", "slice_archive",
                       "slice_skip", "human_ask", "artifact_save"})


class ToolCallError(RuntimeError):
    def __init__(self, tool: str, envelope: Envelope) -> None:
        error = envelope.error
        self.tool = tool
        self.envelope = envelope
        self.code = error.code if error else ErrorCode.ENV_ERROR
        self.message = error.message if error else "unknown error"
        super().__init__(f"{tool}: {self.code.value}: {self.message}")


class ToolClient(Protocol):
    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope: ...


@dataclass(slots=True)
class LocalToolClient:
    profile: str

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> Envelope:
        return await dispatch(self.profile, tool, arguments)


@dataclass(slots=True)
class StepRecord:
    tool: str
    ok: bool
    cost_ms: int
    evidence_ref: str | None = None
    error: str | None = None
    observed_at: str = ""


@dataclass(slots=True)
class Kernel:
    profile: str
    case_id: str | None = None
    budget: int = 40
    client: ToolClient = field(default_factory=lambda: LocalToolClient(profile="trigger"))
    trace: list[StepRecord] = field(default_factory=list)
    used: int = 0

    async def call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        strict: bool = True,
    ) -> Any:
        """调用一次工具；成功返回 data，失败抛 :class:`ToolCallError`（strict 时）。"""
        args = dict(arguments or {})
        if self.case_id and "case_id" not in args and tool in {"db_read", "db_write", "db_undo"}:
            args["case_id"] = self.case_id
        if tool not in UNCOUNTED:
            if self.used >= self.budget:
                raise ToolCallError(
                    tool,
                    Envelope.failure(
                        tool=tool,
                        profile=self.profile,
                        error=_budget_error(self.budget),
                        cost_ms=0,
                    ),
                )
            self.used += 1

        envelope = await self.client.call(tool, args)
        if not envelope.ok:
            self.trace.append(
                StepRecord(
                    tool=tool,
                    ok=False,
                    cost_ms=envelope.cost_ms,
                    error=envelope.error.model_dump_json() if envelope.error else None,
                    observed_at=now_iso(),
                )
            )
            if strict:
                raise ToolCallError(tool, envelope)
            return None

        ref: str | None
        if envelope.evidence_refs:
            ref = envelope.evidence_refs[0]
        else:
            ref = self._record(tool, envelope.data)
        self.trace.append(
            StepRecord(tool=tool, ok=True, cost_ms=envelope.cost_ms, evidence_ref=ref,
                       observed_at=now_iso())
        )
        return envelope.data

    # -- 证据 -------------------------------------------------------------

    def _record(self, tool: str, data: Any) -> str | None:
        if not self.case_id:
            return None
        kind = EVIDENCE_KIND.get(tool)
        if kind is None:
            return None
        return get_runtime().store.add_evidence(self.case_id, kind, tool, _compact(data))

    def record_evidence(self, kind: str, tool: str, payload: Any) -> str | None:
        if not self.case_id:
            return None
        return get_runtime().store.add_evidence(self.case_id, kind, tool, _compact(payload))

    def set_write_targets(self, targets: list[dict[str, Any]]) -> None:
        if not self.case_id:
            return
        get_runtime().store.set_write_targets(self.case_id, targets)

    async def report(self) -> str:
        data = await self.call("case_report", {"case_id": self.case_id or ""})
        return str(data.get("markdown", "")) if isinstance(data, dict) else ""


def _budget_error(budget: int) -> Any:
    from tia.schemas.envelope import ErrorBody

    return ErrorBody(
        code=ErrorCode.BUDGET_EXCEEDED,
        message=f"工具调用预算 {budget} 已用尽",
        retryable=False,
        hint="直接分派下一步，或跳过该切片",
    )


def _compact(data: Any, limit: int = 8192) -> Any:
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return data
    return {"_truncated": True, "preview": text[:limit]}
