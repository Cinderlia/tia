"""Orchestration kernel: tool invocation, evidence persistence, budget, and trace.

The agent does not directly import handlers; it only invokes tools via ``LocalToolClient`` according to the profile,
sharing the same ``registry.dispatch`` semantics as the real MCP stdio path (including G1: unregistered tools are invisible).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from tia.cap.registry import dispatch
from tia.inf.experience import ExperienceRecorder
from tia.inf.runtime import get_runtime
from tia.inf.store import now_iso
from tia.schemas.envelope import Envelope, ErrorCode

#: Tool → evidence type (the kind segment of evidence_ref).
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

#: Tools that do not consume budget (§1.6 main agent budget scope, also applies to trigger/inject).
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
    slice_id: str | None = None
    _recorder: ExperienceRecorder | None = None

    async def call(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        *,
        strict: bool = True,
    ) -> Any:
        """Invoke a tool once; returns data on success, raises :class:`ToolCallError` on failure (in strict mode)."""
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
            self._record_call(tool, args, envelope)
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
        self._record_call(tool, args, envelope)
        return envelope.data

    def _record_call(self, tool: str, args: dict[str, Any], envelope: Envelope) -> None:
        """Persist arguments + a short gist; the raw return goes to a file, not to agents."""
        if not self.case_id:
            return
        try:
            if self._recorder is None:
                self._recorder = ExperienceRecorder(get_runtime().store)
            error = envelope.error.model_dump() if envelope.error else None
            self._recorder.record(
                case_id=self.case_id,
                slice_id=self.slice_id,
                agent=self.profile,
                tool=tool,
                arguments=args,
                ok=envelope.ok,
                cost_ms=envelope.cost_ms,
                data=envelope.data,
                error=error,
            )
        except Exception:  # noqa: BLE001 - tracing must never break a case
            return

    # -- Evidence -------------------------------------------------------------

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
        message=f"Tool call budget {budget} exhausted",
        retryable=False,
        hint="Dispatch the next step directly, or skip this slice",
    )


def _compact(data: Any, limit: int = 8192) -> Any:
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return data
    return {"_truncated": True, "preview": text[:limit]}
