"""Shared objects (wire format).

Corresponds to §2 of the Tool Interface Document. These objects serve as both the contract between agents and the input/output for MCP tools,
so they are placed in the schemas layer, without business logic.

Note: ``Occurrence`` (verify_tag hit) is currently defined in :mod:`tia.cap.verify`,
because its construction depends on the ``ContextKind`` from DOM scanning; fields match §2 of the document,
and will be moved up later if cross-tool reuse is needed, see docs/decisions.md D7.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Slice: The slice handed by the main agent to the trigger (input)
# ---------------------------------------------------------------------------


class SliceSink(BaseModel):
    model_config = ConfigDict(extra="allow")

    file: str
    line: int = Field(ge=1)
    code: str = ""


class Slice(BaseModel):
    """A "read point → sink" slice to be verified.

    ``nodes``/``edges``/``guards`` are static analysis artifacts, passed through as-is without business interpretation.
    """

    model_config = ConfigDict(extra="allow")

    kind: str
    sink: SliceSink
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    guards: list[dict[str, Any]] = Field(default_factory=list)
    guards_complete: bool = False
    #: Request parameter name associated with the sink (``params`` in the taint graph).
    params: list[str] = Field(default_factory=list)
    slice_id: str | None = None


# ---------------------------------------------------------------------------
# WriteTarget: Which line to write
# ---------------------------------------------------------------------------


class WriteTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str
    column: str | None = None
    where: dict[str, Any] = Field(default_factory=dict)
    mode: Literal["insert", "update"] = "insert"


# ---------------------------------------------------------------------------
# FlowRecord: A legal flow (replayable)
# ---------------------------------------------------------------------------


class FlowStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    method: Literal["GET", "POST"] = "GET"
    url: str
    params: dict[str, Any] = Field(default_factory=dict)
    params_order: list[str] = Field(default_factory=list)
    csrf_source: dict[str, Any] | None = None
    referer: str | None = None


class FlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_kind: Literal["form", "direct_write"] = "form"
    steps: list[FlowStep] = Field(default_factory=list)
    code_ver: str = ""


# ---------------------------------------------------------------------------
# PayloadSpec / ReadSelector
# ---------------------------------------------------------------------------


class PayloadSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    context_kind: str = "plain_text"
    out_filter: list[str] = Field(default_factory=list)
    executable_predicate: str = ""
    length_budget: int = 0
    equivalences: list[str] = Field(default_factory=list)
    forbidden: list[str] = Field(default_factory=list)


class ReadSelector(BaseModel):
    model_config = ConfigDict(extra="forbid")

    where: dict[str, Any] = Field(default_factory=dict)
    order_by: str | None = None
    limit: int = 20
    session_filter: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Change: Credential for a database write
# ---------------------------------------------------------------------------


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_id: str
    agent: str = ""
    case_id: str = ""
    table: str = ""
    op: str = ""
    affected: int = 0
    before_image: list[dict[str, Any]] = Field(default_factory=list)
    after_image: list[dict[str, Any]] = Field(default_factory=list)
    undo_sql: str = ""
    ts: str = ""


# ---------------------------------------------------------------------------
# ProbeResult: Probe return value (used after T14 implements the collector)
# ---------------------------------------------------------------------------


class ProbeTarget(BaseModel):
    model_config = ConfigDict(extra="allow")

    file: str = ""
    line: int = 0
    match: str = "line"


class ProbeQuery(BaseModel):
    model_config = ConfigDict(extra="allow")

    sql: str = ""
    bindings: list[Any] = Field(default_factory=list)
    fields: list[dict[str, Any]] = Field(default_factory=list)
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0
    matched_at: str = ""
    execute_time_ms: int = 0
    observed_at: str = ""


class ProbeHttp(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: int | None = None
    content_type: str = ""
    redirect_chain: list[dict[str, Any]] = Field(default_factory=list)
    bytes: int = 0


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    probe_id: str = ""
    mode: Literal["read", "write"] = "read"
    target: ProbeTarget = Field(default_factory=ProbeTarget)
    hit: bool = False
    queries: list[ProbeQuery] = Field(default_factory=list)
    http: ProbeHttp = Field(default_factory=ProbeHttp)


class CaseOutcome(BaseModel):
    """Main agent archival unit: The final result of a slice from trigger to inject."""

    slice_id: str
    case_id: str = ""
    verdict: str
    evidence_refs: list[str] = Field(default_factory=list)
    residue: int = 0
    notes: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
