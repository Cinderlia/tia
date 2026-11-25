"""共享对象（wire format）。

对应《工具接口文档》§2。这些对象同时是 agent 之间的契约与 MCP 工具的输入输出，
因此放在 schemas 层，不放业务判断。

说明：``Occurrence``（verify_tag 命中项）当前定义在 :mod:`tia.cap.verify`，
因为它的构造依赖 DOM 扫描的 ``ContextKind``；字段与文档 §2 一致，
后续若需要跨工具复用再上移，见 docs/decisions.md D7。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Slice：主 agent 交给 trigger 的切片（输入）
# ---------------------------------------------------------------------------


class SliceSink(BaseModel):
    model_config = ConfigDict(extra="allow")

    file: str
    line: int = Field(ge=1)
    code: str = ""


class Slice(BaseModel):
    """一个待验证的"读点 → sink"切片。

    ``nodes``/``edges``/``guards`` 是静态分析产物，原样透传，不做业务解释。
    """

    model_config = ConfigDict(extra="allow")

    kind: str
    sink: SliceSink
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    guards: list[dict[str, Any]] = Field(default_factory=list)
    guards_complete: bool = False
    #: sink 关联的请求参数名（taint 图的 ``params``）。
    params: list[str] = Field(default_factory=list)
    slice_id: str | None = None


# ---------------------------------------------------------------------------
# WriteTarget：写哪一行
# ---------------------------------------------------------------------------


class WriteTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: str
    column: str | None = None
    where: dict[str, Any] = Field(default_factory=dict)
    mode: Literal["insert", "update"] = "insert"


# ---------------------------------------------------------------------------
# FlowRecord：一次合法流程（可重放）
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
# Change：一次写库的凭据
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
# ProbeResult：探针返回（T14 实现采集器后使用）
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
