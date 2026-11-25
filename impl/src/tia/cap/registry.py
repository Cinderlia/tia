"""工具注册表：唯一的事实来源是设计文档《工具接口文档》。

两个职责：
1. 声明 36 个工具的元信息与 schema（``TOOLS``）；
2. 按 profile 过滤并把 handler 的返回/异常统一成信封（``dispatch``）。

handler 只写 ``tia.cap.*`` / ``tia.ad.*``，通过点分路径延迟加载，
避免注册表反向依赖能力实现（也避免 import 环）。
"""

from __future__ import annotations

import importlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from tia.schemas.envelope import Envelope, ErrorBody, ErrorCode, JsonValue, ToolError

PROFILES = ("main", "trigger", "inject")

#: main profile 不注册的 22 个工具（G1：不注册即不可用）。
MAIN_EXCLUDED: frozenset[str] = frozenset(
    {
        "probe_arm",
        "probe_run",
        "probe_disarm",
        "write_probe",
        "http_request",
        "http_replay",
        "form_fill",
        "verify_tag",
        "context_classify",
        "canary_calibrate",
        "budget_solve",
        "db_write",
        "db_undo",
        "trace_run",
        "trace_diff",
        "guard_harvest",
        "session_bind",
        "rate_guard",
        "includer_trace",
        "taint_trace",
        "case_open",
        "case_note",
    }
)

#: handler 的返回：data + 证据引用 + 警告。信封由 registry 统一包装。
Handler = Callable[[dict[str, Any]], Awaitable["ToolOutput"]]


@dataclass(slots=True)
class ToolOutput:
    data: JsonValue
    evidence_refs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    category: str
    mutating: bool = False
    #: JSON Schema（MCP tools/list 原样下发）。详细约束随各工具实现收紧。
    input_schema: dict[str, Any] = field(default_factory=lambda: {"type": "object"})
    #: 形如 ``tia.cap.verify:verify_tag``；None 表示尚未实现。
    handler_path: str | None = None


_SCHEMA = {"type": "object", "additionalProperties": True}


def _t(
    name: str,
    description: str,
    category: str,
    *,
    mutating: bool = False,
    handler_path: str | None = None,
    input_schema: dict[str, Any] | None = None,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        category=category,
        mutating=mutating,
        handler_path=handler_path,
        input_schema=input_schema or _SCHEMA,
    )


_VERIFY_TAG_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "在线页面 URL（与 html 二选一）"},
        "html": {"type": "string", "description": "离线 HTML（与 url 二选一）"},
        "tag": {"type": "string", "description": "4 字符 tag"},
    },
    "required": ["tag"],
    "additionalProperties": False,
}

#: 36 个工具，顺序与《工具接口文档》一致。
TOOLS: tuple[ToolSpec, ...] = (
    # 1. 源码与入口（7）
    _t("source_read", "读取源码片段（带上下文行号）", "source", handler_path="tia.cap.source:source_read"),
    _t("source_grep", "按正则搜索源码，返回命中位置与一行上下文", "source", handler_path="tia.cap.source:source_grep"),
    _t("taint_trace", "从 sink 回溯到请求变量的赋值链（有界）", "source"),
    _t("form_parse", "解析页面或源码中的表单字段与 HTML5 约束", "source"),
    _t("endpoint_search", "按 sink 文件搜索可达的 HTTP 入口", "source"),
    _t("includer_trace", "追踪 include/require 链", "source"),
    _t("filter_analyze", "分析输入/输出侧的过滤与编码", "source"),
    # 2. 数据与探针（8）
    _t("db_schema", "读取库表结构", "data", handler_path="tia.cap.db:db_schema"),
    _t("db_read", "只读 SQL 查询，返回行与列元信息", "data", handler_path="tia.cap.db:db_read"),
    _t("db_write", "写库（必须返回 change_id 与 undo_sql）", "data", mutating=True, handler_path="tia.cap.db:db_write"),
    _t("db_undo", "回滚自己的写入，必须 residue==0", "data", mutating=True, handler_path="tia.cap.db:db_undo"),
    _t("probe_arm", "在读点/写点挂采集探针", "probe", mutating=True),
    _t("probe_run", "运行探针请求并取回命中的 SQL 与绑定参数", "probe", mutating=True),
    _t("probe_disarm", "摘除探针", "probe", mutating=True),
    _t("write_probe", "对目标表做 before/after 差分", "probe", mutating=True),
    # 3. 投递与验收（7）
    _t("http_request", "发起单次 HTTP 请求（显式 Cookie，不跟随重定向）", "http", handler_path="tia.cap.http:http_request"),
    _t("form_fill", "按表单模板填充并生成请求链", "http", mutating=True, handler_path="tia.cap.http:form_fill"),
    _t("http_replay", "在指定会话下重放请求链", "http", mutating=True),
    _t("verify_tag",
       "在页面/HTML 中定位 tag，返回出现位置、上下文与可执行性上限",
       "verify",
       handler_path="tia.cap.verify:verify_tag",
       input_schema=_VERIFY_TAG_SCHEMA),
    _t("context_classify", "把命中上下文归类为 8 类之一", "verify"),
    _t("canary_calibrate", "用 canary 实测写/读变换 F=O(W(x))", "verify", mutating=True),
    _t("budget_solve", "求解可写长度预算与候选骨架", "verify"),
    # 4. 轨迹（3）
    _t("trace_run", "带 filter 的定向 trace（禁止全量）", "trace", mutating=True),
    _t("trace_diff", "比较两次 trace 的分支差异", "trace"),
    _t("guard_harvest", "从入口文件收割拒绝点候选", "trace"),
    # 5. 控制与人机（8）
    _t("case_open", "建立 case", "control", mutating=True, handler_path="tia.cap.case:case_open"),
    _t("case_note", "给 case 追加证据笔记", "control", mutating=True, handler_path="tia.cap.case:case_note"),
    _t("case_report", "生成 case 的 Markdown 报告", "control", handler_path="tia.cap.case:case_report"),
    _t("session_bind", "绑定合法登录态到 case", "control", mutating=True),
    _t("human_ask", "向人类提问（登录、授权、二选一）", "control"),
    _t("artifact_save", "保存产物到项目目录", "control"),
    _t("flow_lookup", "查询流程库中的 form 模板与已知 guard", "control"),
    _t("rate_guard", "限流退避", "control", mutating=True),
    # 6. 切片（3）
    _t("slice_next", "取下一个待处理切片", "slice"),
    _t("slice_archive", "归档切片结果", "slice", mutating=True),
    _t("slice_skip", "跳过切片并记录原因", "slice", mutating=True),
)

_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOLS}
if len(_BY_NAME) != 36:  # pragma: no cover - 设计不变量
    raise RuntimeError(f"工具数量应为 36，实际 {len(_BY_NAME)}")


def tools_for_profile(profile: str) -> tuple[ToolSpec, ...]:
    """按 profile 返回可下发的工具；未知 profile 直接拒绝。"""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    if profile == "main":
        return tuple(spec for spec in TOOLS if spec.name not in MAIN_EXCLUDED)
    return TOOLS


def tool_names(profile: str) -> tuple[str, ...]:
    return tuple(spec.name for spec in tools_for_profile(profile))


_handler_cache: dict[str, Handler] = {}


def _load_handler(path: str) -> Handler:
    cached = _handler_cache.get(path)
    if cached is not None:
        return cached
    module_name, _, attr = path.partition(":")
    module = importlib.import_module(module_name)
    handler: object = getattr(module, attr)
    if not callable(handler):
        raise RuntimeError(f"handler not callable: {path}")
    loaded = handler
    _handler_cache[path] = loaded
    return loaded


def _failure(
    profile: str, name: str, error: ErrorBody, cost_ms: int
) -> Envelope:
    return Envelope.failure(tool=name, profile=profile, error=error, cost_ms=cost_ms)


async def dispatch(
    profile: str,
    name: str,
    arguments: dict[str, Any] | None,
) -> Envelope:
    """执行一次工具调用；任何失败都收敛为信封（H9）。"""
    started = time.perf_counter()
    spec = _BY_NAME.get(name)
    if spec is None or spec.name not in {s.name for s in tools_for_profile(profile)}:
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.NOT_FOUND,
                message=f"tool {name!r} is not available in profile {profile!r}",
                hint="检查工具名，或确认该工具是否在当前 profile 注册",
            ),
            _elapsed_ms(started),
        )
    if spec.handler_path is None:
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.UNSUPPORTED,
                message=f"tool {name!r} 尚未实现",
                retryable=False,
                hint="见 tia-design-kit/TASKS.md 的实现顺序",
            ),
            _elapsed_ms(started),
        )

    handler = _load_handler(spec.handler_path)
    try:
        output = await handler(arguments or {})
    except ToolError as exc:
        return _failure(profile, name, exc.to_body(), _elapsed_ms(started))
    except Exception as exc:  # noqa: BLE001 - 边界：协议要求不抛
        return _failure(
            profile,
            name,
            ErrorBody(
                code=ErrorCode.ENV_ERROR,
                message=f"{type(exc).__name__}: {exc}",
                retryable=True,
                hint="这是未预期异常，查看 server stderr 日志",
            ),
            _elapsed_ms(started),
        )

    return Envelope.success(
        tool=name,
        profile=profile,
        data=output.data,
        evidence_refs=output.evidence_refs,
        warnings=output.warnings,
        cost_ms=_elapsed_ms(started),
    )


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
