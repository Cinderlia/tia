"""`verify_tag`：唯一验收口径。

只回事实，不下结论（H5）：

* tag 是否出现、出现在哪些上下文；
* 每个命中的 ``executable`` 是保守估计，理由写在 ``executable_reason``；
* ``verdict_ceiling`` 恒为 ``EXECUTABLE``——要拿 ``EXECUTED`` 需要浏览器证据。

离线（``html=``）与在线（``url=``）走同一个判定函数，保证可复现（规范 §9）。
判据以《验收判定规范》为准，版本见 ``RULE_VERSION``。
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from tia.cap import domscan
from tia.cap.registry import ToolOutput
from tia.schemas.envelope import ErrorCode, ToolError

RULE_VERSION = "1.0"
MAX_OCCURRENCES_LIMIT = 200
DEFAULT_MAX_OCCURRENCES = 10
HTTP_TIMEOUT_SECONDS = 30.0

#: context_kind 排序优先级（验收规范 §3.2）。
CONTEXT_PRIORITY: dict[str, int] = {
    "script_block": 0,
    "attr": 1,
    "html_text": 2,
    "script_string": 3,
    "json": 4,
    "comment": 5,
    "plain_text": 6,
    "textarea": 7,
}

_EXECUTABLE_CONSTRUCT = re.compile(
    r"""(?is)
    <\s*script\b
    | <\s*(?:svg|math|marquee)\b[^>]*\bon[a-z]+\s*=
    | <\s*(?:img|body|input|details|video|audio|source)\b[^>]*\bon[a-z]+\s*=
    | <\s*iframe\b[^>]*\bsrcdoc\s*=
    | (?:href|src|action|formaction)\s*=\s*["']?\s*javascript:
    """,
    re.VERBOSE,
)

_EVENT_ATTR_INJECT = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)

_DOWNSTREAM_WRITE = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.html\(|eval\s*\(|"
    r"setTimeout\s*\(\s*['\"]",
    re.IGNORECASE,
)


class ContextKind(StrEnum):
    COMMENT = "comment"
    TEXTAREA = "textarea"
    PLAIN_TEXT = "plain_text"
    SCRIPT_STRING = "script_string"
    SCRIPT_BLOCK = "script_block"
    ATTR = "attr"
    JSON = "json"
    HTML_TEXT = "html_text"


class UpwalkOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stop_at: list[str] = Field(default_factory=lambda: ["script", "img", "a", "form"])
    max_depth: int = Field(default=5, ge=1, le=20)


class VerifyTagInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    html: str | None = None
    params: dict[str, str] = Field(default_factory=dict)
    session_id: str | None = None
    tag: str
    #: 可选：完整 payload。给了才能判"闭合/承载"这类需要看注入内容的问题；
    #: 只给 4 字符 tag 时按保守解判（见 _judge_executable）。
    payload: str | None = None
    max_occurrences: int = Field(default=DEFAULT_MAX_OCCURRENCES, ge=1, le=MAX_OCCURRENCES_LIMIT)
    upwalk: UpwalkOptions = Field(default_factory=UpwalkOptions)
    #: 离线模式的响应元信息；在线模式由 HTTP 响应填充。
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    status: int | None = None

    @model_validator(mode="after")
    def _check_source(self) -> VerifyTagInput:
        if (self.url is None) == (self.html is None):
            raise ValueError("url 与 html 必须二选一")
        if not self.tag or len(self.tag) > 64 or any(char.isspace() for char in self.tag):
            raise ValueError("tag 必须是 1..64 个非空白字符")
        if self.url is not None and not self.url.startswith(("http://", "https://")):
            raise ValueError("url 目前只接受绝对 http(s) 地址")
        return self


class Occurrence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    form: Literal["html", "header", "url"] = "html"
    node_path: str | None = None
    context_kind: ContextKind
    quoting: Literal["double", "single", "none"] = "none"
    match_kind: Literal["literal"] = "literal"
    executable: bool
    executable_reason: str
    downstream_write: bool = False
    confidence: Literal["high", "medium", "low"]
    chain_html: str = ""
    chain_truncated: bool = False
    dom_ancestors: list[str] = Field(default_factory=list)
    offset: int = -1


class VerifyTagResult(BaseModel):
    found: bool
    occurrence_count: int
    encoded_count: int
    occurrences: list[Occurrence] = Field(default_factory=list)
    best: Occurrence | None = None
    verdict_ceiling: Literal["EXECUTABLE"] = "EXECUTABLE"
    rule_version: str = RULE_VERSION
    sha256: str
    observed_at: str
    content_type: str = "text/html"
    status: int | None = None
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 命中扫描
# ---------------------------------------------------------------------------


def _encoded_pattern(tag: str) -> re.Pattern[str]:
    """为 tag 生成"字符级可还原编码"的匹配式（规范 §3.1 的四类变换）。"""
    parts: list[str] = []
    for char in tag:
        code = ord(char)
        alternatives = [re.escape(char)]
        if char.isalnum():
            dec = f"&#0*{code};"
            hex_lower = f"&#[xX]0*{code:x};"
            hex_upper = f"&#[xX]0*{code:X};"
            js_hex = rf"\\x0*{code:x}"
            js_hex_upper = rf"\\x0*{code:X}"
            js_unicode = rf"\\u0*{code:x}"
            js_unicode_upper = rf"\\u0*{code:X}"
            url_code = f"%{code:02x}"
            url_code_upper = f"%{code:02X}"
            alternatives.extend(
                [
                    dec,
                    hex_lower,
                    hex_upper,
                    js_hex,
                    js_hex_upper,
                    js_unicode,
                    js_unicode_upper,
                    url_code,
                    url_code_upper,
                ]
            )
        if char == "/":
            alternatives.append(r"\/")
        parts.append("(?:" + "|".join(alternatives) + ")")
    return re.compile("".join(parts))


def _literal_spans(text: str, tag: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        index = text.find(tag, start)
        if index < 0:
            return spans
        spans.append((index, index + len(tag)))
        start = index + 1


def _encoded_spans(text: str, tag: str, literal: list[tuple[int, int]]) -> list[tuple[int, int]]:
    literal_starts = {span[0] for span in literal}
    spans: list[tuple[int, int]] = []
    for match in _encoded_pattern(tag).finditer(text):
        if match.start() in literal_starts and match.group(0) == tag:
            continue
        if match.group(0) == tag:
            # 原样子串，已经由 literal 覆盖。
            continue
        spans.append((match.start(), match.end()))
    return spans


# ---------------------------------------------------------------------------
# 可执行判定（规范 §6）
# ---------------------------------------------------------------------------


def _header_value(headers: dict[str, str], name: str) -> str:
    lowered = {key.lower(): value for key, value in headers.items()}
    return lowered.get(name, "")


def _csp_blocks_inline(headers: dict[str, str]) -> bool:
    csp = _header_value(headers, "content-security-policy").lower()
    if not csp:
        return False
    return "unsafe-inline" not in csp


def _sandbox_blocked(node: domscan.Node | None) -> bool:
    cursor = node
    while cursor is not None:
        if cursor.tag == "iframe" and cursor.has("sandbox"):
            allow = (cursor.get("sandbox") or "").lower()
            return "allow-scripts" not in allow
        cursor = cursor.parent
    return False


def _breaks_out(payload: str, quoting: str) -> bool:
    if quoting == "double":
        return '"' in payload or ">" in payload
    if quoting == "single":
        return "'" in payload or ">" in payload
    return ">" in payload or " " in payload


def _breaks_js_string(payload: str, quoting: str) -> bool:
    if quoting == "double":
        return '"' in payload
    if quoting == "single":
        return "'" in payload
    return True


def _is_event_attr(attr_name: str | None, value: str) -> bool:
    if attr_name is None:
        return False
    name = attr_name.lower()
    if name.startswith("on"):
        return True
    if name == "srcdoc":
        return True
    return value.lower().lstrip().startswith("javascript:")


def _judge(
    *,
    context: domscan.Context,
    payload: str | None,
    downstream: bool,
    csp_blocked: bool,
    sandboxed: bool,
    is_html: bool,
    attr_value: str,
) -> tuple[bool, str, str]:
    """返回 ``(executable, reason, confidence)``；不确定一律 False。"""
    kind = context.kind
    if not is_html:
        return False, "CONTENT_TYPE_PLAIN", "high"
    if sandboxed:
        return False, "SANDBOXED", "high"
    if csp_blocked and kind in {
        ContextKind.HTML_TEXT,
        ContextKind.ATTR,
        ContextKind.SCRIPT_BLOCK,
        ContextKind.SCRIPT_STRING,
    }:
        return False, "CSP_BLOCKED", "high"

    if kind == ContextKind.COMMENT:
        return False, "NOT_CLOSED", "high"
    if kind == ContextKind.TEXTAREA:
        return False, "NO_CARRIER", "high"
    if kind == ContextKind.PLAIN_TEXT:
        return False, "NO_CARRIER", "high"
    if kind == ContextKind.JSON:
        return False, "NEEDS_RUNTIME", "medium"

    if kind == ContextKind.HTML_TEXT:
        if context.node is not None and context.node.tag == "title":
            return False, "TITLE_NOT_EXECUTABLE", "high"
        if payload:
            if _EXECUTABLE_CONSTRUCT.search(payload):
                return True, "HTML_EXECUTABLE", "high"
            return False, "INERT_PAYLOAD", "medium"
        return False, "NEEDS_EXECUTABLE_PAYLOAD", "medium"

    if kind == ContextKind.ATTR:
        if context.js_state == "style":
            return False, "STYLE_NOT_SCRIPTABLE", "medium"
        event = _is_event_attr(context.attr_name, attr_value)
        if payload is not None and payload != "":
            if event:
                return True, "EVENT_HANDLER", "high"
            if _breaks_out(payload, context.quoting) and (
                _EXECUTABLE_CONSTRUCT.search(payload) or _EVENT_ATTR_INJECT.search(payload)
            ):
                return True, "ATTR_BREAKOUT", "high"
            if _breaks_out(payload, context.quoting):
                return False, "INERT_PAYLOAD", "medium"
            return False, "NOT_CLOSED", "high"
        if event:
            return False, "NEEDS_EXECUTABLE_PAYLOAD", "medium"
        return False, "NEEDS_CLOSING_QUOTE", "medium"

    if kind == ContextKind.SCRIPT_BLOCK:
        if context.js_state in {"line_comment", "block_comment"}:
            return False, "JS_COMMENT", "high"
        if payload:
            if re.search(r"</\s*script", payload, re.IGNORECASE):
                return True, "SCRIPT_BREAKOUT", "high"
            if downstream:
                return True, "DOWNSTREAM_DOM_WRITE", "medium"
            return True, "SCRIPT_BLOCK_CODE", "medium"
        if downstream:
            return False, "NEEDS_RUNTIME", "low"
        return True, "SCRIPT_BLOCK_CODE", "low"

    if kind == ContextKind.SCRIPT_STRING:
        if payload:
            if _breaks_js_string(payload, context.quoting) and (
                ";" in payload or "\n" in payload or "//" in payload
            ):
                return True, "SCRIPT_STRING_BREAKOUT", "medium"
            if downstream:
                return True, "DOWNSTREAM_DOM_WRITE", "medium"
            return False, "NOT_CLOSED", "high"
        if downstream:
            return False, "NEEDS_RUNTIME", "low"
        return False, "NEEDS_CLOSING_QUOTE", "medium"

    return False, "NEEDS_RUNTIME", "low"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def analyze(
    html: str,
    tag: str,
    *,
    payload: str | None = None,
    content_type: str = "text/html",
    headers: dict[str, str] | None = None,
    status: int | None = None,
    max_occurrences: int = DEFAULT_MAX_OCCURRENCES,
) -> VerifyTagResult:
    """纯函数入口：同一 (html, tag, options) 任意时刻结果一致（规范 §9）。"""
    safe_headers = headers or {}
    document = domscan.parse(html)
    literal = _literal_spans(html, tag)
    encoded = _encoded_spans(html, tag, literal)
    is_html = domscan.is_html_content_type(content_type)
    csp_blocked = _csp_blocks_inline(safe_headers)
    downstream = bool(_DOWNSTREAM_WRITE.search(html))

    occurrences: list[Occurrence] = []
    seen: set[tuple[str, str | None]] = set()
    for start, end in literal:
        context = domscan.classify(document, start, content_type=content_type)
        node = context.node
        path = domscan.node_path(node) if node is not None else None
        key = ("html", path)
        if key in seen:
            continue
        seen.add(key)

        attr_value = ""
        if context.attr_name and node is not None:
            attr_value = node.get(context.attr_name) or ""
        executable, reason, confidence = _judge(
            context=context,
            payload=payload,
            downstream=downstream,
            csp_blocked=csp_blocked,
            sandboxed=_sandbox_blocked(node),
            is_html=is_html,
            attr_value=attr_value,
        )
        chain, truncated = (
            domscan.chain_html(html, node, start, end)
            if node is not None
            else ("", False)
        )
        occurrences.append(
            Occurrence(
                form="html",
                node_path=path,
                context_kind=ContextKind(context.kind),
                quoting=context.quoting,  # type: ignore[arg-type]
                executable=executable,
                executable_reason=reason,
                downstream_write=downstream,
                confidence=confidence,  # type: ignore[arg-type]
                chain_html=chain,
                chain_truncated=truncated,
                dom_ancestors=domscan.dom_ancestors(node) if node is not None else [],
                offset=start,
            )
        )

    # 响应头 / URL 里的 tag：返回但不进 best（规范 §3.3）。
    for _name, value in safe_headers.items():
        if tag in value:
            key = ("header", None)
            if key not in seen:
                seen.add(key)
                occurrences.append(
                    Occurrence(
                        form="header",
                        node_path=None,
                        context_kind=ContextKind.PLAIN_TEXT,
                        executable=False,
                        executable_reason="HEADER_ONLY",
                        confidence="high",
                        offset=-1,
                    )
                )

    warnings: list[str] = []
    if encoded:
        warnings.append(f"ENCODED_ONLY: encoded_count={len(encoded)}")
    if not is_html:
        warnings.append("NON_HTML_CONTENT_TYPE")
    if status is not None and status >= 400:
        warnings.append("ERROR_PAGE")
    if status is not None and 300 <= status < 400:
        warnings.append(f"REDIRECT_NOT_FOLLOWED: {_header_value(safe_headers, 'location')}")

    ranked = sorted(
        occurrences,
        key=lambda item: (
            not item.executable,
            CONTEXT_PRIORITY.get(item.context_kind.value, 99),
            item.offset,
        ),
    )
    if len(ranked) > max_occurrences:
        warnings.append(
            f"TRUNCATED_OCCURRENCES: total={len(ranked)} returned={max_occurrences}"
        )
        ranked = ranked[:max_occurrences]

    candidates = [item for item in ranked if item.node_path is not None]
    best = candidates[0] if candidates else None

    found = bool(literal) or bool(encoded)
    if status is not None and status >= 400:
        found = False

    return VerifyTagResult(
        found=found,
        occurrence_count=len(ranked),
        encoded_count=len(encoded),
        occurrences=ranked,
        best=best,
        sha256=hashlib.sha256(html.encode("utf-8", "replace")).hexdigest(),
        observed_at=_now(),
        content_type=content_type,
        status=status,
        warnings=warnings,
    )


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _fetch(input_: VerifyTagInput) -> tuple[str, str, dict[str, str], int]:
    assert input_.url is not None
    try:
        with httpx.Client(follow_redirects=False, timeout=HTTP_TIMEOUT_SECONDS) as client:
            response = client.get(input_.url, params=input_.params)
    except httpx.HTTPError as exc:
        raise ToolError(
            ErrorCode.ENV_ERROR,
            f"请求失败: {type(exc).__name__}: {exc}",
            retryable=True,
            hint="检查目标是否可达、URL 是否正确",
        ) from exc
    headers = {key.lower(): value for key, value in response.headers.items()}
    return response.text, response.headers.get("content-type", "text/html"), headers, response.status_code


async def verify_tag(arguments: dict[str, Any]) -> ToolOutput:
    """MCP handler：参数校验 → 取页面（或离线 HTML）→ 纯函数判定。"""
    try:
        input_ = VerifyTagInput.model_validate(arguments)
    except ValidationError as exc:
        raise ToolError(
            ErrorCode.BAD_ARGS,
            "参数不合法: " + "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            ),
            hint="url 与 html 二选一；tag 为 1..64 个非空白字符",
        ) from exc

    if input_.html is not None:
        html = input_.html
        content_type = input_.content_type or "text/html"
        headers = input_.headers
        status = input_.status
        warnings: list[str] = []
    else:
        html, content_type, headers, status = _fetch(input_)
        warnings = []
        if input_.session_id is not None:
            warnings.append("SESSION_NOT_IMPLEMENTED: 当前版本忽略 session_id")

    result = analyze(
        html,
        input_.tag,
        payload=input_.payload,
        content_type=content_type,
        headers=headers,
        status=status,
        max_occurrences=input_.max_occurrences,
    )
    result.warnings = [*warnings, *result.warnings]
    return ToolOutput(data=result.model_dump(mode="json"))
