"""离线分析：filter_analyze / guard_harvest / endpoint_search / includer_trace。

四个工具都只接受调用方给的文本或结构（源码片段、HTML、端点索引、包含关系边），
不读文件、不发请求、不查库；同样的输入永远得到同样的输出（可复现的归因依据）。
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tia.cap.registry import ToolOutput
from tia.schemas.envelope import ErrorCode, ToolError

MAX_CODE_BYTES = 256 * 1024
MAX_ITEMS = 200


def _bad(message: str, hint: str = "") -> ToolError:
    return ToolError(ErrorCode.BAD_ARGS, message, hint=hint)


def _validate(model: type[BaseModel], arguments: dict[str, Any]) -> Any:
    try:
        return model.model_validate(arguments)
    except ValidationError as exc:
        raise _bad(f"参数不合法: {exc.errors()[0]['msg']}") from exc


# ---------------------------------------------------------------------------
# filter_analyze
# ---------------------------------------------------------------------------

_FILTERS: dict[str, tuple[str, bool, str]] = {
    # name -> (category, reversible, note)
    "htmlspecialchars": ("encode", True, "HTML 实体编码；默认 ENT_QUOTES 时引号也被编码"),
    "htmlentities": ("encode", True, "HTML 实体编码，可被浏览器解码"),
    "strip_tags": ("sanitize", True, "剥离标签；属性里的恶意字符可能保留"),
    "addslashes": ("escape", True, "反斜杠转义，可被 stripslashes 逆变换"),
    "stripslashes": ("escape", True, "去掉反斜杠"),
    "urlencode": ("encode", True, "URL 编码，可逆"),
    "rawurlencode": ("encode", True, "URL 编码，可逆"),
    "urldecode": ("encode", True, "URL 解码"),
    "base64_encode": ("encode", True, "Base64，可逆"),
    "base64_decode": ("encode", True, "Base64 解码"),
    "str_rot13": ("encode", True, "ROT13，可逆"),
    "json_encode": ("encode", True, "JSON 编码，可逆"),
    "serialize": ("encode", True, "PHP 序列化，可逆"),
    "mysqli_real_escape_string": ("escape", True, "SQL 转义，可逆（但只对 SQL 有意义）"),
    "mysql_real_escape_string": ("escape", True, "SQL 转义，可逆"),
    "intval": ("cast", False, "强制转整数，信息不可恢复"),
    "floatval": ("cast", False, "强制转浮点，信息不可恢复"),
    "trim": ("normalize", False, "去首尾空白，信息不可恢复"),
    "substr": ("truncate", False, "截断，超出部分不可恢复"),
    "mb_substr": ("truncate", False, "截断，超出部分不可恢复"),
    "md5": ("hash", False, "单向散列"),
    "sha1": ("hash", False, "单向散列"),
    "hash": ("hash", False, "单向散列"),
    "preg_replace": ("blackbox", False, "结果取决于正则，需人工确认是否可逆"),
    "filter_var": ("blackbox", False, "结果取决于 FILTER_* 常量"),
    "str_replace": ("blackbox", False, "结果取决于替换规则"),
    "htmlspecialchars_decode": ("decode", True, "实体解码"),
}

_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CAST_RE = re.compile(r"\(\s*(int|integer|float|double|bool|boolean|string)\s*\)")
_VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")


class FilterAnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=MAX_CODE_BYTES)
    language: Literal["php", "js"] = "php"
    variable: str | None = Field(default=None, max_length=64)


async def filter_analyze(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(FilterAnalyzeInput, arguments)
    filters: list[dict[str, Any]] = []
    for match in _CALL_RE.finditer(params.code):
        name = match.group(1)
        known = _FILTERS.get(name)
        if known is None:
            continue
        line, column = _position(params.code, match.start())
        if params.variable and params.variable not in _argument_text(params.code, match.end()):
            continue
        category, reversible, note = known
        filters.append(
            {
                "name": name,
                "line": line,
                "column": column,
                "category": category,
                "reversible": reversible,
                "note": note,
            }
        )
    for match in _CAST_RE.finditer(params.code):
        window = params.code[match.start() : match.start() + 200].split(";")[0]
        if params.variable and params.variable not in window:
            continue
        line, column = _position(params.code, match.start())
        filters.append(
            {
                "name": f"({match.group(1)})",
                "line": line,
                "column": column,
                "category": "cast",
                "reversible": False,
                "note": "强制类型转换，信息不可恢复",
            }
        )
    filters.sort(key=lambda f: (f["line"], f["column"]))
    reversible_all = bool(filters) and all(f["reversible"] for f in filters)
    return ToolOutput(
        data={
            "filters": filters[:MAX_ITEMS],
            "filter_count": len(filters),
            "truncated": len(filters) > MAX_ITEMS,
            "reversible": reversible_all,
            "has_output_filter": bool(filters),
            "out_filter": "none" if not filters else ("reversible" if reversible_all else "lossy"),
            "variables": sorted(set(_VARIABLE_RE.findall(params.code)))[:50],
        }
    )


def _position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    column = offset - text.rfind("\n", 0, offset)
    return line, column


def _argument_text(code: str, start: int) -> str:
    depth = 1
    index = start
    while index < len(code) and depth > 0:
        char = code[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        index += 1
    return code[start:index]


# ---------------------------------------------------------------------------
# guard_harvest
# ---------------------------------------------------------------------------

_CSP_META_RE = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*[\"']?content-security-policy[\"']?[^>]*>", re.IGNORECASE
)
_CSP_CONTENT_RE = re.compile(r"content\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_SANDBOX_RE = re.compile(r"<iframe[^>]*\bsandbox\b[^>]*>", re.IGNORECASE)
_MAXLENGTH_RE = re.compile(r"\bmaxlength\s*=\s*[\"']?(\d+)", re.IGNORECASE)
_PATTERN_RE = re.compile(r"\bpattern\s*=\s*[\"']([^\"']{1,120})[\"']", re.IGNORECASE)


class GuardHarvestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    html: str | None = Field(default=None, max_length=MAX_CODE_BYTES)
    source: str | None = Field(default=None, max_length=MAX_CODE_BYTES)
    headers: dict[str, str] = Field(default_factory=dict)


async def guard_harvest(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(GuardHarvestInput, arguments)
    if not params.html and not params.source and not params.headers:
        raise _bad("至少提供 html / source / headers 之一")

    guards: list[dict[str, Any]] = []
    html = params.html or ""
    source = params.source or ""

    for header, value in params.headers.items():
        lowered = header.lower()
        if lowered == "content-security-policy":
            guards.append(
                {
                    "kind": "csp",
                    "value": value[:1000],
                    "evidence": f"header:{header}",
                    "blocking": _csp_blocks(value),
                }
            )
        elif lowered in {"x-frame-options", "x-content-type-options"} and value.strip():
            guards.append(
                {"kind": "header", "value": value[:200], "evidence": f"header:{header}",
                 "blocking": False}
            )

    for match in _CSP_META_RE.finditer(html):
        content = _CSP_CONTENT_RE.search(match.group(0))
        value = content.group(1) if content else ""
        guards.append(
            {"kind": "csp", "value": value[:1000], "evidence": "meta:content-security-policy",
             "blocking": _csp_blocks(value)}
        )
    for match in _SANDBOX_RE.finditer(html):
        guards.append(
            {"kind": "sandbox", "value": match.group(0)[:300], "evidence": "iframe@sandbox",
             "blocking": True}
        )
    for match in _MAXLENGTH_RE.finditer(html):
        guards.append(
            {"kind": "length_limit", "value": match.group(0)[:120], "evidence": "input@maxlength",
             "blocking": False, "limit": int(match.group(1))}
        )
    for match in _PATTERN_RE.finditer(html):
        guards.append(
            {"kind": "validation", "value": match.group(0)[:200], "evidence": "input@pattern",
             "blocking": False}
        )

    for name in ("htmlspecialchars", "strip_tags", "htmlentities", "filter_var", "preg_replace"):
        for match in re.finditer(rf"\b{name}\s*\(", source):
            line, _ = _position(source, match.start())
            guards.append(
                {"kind": "sanitizer", "value": name, "evidence": f"source:{line}",
                 "blocking": False}
            )

    guards = guards[:MAX_ITEMS]
    return ToolOutput(
        data={
            "guards": guards,
            "guard_count": len(guards),
            "blocked": any(g.get("blocking") for g in guards),
            "blocking_kinds": sorted({g["kind"] for g in guards if g.get("blocking")}),
        }
    )


def _csp_blocks(value: str) -> bool:
    lowered = value.lower()
    if "default-src" not in lowered and "script-src" not in lowered:
        return False
    return "unsafe-inline" not in lowered


# ---------------------------------------------------------------------------
# endpoint_search
# ---------------------------------------------------------------------------

class EndpointSearchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: list[dict[str, Any]] = Field(max_length=5000)
    query: str | None = Field(default=None, max_length=200)
    method: str | None = Field(default=None, max_length=10)
    path_contains: str | None = Field(default=None, max_length=200)
    limit: int = Field(default=50, ge=1, le=MAX_ITEMS)


async def endpoint_search(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(EndpointSearchInput, arguments)
    needle = (params.query or "").lower()
    path_needle = (params.path_contains or "").lower()
    hits: list[dict[str, Any]] = []
    for entry in params.index:
        path = str(entry.get("path") or entry.get("url") or "")
        if params.method and str(entry.get("method") or "").upper() != params.method.upper():
            continue
        if path_needle and path_needle not in path.lower():
            continue
        if needle:
            haystack = " ".join(
                [path, str(entry.get("source") or ""), " ".join(map(str, entry.get("params") or []))]
            ).lower()
            if needle not in haystack:
                continue
        hits.append(
            {
                "path": path,
                "method": str(entry.get("method") or "GET").upper(),
                "params": list(entry.get("params") or [])[:50],
                "source": str(entry.get("source") or "")[:300],
            }
        )
        if len(hits) >= params.limit:
            break
    return ToolOutput(
        data={
            "hits": hits,
            "hit_count": len(hits),
            "scanned": len(params.index),
            "truncated": len(hits) >= params.limit and len(params.index) > len(hits),
        }
    )


# ---------------------------------------------------------------------------
# includer_trace
# ---------------------------------------------------------------------------

class IncluderTraceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edges: list[dict[str, Any]] = Field(max_length=10000)
    entry: str = Field(min_length=1, max_length=300)
    target: str = Field(min_length=1, max_length=300)
    max_depth: int = Field(default=10, ge=1, le=30)
    max_paths: int = Field(default=5, ge=1, le=20)


async def includer_trace(arguments: dict[str, Any]) -> ToolOutput:
    params = _validate(IncluderTraceInput, arguments)
    graph: dict[str, list[tuple[str, str]]] = {}
    for edge in params.edges:
        source = str(edge.get("from") or "")
        dest = str(edge.get("to") or "")
        if not source or not dest:
            continue
        graph.setdefault(source, []).append((dest, str(edge.get("kind") or "include")))

    paths: list[dict[str, Any]] = []
    queue: deque[tuple[str, list[dict[str, str]]]] = deque([(params.entry, [])])
    seen_depth = {params.entry: 0}
    while queue and len(paths) < params.max_paths:
        node, edges = queue.popleft()
        if len(edges) >= params.max_depth:
            continue
        for dest, kind in graph.get(node, []):
            next_edges = [*edges, {"from": node, "to": dest, "kind": kind}]
            if dest == params.target:
                paths.append(
                    {
                        "files": [params.entry, *[e["to"] for e in next_edges]],
                        "edges": next_edges,
                        "length": len(next_edges),
                    }
                )
                if len(paths) >= params.max_paths:
                    break
                continue
            if seen_depth.get(dest, 1 << 30) <= len(next_edges):
                continue
            seen_depth[dest] = len(next_edges)
            queue.append((dest, next_edges))
    return ToolOutput(
        data={
            "found": bool(paths),
            "paths": paths,
            "path_count": len(paths),
            "entry": params.entry,
            "target": params.target,
            "truncated": len(paths) >= params.max_paths,
        }
    )
