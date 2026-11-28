"""Bounded, frame-aware view of a directed trace for a planning prompt.

A directed trace can still hold hundreds of entries, and a model reading it as
a flat list loses the call structure that explains why a statement did or did
not run. This module keeps the frames (one line per call site) and the lines
that touch the sink, collapses repeated cycles, and renders the result as a
short text block. The full trace is never handed to the model.
"""

from __future__ import annotations

import json
from typing import Any

from tia.cap.trace import TraceEntry

MAX_SLICE = 24
MAX_RENDER = 1600
MAX_DIFF = 1200


def _field(entry: TraceEntry | dict[str, Any], name: str, default: Any = "") -> Any:
    if isinstance(entry, dict):
        return entry.get(name, default)
    return getattr(entry, name, default)


def _line_of(entry: TraceEntry | dict[str, Any]) -> dict[str, Any]:
    return {
        "depth": _field(entry, "depth") or 0,
        "func": _field(entry, "func") or "",
        "file": _field(entry, "file") or "",
        "line": _field(entry, "line") or 0,
        "op": _field(entry, "op") or "",
    }


def slice_trace(
    entries: list[TraceEntry] | list[dict[str, Any]],
    *,
    sink_file: str = "",
    sink_line: int = 0,
    limit: int = MAX_SLICE,
) -> dict[str, Any]:
    """Keep call sites and sink lines; collapse repeated cycles; bound output."""

    rows = [_line_of(entry) for entry in entries]
    total = len(rows)
    if not rows:
        return {"entries": [], "total": 0, "truncated": False, "kept": 0}
    sink_name = sink_file.replace("\\", "/")
    tail = sink_name.rsplit("/", 2)[-2:] if "/" in sink_name else [sink_name]
    sink_tail = "/".join(item for item in tail if item)

    def touches_sink(row: dict[str, Any]) -> bool:
        name = str(row["file"]).replace("\\", "/")
        if sink_line and row["line"] == sink_line and sink_tail and sink_tail in name:
            return True
        return bool(sink_tail) and sink_tail in name

    kept: list[dict[str, Any]] = []
    seen: dict[tuple[Any, ...], int] = {}
    for index, row in enumerate(rows):
        depth = int(row["depth"] or 0)
        nxt = rows[index + 1] if index + 1 < len(rows) else None
        call_site = nxt is not None and int(nxt["depth"] or 0) > depth
        key = (row["file"], row["line"], row["op"], row["func"], depth)
        seen[key] = seen.get(key, 0) + 1
        if not (touches_sink(row) or call_site or seen[key] == 1):
            continue
        item = dict(row)
        if seen[key] > 1:
            item["repeat"] = seen[key]
        kept.append(item)
    if len(kept) > limit:
        # Keep the beginning and the end: the entry point and the sink path.
        head = kept[: limit - 6]
        tail_rows = kept[-6:]
        kept = head + [{"elided": len(kept) - limit}] + tail_rows
    return {
        "entries": kept,
        "total": total,
        "kept": len(kept),
        "truncated": len(kept) < total,
        "sink": f"{sink_file}:{sink_line}" if sink_file else "",
    }


def render_trace(view: dict[str, Any] | None) -> str:
    """Render a slice as depth-indented lines for the prompt."""

    if not view or not view.get("entries"):
        return ""
    lines: list[str] = []
    for item in view["entries"]:
        if "elided" in item:
            lines.append(f"  ... {item['elided']} entries elided ...")
            continue
        depth = int(item.get("depth") or 0)
        func = item.get("func") or "-"
        name = str(item.get("file") or "")
        short = name.rsplit("/", 2)[-2:] if "/" in name else [name]
        repeat = f" x{item['repeat']}" if item.get("repeat") else ""
        lines.append(
            f"{'  ' * min(depth, 8)}d{depth} {func} at {'/'.join(short)}:"
            f"{item.get('line')} {item.get('op')}{repeat}"
        )
    return "\n".join(lines)[:MAX_RENDER]


def render_diff(diff: dict[str, Any] | None) -> str:
    """Render the divergence summary (regions and counts only)."""

    if not diff:
        return ""
    counts = diff.get("counts") or {}
    lines = [
        f"baseline {counts.get('before_total', 0)} entries, "
        f"this request {counts.get('after_total', 0)} entries, "
        f"first divergence at region 0 (regions: {diff.get('region_count', 0)})"
    ]
    for region in (diff.get("regions") or [])[:2]:
        before = (region.get("a_sample") or [{}])[0]
        after = (region.get("b_sample") or [{}])[0]
        lines.append(
            f"- only in baseline: {before.get('file')}:{before.get('line')} "
            f"{before.get('op')}; only in this request: "
            f"{after.get('file')}:{after.get('line')} {after.get('op')}"
        )
    return "\n".join(lines)[:MAX_DIFF]


def diff_view(diff: dict[str, Any] | None) -> dict[str, Any] | None:
    """Small JSON-safe diff payload for the prompt."""

    if not diff:
        return None
    return {
        "counts": diff.get("counts") or {},
        "region_count": diff.get("region_count", 0),
        "regions": [
            {
                "kind": region.get("kind"),
                "a": (region.get("a_sample") or [{}])[0],
                "b": (region.get("b_sample") or [{}])[0],
            }
            for region in (diff.get("regions") or [])[:3]
        ],
    }


def make_trace_probe(
    call: Any,
    *,
    case_id: str,
    file: str,
    line: int,
    account: str = "",
) -> Any:
    """Return a probe that traces one already-sent attempt, bounded to the sink."""

    async def probe(attempt: Any) -> dict[str, Any]:
        url = str(getattr(attempt, "url", "") or "")
        if not url or not file:
            return {}
        method = str(getattr(attempt, "method", "GET") or "GET").upper()
        values = dict(getattr(attempt, "values", {}) or {})
        arguments: dict[str, Any] = {
            "case_id": case_id,
            "url": url,
            "method": method,
            "targets": [
                {
                    "file": file,
                    "line_from": max(1, int(line or 1) - 2),
                    "line_to": int(line or 1) + 2,
                }
            ],
            "max_lines": 4000,
            "max_entries": 300,
            "account_label": account or getattr(attempt, "account", ""),
        }
        if method == "GET":
            arguments["params"] = values
        else:
            from urllib.parse import urlencode

            arguments["body"] = urlencode(values)
        result = await call("trace_run", arguments)
        raw = list(result.get("entries") or [])
        view = slice_trace(raw, sink_file=file, sink_line=int(line or 0))
        return {"slice": view, "raw": raw, "trace_id": result.get("trace_id", "")}

    return probe


def as_json(view: dict[str, Any] | None, limit: int = MAX_RENDER) -> str:
    """JSON block for the prompt."""

    if not view:
        return ""
    return json.dumps(view, ensure_ascii=False)[:limit]
