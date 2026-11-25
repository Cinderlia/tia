"""Per-slice tool experience: short summaries for learning, raw payloads for audit.

Downstream agents read the summary only. Full tool returns are archived under
``<store dir>/traces/<case_id>/`` so a later review (or a model) can look them
up, but they never enter another agent's context directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tia.inf.store import Store, now_iso

#: Cap for an archived raw return (bytes).
RAW_LIMIT = 262_144


def summarize(tool: str, data: Any) -> dict[str, Any]:
    """Return a compact, agent-readable gist of one tool result (never the raw body)."""
    if not isinstance(data, dict):
        return {"result": type(data).__name__}
    if tool == "verify_tag":
        best = data.get("best") or {}
        return {
            "found": data.get("found"),
            "occurrences": data.get("occurrence_count"),
            "context_kind": best.get("context_kind"),
            "executable": best.get("executable"),
            "reason": best.get("executable_reason"),
        }
    if tool == "db_read":
        rows = data.get("rows") or []
        return {"rows": data.get("row_count", len(rows)), "columns": list((rows[0] or {}).keys())[:8] if rows else []}
    if tool == "db_write":
        change = data.get("change") or {}
        return {
            "change_id": change.get("change_id"),
            "affected": data.get("affected_rows"),
            "table": (data.get("write") or {}).get("table") if isinstance(data.get("write"), dict) else None,
        }
    if tool == "db_undo":
        return {"reverted": data.get("reverted"), "residue": data.get("residue")}
    if tool == "db_schema":
        tables = data.get("tables") or []
        return {"tables": [item.get("name") for item in tables][:5], "count": len(tables)}
    if tool in {"source_read", "source_grep"}:
        return {
            "file": data.get("path") or data.get("file"),
            "lines": len(data.get("lines") or data.get("hits") or []),
            "sha256": (data.get("sha256") or "")[:16] or None,
        }
    if tool in {"http_request", "http_replay"}:
        raw_http = data.get("http")
        http: dict[str, Any] = raw_http if isinstance(raw_http, dict) else data
        chain = http.get("redirect_chain") or []
        return {
            "status": http.get("status"),
            "content_type": http.get("content_type"),
            "bytes": http.get("body_bytes"),
            "redirects": [str(hop.get("url")) for hop in chain][-3:],
        }
    if tool in {"probe_arm", "probe_run", "probe_disarm"}:
        return {
            "hit": data.get("hit"),
            "mode": data.get("mode"),
            "queries": len(data.get("queries") or []),
            "rows": sum(len(query.get("rows") or []) for query in (data.get("queries") or [])),
        }
    if tool == "case_open":
        return {"case_id": data.get("case_id")}
    if tool == "case_report":
        return {"chars": len(str(data.get("markdown") or ""))}
    keys = list(data.keys())
    return {"keys": keys[:8]}


class ExperienceRecorder:
    """Write one tool-trace row plus the raw return kept out of agent context."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.trace_dir = Path(store.path).parent / "traces"

    def record(
        self,
        *,
        case_id: str,
        slice_id: str | None,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        ok: bool,
        cost_ms: int,
        data: Any = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        seq = self.store.add_tool_trace(
            case_id=case_id,
            slice_id=slice_id,
            agent=agent,
            tool=tool,
            arguments=_bounded(arguments),
            ok=ok,
            cost_ms=cost_ms,
            summary=summarize(tool, data) if ok else {"error": (error or {}).get("code")},
            error_code=(error or {}).get("code") if not ok else None,
            observed_at=now_iso(),
        )
        raw = data if ok else {"error": error}
        path = self._write_raw(case_id, seq, tool, raw)
        self.store.set_tool_trace_raw(case_id=case_id, seq=seq, raw_path=str(path))

    def _write_raw(self, case_id: str, seq: int, tool: str, raw: Any) -> Path:
        folder = self.trace_dir / case_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{seq:04d}-{tool}.json"
        text = json.dumps(raw, ensure_ascii=False, default=str)
        path.write_text(text[:RAW_LIMIT], encoding="utf-8")
        return path


def _bounded(arguments: dict[str, Any], limit: int = 4096) -> dict[str, Any]:
    text = json.dumps(arguments, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return arguments
    return {"_truncated": True, "preview": text[:limit]}
