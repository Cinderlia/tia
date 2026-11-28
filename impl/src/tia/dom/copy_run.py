"""Execute a copy path: write the marker at the entry, then let the
application copy it from column to column, verifying every hop.

A copy path is ordered from the entry write to the read column.  Each hop
names the slice that performs a write (its handler and line); sending a
request that reaches that handler is the evidence that the hop ran.  The
payload is only carried by the first hop: the later hops copy whatever the
application finds in the source row, so they carry a harmless value.
"""

from __future__ import annotations

import contextlib
from typing import Any
from urllib.parse import urlencode

COPY_NOT_REACHED = "COPY_NOT_REACHED"
COPY_TAG_LOST = "COPY_TAG_LOST"


def _hop_request(hop: dict[str, Any], base_url: str, value: str) -> dict[str, Any]:
    raw = dict(hop.get("raw") or {})
    params = [str(item) for item in raw.get("params") or [] if str(item)]
    url = str(hop.get("url") or "")
    if not url:
        sink = str(raw.get("sinkFile") or "")
        parent = sink.rsplit("/", 1)[0] if "/" in sink else ""
        url = base_url.rstrip("/") + ("/" + parent.strip("/") if parent else "") + "/"
    fields = {name: value for name in params}
    if not fields:
        fields = {"tia": value}
    return {
        "url": url,
        "method": "POST",
        "body": urlencode(fields),
        "fields": fields,
        "file": str(raw.get("sinkFile") or ""),
        "line": int(raw.get("sinkLine") or 0),
    }


async def _tag_rows(call: Any, case_id: str, table: str, columns: list[str], tag: str) -> int:
    where = " OR ".join(f"`{column}` LIKE '%{tag}%'" for column in columns)
    envelope = await call(
        "db_read", {"case_id": case_id, "sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE {where}"}
    )
    rows = envelope.get("rows") if isinstance(envelope, dict) else []
    if rows:
        return int(rows[0].get("n") or 0)
    return 0


async def run_copy_chain(
    call: Any,
    *,
    case_id: str,
    copy_path: dict[str, Any],
    base_url: str,
    payload: str,
    tag: str,
    account: str = "",
) -> dict[str, Any]:
    """Run the hops of a copy path and report the evidence.

    Returns ``{"ok", "hops", "failed_kind", "probed", "stored", "submitted"}``.
    The first hop writes ``payload``; every later hop carries the harmless
    value ``1`` so the application copies the stored marker itself.
    """
    hops = [hop for hop in copy_path.get("hops") or [] if isinstance(hop, dict)]
    evidence: list[dict[str, Any]] = []
    submitted: dict[str, Any] = {}
    for index, hop in enumerate(hops):
        request = _hop_request(hop, base_url, payload if index == 0 else "1")
        record: dict[str, Any] = {
            "index": index,
            "table": hop.get("table"),
            "column": hop.get("column"),
            "is_copy": bool(hop.get("is_copy")),
            "url": request["url"],
            "file": request["file"],
            "line": request["line"],
            "fields": request["fields"],
            "ok": False,
            "statements": [],
        }
        if request["file"] and request["line"] > 0:
            with contextlib.suppress(Exception):
                await call(
                    "probe_arm",
                    {
                        "case_id": case_id,
                        "targets": [{"file": request["file"], "line": request["line"]}],
                        "output": f"copy-{tag}-{index}.json",
                    },
                )
        try:
            envelope = await call(
                "probe_run",
                {
                    "case_id": case_id,
                    "url": request["url"],
                    "method": request["method"],
                    "body": request["body"],
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "capture_html": True,
                    "account_label": account,
                },
            )
        except Exception as exc:  # noqa: BLE001 - a hop that did not run is evidence
            record["error"] = f"{type(exc).__name__}: {exc}"
            evidence.append(record)
            return {
                "ok": False,
                "failed_kind": COPY_NOT_REACHED,
                "hops": evidence,
                "probed": False,
                "stored": 0,
                "submitted": submitted,
            }
        with contextlib.suppress(Exception):
            await call("probe_disarm", {"case_id": case_id})
        queries = envelope.get("queries") or []
        record["statements"] = [str(q.get("sql") or "") for q in queries if q.get("sql")]
        record["status"] = envelope.get("status")
        record["ok"] = bool(record["statements"]) or int(envelope.get("status") or 0) < 400
        submitted = envelope
        evidence.append(record)
        if not record["ok"]:
            return {
                "ok": False,
                "failed_kind": COPY_NOT_REACHED,
                "hops": evidence,
                "probed": False,
                "stored": 0,
                "submitted": submitted,
            }
    table = str(copy_path.get("table") or "")
    column = str(copy_path.get("column") or "")
    stored = 0
    if table and column:
        with contextlib.suppress(Exception):
            stored = await _tag_rows(call, case_id, table, [column], tag)
    if stored <= 0:
        return {
            "ok": False,
            "failed_kind": COPY_TAG_LOST,
            "hops": evidence,
            "probed": False,
            "stored": stored,
            "submitted": submitted,
        }
    return {
        "ok": True,
        "failed_kind": "",
        "hops": evidence,
        "probed": True,
        "stored": stored,
        "submitted": submitted,
    }
