"""Walk a chain of application writes: seed, then one or more transforms.

A chain step is an application request that reaches a write handler.  The
first step (``payload=True``) carries the marker; later steps carry no
payload at all, they only make the application read what was stored and
write it somewhere else.  Each step proves itself with the same evidence as
a single write: the probe hit the handler line, and (for the step that
carries the marker) the target column contains the tag.  The tag has to be
in the last step's column at the end, otherwise the application lost it on
the way.
"""

from __future__ import annotations

import contextlib
from typing import Any
from urllib.parse import urlencode

CHAIN_STEP_NOT_REACHED = "CHAIN_STEP_NOT_REACHED"
CHAIN_TAG_LOST = "CHAIN_TAG_LOST"


def _step_place(step: dict[str, Any], base_url: str) -> tuple[str, str, int]:
    raw = dict(step.get("raw") or {})
    url = str(step.get("url") or "")
    if not url:
        sink = str(raw.get("sinkFile") or step.get("file") or "")
        parent = sink.rsplit("/", 1)[0] if "/" in sink else ""
        url = base_url.rstrip("/") + ("/" + parent.strip("/") if parent else "") + "/"
    return url, str(raw.get("sinkFile") or step.get("file") or ""), int(
        raw.get("sinkLine") or step.get("line") or 0
    )


def _resolve_needs(needs: dict[str, Any], emitted: dict[int, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for field, ref in needs.items():
        text = str(ref or "")
        if text.startswith("step-") and text.endswith(".id"):
            index = int(text[len("step-") : -len(".id")])
            values[str(field)] = str(emitted.get(index) or "1")
        elif text:
            values[str(field)] = text
    return values


def _step_values(
    step: dict[str, Any], payload: str, *, emitted: dict[int, str]
) -> dict[str, str]:
    raw = dict(step.get("raw") or {})
    params = [str(item) for item in raw.get("params") or [] if str(item)]
    values = {str(k): str(v) for k, v in dict(step.get("values") or {}).items()}
    for name in params:
        values.setdefault(name, "1")
    values.update(_resolve_needs(dict(step.get("needs") or {}), emitted))
    if step.get("payload"):
        if params:
            values[params[0]] = payload
        else:
            values.setdefault("tia", payload)
    if not values:
        values = {"tia": "1"}
    return values


def _emitted_id(envelope: dict[str, Any], index: int) -> str:
    for query in envelope.get("queries") or []:
        write = query.get("write") if isinstance(query.get("write"), dict) else {}
        for value in (write.get("last_insert_id"), query.get("last_insert_id")):
            if value:
                return str(value)
    return ""


async def _tag_rows(
    call: Any, case_id: str, table: str, columns: list[str], tag: str
) -> int:
    where = " OR ".join(f"`{column}` LIKE '%{tag}%'" for column in columns)
    envelope = await call(
        "db_read",
        {"case_id": case_id, "sql": f"SELECT COUNT(*) AS n FROM `{table}` WHERE {where}"},
    )
    rows = envelope.get("rows") if isinstance(envelope, dict) else []
    return int(rows[0].get("n") or 0) if rows else 0


async def run_chain(
    call: Any,
    *,
    case_id: str,
    chain: list[dict[str, Any]],
    base_url: str,
    payload: str,
    tag: str,
    account: str = "",
) -> dict[str, Any]:
    """Run the ordered steps of a chain and report the evidence per step."""
    steps = [step for step in chain if isinstance(step, dict)]
    evidence: list[dict[str, Any]] = []
    submitted: dict[str, Any] = {}
    last_table = ""
    last_columns: list[str] = []
    emitted: dict[int, str] = {}
    for index, step in enumerate(steps):
        url, file, line = _step_place(step, base_url)
        values = _step_values(step, payload, emitted=emitted)
        table = str(step.get("table") or "")
        columns = [str(column) for column in step.get("columns") or [] if column]
        if not columns and step.get("column"):
            columns = [str(step["column"])]
        record: dict[str, Any] = {
            "index": index,
            "url": url,
            "file": file,
            "line": line,
            "values": values,
            "table": table,
            "columns": columns,
            "carries_payload": bool(step.get("payload")),
            "ok": False,
            "statements": [],
        }
        if file and line > 0:
            with contextlib.suppress(Exception):
                await call(
                    "probe_arm",
                    {
                        "case_id": case_id,
                        "targets": [{"file": file, "line": line}],
                        "output": f"chain-{tag}-{index}.json",
                    },
                )
        try:
            envelope = await call(
                "probe_run",
                {
                    "case_id": case_id,
                    "url": url,
                    "method": "POST",
                    "body": urlencode(values),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "capture_html": True,
                    "account_label": account,
                },
            )
        except Exception as exc:  # noqa: BLE001 - a step that did not run is evidence
            record["error"] = f"{type(exc).__name__}: {exc}"
            evidence.append(record)
            return {
                "ok": False,
                "failed_kind": CHAIN_STEP_NOT_REACHED,
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
        hit = bool(record["statements"]) or int(envelope.get("status") or 0) < 400
        stored = 0
        if hit and step.get("payload") and table and columns:
            with contextlib.suppress(Exception):
                stored = await _tag_rows(call, case_id, table, columns, tag)
            record["stored"] = stored
        record["ok"] = bool(hit) and (not step.get("payload") or stored > 0)
        emitted[index] = _emitted_id(envelope, index)
        record["emitted_id"] = emitted[index]
        submitted = envelope
        evidence.append(record)
        if not record["ok"]:
            return {
                "ok": False,
                "failed_kind": CHAIN_STEP_NOT_REACHED,
                "hops": evidence,
                "probed": True,
                "stored": 0,
                "submitted": submitted,
            }
        last_table = table or last_table
        last_columns = columns or last_columns
    stored = 0
    if last_table and last_columns:
        with contextlib.suppress(Exception):
            stored = await _tag_rows(call, case_id, last_table, last_columns, tag)
    if stored <= 0:
        return {
            "ok": False,
            "failed_kind": CHAIN_TAG_LOST,
            "hops": evidence,
            "probed": True,
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
