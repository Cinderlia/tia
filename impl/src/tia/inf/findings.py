"""Vulnerability reports.

A report is written the moment an agent confirms something: confirmed
first-order, confirmed second-order, or a second-order candidate that only the
database path could trigger (no HTTP request was proven to store the value).
All fields come from the case notes, so no model call is involved.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

from tia.inf.reports import _safe, reports_root

KIND_TITLES = {
    "first_order": "Confirmed first-order XSS",
    "second_order": "Confirmed second-order XSS",
    "second_order_db_only": "Potential second-order XSS (database path only)",
}


def _notes(store: Any, case_id: str) -> dict[str, Any]:
    row = store.get_case(case_id)
    if row is None:
        return {}
    import json

    try:
        loaded = json.loads(row.get("notes") or "{}")
    except ValueError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _account(notes: dict[str, Any]) -> str:
    return str(notes.get("account") or os.environ.get("TIA_ACCOUNT") or "anonymous (no login)")


def _sink(notes: dict[str, Any]) -> str:
    read_sink = str(notes.get("read_sink") or "").strip()
    if read_sink:
        return read_sink
    sink = str(notes.get("sink") or "").strip()
    if sink:
        return sink
    file = str(notes.get("sink_file") or "").strip()
    if file:
        return file
    probe = notes.get("read_target")
    if isinstance(probe, dict) and probe.get("file"):
        return f"{probe['file']}:{probe.get('line') or '?'}"
    return "unknown"


def _request(notes: dict[str, Any]) -> tuple[str, str]:
    """Return (short label, markdown detail) for the request that stores the value."""

    entry = notes.get("entry")
    if isinstance(entry, dict) and entry.get("url"):
        method = str(entry.get("method") or "post").upper()
        url = str(entry.get("url"))
        field = str(entry.get("field") or entry.get("param") or "")
        payload = str(notes.get("payload") or "")
        detail = f"{method} {url}"
        if field:
            detail += f" — field `{field}` = `{payload}`"
        return f"{method} {url} field {field}", detail
    base = str(notes.get("base_url") or "")
    probe = notes.get("probe")
    if isinstance(probe, dict) and probe.get("targets"):
        return f"direct DB write ({base})", f"no HTTP request used; see the SQL below (page {base})"
    return f"(none) {base}".strip(), "no request recorded"


def _storage(notes: dict[str, Any]) -> str:
    target = notes.get("target")
    if isinstance(target, dict) and target.get("table"):
        columns = target.get("columns") or []
        return f"`{target['table']}`.`{target.get('column') or columns}`"
    table = str(notes.get("table") or "")
    constraints = notes.get("payload_constraints")
    if table and isinstance(constraints, dict) and constraints.get("column"):
        return f"`{table}`.`{constraints['column']}`"
    if table:
        return f"`{table}`"
    return "(not recorded)"


def _sql(notes: dict[str, Any]) -> str:
    probe = notes.get("probe")
    if isinstance(probe, dict) and probe.get("sql"):
        return str(probe["sql"])
    insert = notes.get("insert_sql")
    if insert:
        return str(insert)
    return ""


def _read_request(notes: dict[str, Any]) -> str:
    target = notes.get("read_target")
    url = str(notes.get("read_url") or notes.get("base_url") or "")
    if isinstance(target, dict) and target.get("file"):
        return f"GET {url} (reads `{target['file']}:{target.get('line') or '?'}`)"
    return f"GET {url}" if url else "(not recorded)"


def _payload(notes: dict[str, Any]) -> str:
    payload = str(notes.get("payload") or "")
    if payload:
        return payload
    attempts = notes.get("attempts") or []
    for attempt in reversed(attempts):
        if attempt.get("executable") and attempt.get("payload"):
            return str(attempt["payload"])
    for attempt in reversed(attempts):
        if attempt.get("payload"):
            return str(attempt["payload"])
    return ""


def _verify_section(notes: dict[str, Any], kind: str) -> list[str]:
    """Steps a human can execute in a browser (URL, plus a form for POST)."""

    payload = _payload(notes)
    raw_entry = notes.get("entry")
    entry: dict[str, Any] = raw_entry if isinstance(raw_entry, dict) else {}
    url = str(entry.get("url") or notes.get("read_url") or notes.get("base_url") or "")
    method = str(entry.get("method") or "get").lower()
    field = str(entry.get("field") or entry.get("param") or "")
    lines = ["", "## Verify in a browser", ""]
    if kind == "second_order_db_only":
        lines += [
            "1. Run the SQL above against the target database.",
            f"2. Open: {_read_request(notes)}",
            "3. The page reflects the value (payload derived from the stored tag is in Evidence).",
        ]
        return lines
    if not url:
        return lines + ["- No URL recorded for this finding."]
    step = 1
    if method == "get" and field and payload:
        target = f"{url}{'&' if '?' in url else '?'}{field}={quote(payload, safe='')}"
        lines += [f"{step}. Open: {target}"]
        step += 1
    elif method == "get":
        lines += [f"{step}. Open: {url}"]
        step += 1
    else:
        lines += [
            f"{step}. Open: {url}",
            f"{step + 1}. POST the form with:",
            "",
            "| Field | Value |",
            "| --- | --- |",
        ]
        step += 2
        raw_fields = entry.get("fields")
        if isinstance(raw_fields, dict):
            names = list(raw_fields)
        elif isinstance(raw_fields, list):
            names = [str(name) for name in raw_fields]
        else:
            names = []
        for name in names:
            if name == field:
                lines.append(f"| `{name}` | `{payload}` |")
            else:
                lines.append(f"| `{name}` | (empty) |")
        if not names:
            lines.append(f"| `{field}` | `{payload}` |")
        lines.append("")
    if kind == "second_order":
        lines.append(f"{step}. Open the read page: {_read_request(notes)}")
        step += 1
    lines.append(f"{step}. The value is rendered at the sink above.")
    return lines


def _evidence(notes: dict[str, Any]) -> str:
    parts: list[str] = []
    if notes.get("tag"):
        parts.append(f"tag `{notes['tag']}`")
    if notes.get("occurrence_count") is not None:
        parts.append(f"occurrences={notes['occurrence_count']}")
    best = notes.get("best")
    if isinstance(best, dict):
        parts.append(f"context={best.get('context_kind')}, reason={best.get('reason')}")
    if notes.get("tag_in_db") is not None:
        parts.append(f"tag_in_db={notes['tag_in_db']}")
    return ", ".join(parts) or "(see case report)"


def write_finding(
    store: Any,
    *,
    kind: str,
    case_id: str,
    notes: dict[str, Any],
    evidence_refs: list[str] | None = None,
) -> Path | None:
    """Write one finding file (idempotent) and append it to the findings index."""

    sink = _sink(notes)
    storage = _storage(notes)
    request_label, request_detail = _request(notes)
    # One finding per file + storage + request: the same value echoed on
    # several lines of one page is one vulnerability, not three.
    sink_file = sink.split(":", 1)[0]
    key = hashlib.sha1(
        "|".join([kind, sink_file, storage, request_label]).encode("utf-8")
    ).hexdigest()[:8]

    directory = reports_root(store) / "vulnerabilities"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kind}-{_safe(sink_file.replace('/', '-'))}-{key}.md"
    if path.exists():
        return path

    title = KIND_TITLES.get(kind, kind)
    lines = [
        f"# {title}",
        "",
        f"- Case: `{case_id}`",
        f"- Sink (trigger point): `{sink}`",
    ]
    code = str(notes.get("sink_code") or "").strip()
    if code:
        lines[-1] += f" — `{code}`"
    sql = _sql(notes)
    if kind == "second_order_db_only":
        lines.append(f"- Read request: {_read_request(notes)}")
    else:
        lines.append(f"- Injection request: {request_detail}")
    if kind != "first_order":
        lines.append(f"- Storage (database field): {storage}")
    if sql:
        label = "Application SQL observed" if kind != "second_order_db_only" else "SQL executed"
        lines.append(f"- {label}:\n\n```sql\n{sql}\n```")
    if kind == "second_order":
        lines.append(f"- Read request: {_read_request(notes)}")
    lines += [
        f"- Account: {_account(notes)}",
        f"- Evidence: {_evidence(notes)}",
    ]
    if evidence_refs:
        lines.append(f"- Evidence refs: {', '.join(f'`{ref}`' for ref in evidence_refs)}")
    if kind == "second_order_db_only":
        lines += [
            "",
            "This value was written to the database directly (no HTTP request was confirmed to store it).",
        ]
    lines += _verify_section(notes, kind)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    index = reports_root(store) / "findings.md"
    if not index.exists():
        index.write_text(
            "# Confirmed vulnerabilities\n\n| # | Kind | Sink | Storage | Request | Account | Report |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n",
            encoding="utf-8",
        )
    existing = sum(
        1
        for line in index.read_text(encoding="utf-8").splitlines()
        if line.startswith("| ") and line.split(" | ")[0].strip("| ").isdigit()
    )
    row = (
        f"| {existing + 1} | {title} | `{sink}` | {storage} | {request_label} | {_account(notes)} "
        f"| [{path.name}](vulnerabilities/{path.name}) |\n"
    )
    with index.open("a", encoding="utf-8") as handle:
        handle.write(row)
    return path


def finding_first_order(store: Any, case_id: str) -> Path | None:
    notes = _notes(store, case_id)
    if not notes:
        return None
    return write_finding(store, kind="first_order", case_id=case_id, notes=notes)


def finding_second_order(store: Any, case_id: str) -> Path | None:
    notes = _notes(store, case_id)
    if not notes:
        return None
    return write_finding(store, kind="second_order", case_id=case_id, notes=notes)


def finding_db_only(store: Any, case_id: str) -> Path | None:
    notes = _notes(store, case_id)
    if not notes:
        return None
    return write_finding(store, kind="second_order_db_only", case_id=case_id, notes=notes)
