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
    if isinstance(probe, dict):
        statements = [str(item) for item in probe.get("statements") or [] if item]
        if len(statements) > 1:
            return ";\n".join(statements)
        if probe.get("sql"):
            return str(probe["sql"])
    insert = notes.get("insert_sql")
    if insert:
        return str(insert)
    return ""


def _read_request(notes: dict[str, Any]) -> str:
    target = notes.get("read_target")
    url = str(notes.get("read_url") or "")
    if not url:
        execution = notes.get("execution")
        if isinstance(execution, dict):
            url = str(execution.get("final_url") or "")
    url = url or str(notes.get("base_url") or "")
    if isinstance(target, dict) and target.get("file"):
        return f"GET {url} (reads `{target['file']}:{target.get('line') or '?'}`)"
    return f"GET {url}" if url else "(not recorded)"


def _constraints(notes: dict[str, Any]) -> list[dict[str, Any]]:
    """Branch conditions that must hold for the read path to return the row."""

    steps = notes.get("constraint_steps")
    if isinstance(steps, list):
        found = [item for item in steps if isinstance(item, dict)]
        if found:
            return found
    legacy = notes.get("constraints")
    if isinstance(legacy, list):
        return [item for item in legacy if isinstance(item, dict)]
    return []


def _replay_url(item: dict[str, Any]) -> str:
    replay = item.get("replay")
    if isinstance(replay, dict):
        return str(replay.get("url") or (replay.get("urls") or [""])[0] or "")
    return str(item.get("replay_url") or "")


def _replay_params(item: dict[str, Any]) -> dict[str, Any]:
    replay = item.get("replay")
    if not isinstance(replay, dict):
        return {}
    attempts = replay.get("attempts")
    if isinstance(attempts, list):
        for attempt in reversed(attempts):
            if isinstance(attempt, dict) and attempt.get("params"):
                return dict(attempt["params"])
    return {}


def _params_hint(params: dict[str, Any]) -> str:
    shown: list[str] = []
    for name, value in params.items():
        if name.lower() == "formid":
            shown.append("`formid=(your session token)`")
        else:
            shown.append(f"`{name}={value}`")
    return ", ".join(shown)


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


def _entry_pairs(entry: dict[str, Any], field: str, payload: str) -> list[tuple[str, str]]:
    raw_fields = entry.get("fields")
    names = [str(name) for name in raw_fields] if isinstance(raw_fields, (dict, list)) else []
    if field and field not in names:
        names.append(field)
    pairs: list[tuple[str, str]] = []
    for name in names:
        if name == field:
            pairs.append((name, payload))
        elif name.lower() in {"submit", "btnsubmit", "login", "go"}:
            pairs.append((name, "1"))
        else:
            pairs.append((name, ""))
    return pairs



def _constraint_section(notes: dict[str, Any], kind: str) -> list[str]:
    """Extra SQL requirements (branch conditions) and how the run satisfied them."""
    if kind not in {"second_order", "second_order_db_only"}:
        return []
    constraints = _constraints(notes)
    if not constraints:
        return []
    lines = [
        "",
        "## Additional SQL requirements",
        "",
        "The payload alone is not enough: the read path only returns the row when these "
        "database conditions hold. They are part of the reachability, not of the payload.",
        "",
    ]
    for index, item in enumerate(constraints, 1):
        table = item.get("table") or "?"
        column = item.get("column") or "?"
        value = item.get("value")
        predicate = str(item.get("predicate") or "").strip().splitlines()[0][:160]
        line = f"{index}. `{table}`.`{column}` must equal `{value}`"
        if predicate:
            line += f" — `{predicate}`"
        lines.append(line)

    satisfied = [
        item
        for item in constraints
        if isinstance(item.get("replay"), dict) and item["replay"].get("confirmed")
    ]
    if satisfied:
        lines += [
            "",
            "### How this run satisfied them (through the application, not direct SQL)",
            "",
        ]
        for item in satisfied:
            table = item.get("table") or "?"
            column = item.get("column") or "?"
            url = _replay_url(item)
            params = _params_hint(_replay_params(item))
            account = str(item.get("account") or item.get("replay_account") or "")
            replay = item["replay"] if isinstance(item.get("replay"), dict) else {}
            queries = 0
            for attempt in replay.get("attempts") or []:
                if isinstance(attempt, dict):
                    queries += int(attempt.get("queries") or 0)
            bits = [f"`{table}`.`{column}` = `{item.get('value')}`"]
            if url:
                bits.append(f"request `GET {url}`" + (f" with {params}" if params else ""))
            if account:
                bits.append(f"account `{account}`")
            if queries:
                bits.append(f"probe matched {queries} executed statement(s)")
            if replay.get("observed") is not None:
                bits.append(f"database confirmed the column equals `{item.get('value')}`")
            lines.append("- " + "; ".join(bits) + ".")
    else:
        lines += [
            "",
            "During this run the condition was not replayed through the application; "
            "see the case report for the exact SQL.",
        ]
    return lines


def _browser_params(params: dict[str, Any]) -> str:
    parts: list[str] = []
    for name, value in params.items():
        low = str(name).lower()
        if low == "formid":
            parts.append("formid=<session token>")
        elif low in {"tid", "id"}:
            parts.append(f"{name}=<id of the row you created>")
        else:
            parts.append(f"{name}={value}")
    return "&".join(parts)


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
    pairs = _entry_pairs(entry, field, payload) if payload else []
    raw_fields = entry.get("fields")
    recorded: dict[str, Any] = dict(raw_fields) if isinstance(raw_fields, dict) else {}
    plan = notes.get("request_plan")
    if isinstance(plan, dict):
        for name, value in (plan.get("model") or {}).items():
            if recorded.get(name) in (None, ""):
                recorded[name] = value
    if method == "get" and pairs:
        query = "&".join(f"{quote(name)}={quote(value, safe='')}" for name, value in pairs)
        target = f"{url}{'&' if '?' in url else '?'}{query}"
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
        for name, _value in pairs or [(field, payload)]:
            if name == field:
                shown = f"`{payload}`" if payload else "(empty)"
            elif name.lower() == "formid":
                shown = "(the token your session received on this page)"
            elif name in recorded and recorded[name] not in ("", None):
                shown = f"`{recorded[name]}`"
            else:
                shown = "(empty)"
            lines.append(f"| `{name}` | {shown} |")
        lines.append("")
    if kind == "second_order":
        for item in _constraints(notes):
            replay_url = _replay_url(item)
            if not replay_url:
                continue
            params = _browser_params(_replay_params(item))
            target = f"{replay_url}{'&' if '?' in replay_url else '?'}{params}" if params else replay_url
            account = str(item.get("account") or "")
            who = f"As `{account}`, " if account else ""
            lines.append(
                f"{step}. {who}open the approval/action request that satisfies "
                f"`{item.get('table')}`.`{item.get('column')}` = `{item.get('value')}`: {target}"
            )
            step += 1
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
    # Confirming the same vulnerability again refreshes the evidence (payload,
    # row id, constraint replay) instead of leaving the first run's snapshot.
    refreshed = path.exists()

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
    lines += _constraint_section(notes, kind)
    lines += _verify_section(notes, kind)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if refreshed:
        return path

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
