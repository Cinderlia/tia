"""Locate the SQL a read path really executed.

A read sink in a template usually just renders one row; the query itself is
built in a sibling module. A full opcode trace is forbidden, so this helper is
deliberately mechanical and bounded:

* grep the sink's directory for PHP files (a module lives next to its templates),
* trace only those files around the request,
* read the lines that actually executed,
* arm the SQL probe at executed query calls and keep the statement the engine
  reports.

The probe returns the executed SQL verbatim, so no source-level guess about the
predicate (or its table) is needed.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]

_QUERY_CALL = re.compile(r"(?:query|prepare|execute)\s*\(")
MAX_FILES = 8
MAX_PROBES = 3
WINDOW = 400


def _line_number(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _same_file(left: str, right: str) -> bool:
    return left == right or left.endswith("/" + right)


async def _probe_statement(
    call: Call,
    *,
    case_id: str,
    url: str,
    file: str,
    line: int,
    account: str,
) -> dict[str, Any]:
    output = "read-" + hashlib.sha1(f"{case_id}|{file}|{line}".encode()).hexdigest()[:10] + ".json"
    armed = await call(
        "probe_arm",
        {
            "case_id": case_id,
            "file": file,
            "line": line,
            "output": output,
        },
    )
    try:
        run = await call(
            "probe_run",
            {
                "case_id": case_id,
                "url": url,
                "method": "GET",
                "output": output,
                "account_label": account,
            },
        )
    finally:
        with contextlib.suppress(Exception):
            await call("probe_disarm", {"case_id": case_id})
    return {
        "file": file,
        "line": line,
        "arm": armed,
        "status": (run.get("http") or {}).get("status"),
        "queries": run.get("queries") or [],
    }


async def collect_read_sql(
    call: Call,
    *,
    case_id: str,
    url: str,
    sink_file: str,
    sink_line: int = 0,
    account: str = "",
) -> dict[str, Any]:
    """Trace the read path and return the SQL the engine executed."""

    files: list[str] = [sink_file]

    async def _directory_files(directory: str) -> list[str]:
        if not directory or directory in {".", ""}:
            return []
        found: list[str] = []
        with contextlib.suppress(Exception):
            grep = await call(
                "source_grep",
                {"pattern": r"<\?php", "path": directory, "glob": "*.php", "max": MAX_FILES},
            )
            for hit in grep.get("hits") or []:
                name = str(hit.get("file") or "")
                if name and name not in found:
                    found.append(name)
        return found

    # The sink lives under ``templates/``; the module that builds its query is
    # one level up. Look in both directories, never across the whole tree.
    directories = [Path(sink_file).parent.as_posix(), Path(sink_file).parent.parent.as_posix()]
    for directory in directories:
        for name in await _directory_files(directory):
            if name not in files:
                files.append(name)
    files = files[:MAX_FILES]
    window = max(sink_line + 40, 80)
    targets = [{"file": item, "line_from": 1, "line_to": max(window, WINDOW)} for item in files]
    result: dict[str, Any] = {
        "files": files,
        "trace_id": "",
        "executed": {},
        "statements": [],
        "probes": [],
    }
    trace = await call(
        "trace_run",
        {
            "case_id": case_id,
            "url": url,
            "targets": targets,
            "max_lines": 4000,
            "max_entries": 300,
            "account_label": account,
        },
    )
    result["trace_id"] = str(trace.get("trace_id") or "")
    from tia.cap.trace_view import slice_trace

    entries = trace.get("entries") or []
    result["trace"] = slice_trace(entries, sink_file=sink_file, sink_line=sink_line)
    executed: dict[str, list[int]] = {}
    for entry in trace.get("entries") or []:
        name = str(entry.get("file") or "")
        line = _line_number(entry.get("line"))
        if name and line:
            executed.setdefault(name, []).append(line)
    result["executed"] = {name: sorted(set(lines)) for name, lines in executed.items()}
    if not executed:
        return result

    for relative in files:
        absolute = next((name for name in executed if _same_file(name, relative)), "")
        if not absolute:
            continue
        try:
            source = await call(
                "source_read", {"file": relative, "line_from": 1, "line_to": max(window, WINDOW)}
            )
        except Exception:  # noqa: BLE001 - skip a file the reader cannot open
            continue
        text = {
            _line_number(item.get("n") or item.get("line")): str(item.get("text") or "")
            for item in source.get("lines") or []
        }
        for line in executed[absolute]:
            code = text.get(line, "")
            if not code or _QUERY_CALL.search(code) is None:
                continue
            if len(result["probes"]) >= MAX_PROBES:
                return result
            try:
                probe = await _probe_statement(
                    call, case_id=case_id, url=url, file=relative, line=line, account=account
                )
            except Exception as exc:  # noqa: BLE001 - one failed arm must not stop the scan
                result["probes"].append({"file": relative, "line": line, "error": str(exc)})
                continue
            result["probes"].append(probe)
            for query in probe.get("queries") or []:
                sql = str(query.get("sql") or "").strip()
                if sql and sql not in result["statements"]:
                    result["statements"].append(sql)
            if result["statements"]:
                return result
    return result
