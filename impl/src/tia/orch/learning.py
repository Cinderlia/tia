"""Cross-family learning.

First- and second-order slices are searched by two different agents, but a site
is one site. Every finished case leaves a small, cheap prior keyed by the sink
location (and its parent area): which payload shapes actually executed there,
which way the entry page reads, and how often the site yielded a verdict.

Both families read the same table and write to it, so a success discovered by
the direct agent is available to the next injection candidate at the same site
and vice versa. The prior only reorders work (queue score, shape order, payload
choice); it never decides a verdict.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

SUCCESS_VERDICTS = {"EXECUTED", "EXECUTABLE"}


def _sink_file(raw: dict[str, Any]) -> str:
    sink_value = raw.get("sink")
    sink: dict[str, Any] = sink_value if isinstance(sink_value, dict) else {}
    return str(sink.get("file") or raw.get("sinkFile") or "")


def site_keys(raw: dict[str, Any]) -> tuple[str, str]:
    """(file signature, area signature) for a slice; both empty without a sink."""
    parts = [part for part in PurePosixPath(_sink_file(raw).lstrip("./")).parts if part not in ("", ".")]
    if not parts:
        return "", ""
    file_key = "/".join(parts[-3:])
    area_key = "/".join(parts[-3:-1]) if len(parts) >= 2 else file_key
    return file_key, area_key


def record_case(
    store: Any,
    raw: dict[str, Any],
    verdict: str,
    notes: dict[str, Any] | None,
    *,
    shape: str | None = None,
) -> None:
    """Best-effort: never let learning break a case."""
    try:
        file_key, area_key = site_keys(raw)
        if not file_key or store is None:
            return
        notes = notes or {}
        ok = str(verdict) in SUCCESS_VERDICTS
        attempts_value = notes.get("attempts") or notes.get("verify_attempts") or []
        attempts: list[Any] = attempts_value if isinstance(attempts_value, list) else []
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            name = str(attempt.get("shape") or shape or "")
            if not name:
                continue
            success = bool(attempt.get("executable"))
            store.bump_learning(file_key, "shape", name, success)
            context_kind = str(attempt.get("context_kind") or "")
            if success and context_kind:
                store.bump_learning(file_key, "context", context_kind, True)
        entry_value = notes.get("entry")
        entry: dict[str, Any] = entry_value if isinstance(entry_value, dict) else {}
        fields_value = entry.get("fields")
        for name in fields_value if isinstance(fields_value, list) else []:
            store.bump_learning(file_key, "entry_field", str(name), ok)
        store.bump_learning(file_key, "verdict", str(verdict), ok)
    except Exception:  # noqa: BLE001 - the prior is optional
        return


def _merge(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    merged: dict[tuple[str, str], dict[str, int]] = {}
    for row in rows:
        key = (str(row["attribute"]), str(row["value"]))
        item = merged.setdefault(key, {"successes": 0, "failures": 0})
        item["successes"] += int(row["successes"])
        item["failures"] += int(row["failures"])
    return merged


def hints_for(store: Any, raw: dict[str, Any]) -> dict[str, Any]:
    """Aggregated prior for a slice: shape order, entry fields, case statistics."""
    try:
        file_key, area_key = site_keys(raw)
        if not file_key or store is None:
            return {}
        # One row set per exact site: both families share the same sink file.
        rows = store.learning_rows(file_key)
    except Exception:  # noqa: BLE001
        return {}
    merged = _merge(rows)
    verdict_rows = [item for (attr, _), item in merged.items() if attr == "verdict"]
    win = sum(item["successes"] for item in verdict_rows)
    lose = sum(item["failures"] for item in verdict_rows)
    shapes: list[tuple[str, int, int]] = []
    contexts: list[tuple[str, int]] = []
    fields: list[tuple[str, int, int]] = []
    for (attribute, value), item in merged.items():
        if attribute == "shape":
            shapes.append((value, item["successes"], item["failures"]))
        elif attribute == "context":
            contexts.append((value, item["successes"]))
        elif attribute == "entry_field":
            fields.append((value, item["successes"], item["failures"]))
    preferred = [value for value, ok, bad in sorted(shapes, key=lambda it: (-it[1], it[2])) if ok > 0 and ok >= bad]
    avoid = [value for value, ok, bad in shapes if ok == 0 and bad >= 2]
    return {
        "signature": file_key,
        "area": area_key,
        "successes": win,
        "failures": lose,
        "preferred_shapes": preferred,
        "avoid_shapes": avoid,
        "contexts": [value for value, ok in sorted(contexts, key=lambda it: -it[1]) if ok > 0],
        "entry_fields": [value for value, ok, bad in sorted(fields, key=lambda it: (-it[1], it[2])) if ok > 0],
    }


def score_delta(hints: dict[str, Any]) -> tuple[int, list[str]]:
    """Queue-score adjustment from cross-family evidence; zero without history."""
    successes = int(hints.get("successes") or 0)
    failures = int(hints.get("failures") or 0)
    cases = successes + failures
    if cases < 2:
        return 0, []
    signature = str(hints.get("signature") or "")
    if successes >= 1 and successes * 2 >= cases:
        return 10, [f"cross-family prior: {successes}/{cases} earlier cases succeeded at {signature}"]
    if successes == 0 and cases >= 3:
        return -10, [f"cross-family prior: {cases} earlier cases failed at {signature}"]
    return 0, []


def order_shapes(shapes: list[str], hints: dict[str, Any] | None) -> list[str]:
    """Learned shapes first, unknown shapes in code order, known-bad ones last."""
    if not hints:
        return list(shapes)
    preferred = [name for name in hints.get("preferred_shapes") or [] if name in shapes]
    avoid = {name for name in hints.get("avoid_shapes") or []}
    rest = [name for name in shapes if name not in preferred and name not in avoid]
    tail = [name for name in shapes if name in avoid]
    return [*preferred, *rest, *tail]


def preferred_payload_shape(hints: dict[str, Any] | None, context_kind: str | None) -> str | None:
    """First learned, context-compatible shape, if any."""
    if not hints:
        return None
    from tia.sinks.registry import sink_class_for

    known = sink_class_for("Xss").shapes(context_kind or "html_text")
    candidates = [name for name in hints.get("preferred_shapes") or [] if name in known]
    return candidates[0] if candidates else None
