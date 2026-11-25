"""Read-page entry derivation (shared by the trigger and inject agents).

A second-order read often needs its own request parameters: the row is only
rendered when the page receives e.g. ``search`` or ``id``. Those values are
*derived*, never guessed: the field comes from the read sink's source, its
usage from the surrounding SQL, and its value from the row the agent just
wrote (the tag identifies that row) or from the tag itself for substring
matches.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from tia.ad.llm import LlmClient

_POST_ARG_RE = re.compile(r"\$_POST\['([A-Za-z_][\w]*)'\]")
_GET_ARG_RE = re.compile(r"\$_GET\['([A-Za-z_][\w]*)'\]")
_LIKE_RE = re.compile(r"like\b", re.IGNORECASE)
_CAST_RE = re.compile(r"\b(?:intval|\(int\)|\(float\)|floatval)\b", re.IGNORECASE)

Usage = Literal["contains", "exact", "unknown"]


@dataclass(frozen=True)
class EntryField:
    """One read-page parameter and how the page compares it."""

    name: str
    usage: Usage
    numeric: bool = False


def entry_field(item: dict[str, Any]) -> EntryField:
    """Normalise a serialised entry field (from a slice or a previous agent)."""
    usage = str(item.get("usage") or "unknown")
    if usage not in ("contains", "exact", "unknown"):
        usage = "unknown"
    return EntryField(
        name=str(item.get("name") or ""),
        usage=cast(Usage, usage),
        numeric=bool(item.get("numeric")),
    )


def infer_read_entry(source_text: str, *, require_where: bool = True) -> tuple[str, list[EntryField]]:
    """Infer the read page's method and parameter list from its source.

    ``contains`` fields are compared with ``LIKE``; the tag itself is a valid
    value because the written row contains it. ``exact`` fields need a real
    value from the row that was written.
    """
    if require_where and not re.search(r"\bwhere\b", source_text, re.IGNORECASE):
        # A page whose query has no filter renders every row already; sending
        # its form fields would turn a read into an unwanted write.
        return "GET", []
    posts = sorted(set(_POST_ARG_RE.findall(source_text)))
    gets = sorted(set(_GET_ARG_RE.findall(source_text)))
    fields = posts or gets
    if not fields:
        return "GET", []
    lines = source_text.splitlines()
    result: list[EntryField] = []
    for name in fields:
        usage: Usage = "unknown"
        numeric = False
        for line in lines:
            if name not in line:
                continue
            if _LIKE_RE.search(line):
                usage = "contains"
            elif "=" in line and usage == "unknown":
                usage = "exact"
            if _CAST_RE.search(line) and name in line:
                numeric = True
        result.append(EntryField(name=name, usage=usage, numeric=numeric))
    return ("POST" if posts else "GET"), result


def resolve_values_detailed(
    fields: list[EntryField],
    *,
    tag: str,
    row: dict[str, Any] | None,
    pk_columns: list[str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Values plus per-field evidence: ``tag`` / ``row`` / ``fallback``."""
    values: dict[str, str] = {}
    basis: dict[str, str] = {}
    pk_value: Any = None
    if row and pk_columns:
        pk_value = row.get(pk_columns[0])
    for field in fields:
        if field.usage == "contains":
            values[field.name] = tag
            basis[field.name] = "tag"
        elif field.usage == "exact" and pk_value not in (None, ""):
            values[field.name] = str(pk_value)
            basis[field.name] = "row"
        elif field.usage == "exact" and row:
            values[field.name] = str(next(iter(row.values()), tag))
            basis[field.name] = "row"
        else:
            # No evidence in the source or the written row: a guess may still
            # be right and the next request will prove or disprove it.
            basis[field.name] = "fallback"
    return values, basis


def resolve_values(
    fields: list[EntryField],
    *,
    tag: str,
    row: dict[str, Any] | None,
    pk_columns: list[str],
) -> dict[str, str]:
    """Fill every entry field from the written row (keyed by the tag) or the tag."""
    values, _ = resolve_values_detailed(fields, tag=tag, row=row, pk_columns=pk_columns)
    for field in fields:
        values.setdefault(field.name, tag)
    return values


async def resolve_values_with_guess(
    fields: list[EntryField],
    *,
    tag: str,
    row: dict[str, Any] | None,
    pk_columns: list[str],
    context: str = "",
    client: LlmClient | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve entry values from evidence, then let a model guess what is left."""
    values, basis = resolve_values_detailed(fields, tag=tag, row=row, pk_columns=pk_columns)
    missing = [field for field in fields if basis.get(field.name) == "fallback"]
    if not missing or client is None:
        for field in fields:
            values.setdefault(field.name, tag)
        return values, basis
    guessed = await _guess(client, missing, context=context, tag=tag, row=row)
    for field in missing:
        value = str(guessed.get(field.name) or "").strip()
        if value:
            values[field.name] = value
            basis[field.name] = "guessed"
        else:
            values[field.name] = tag
    return values, basis


async def _guess(
    client: LlmClient,
    fields: list[EntryField],
    *,
    context: str,
    tag: str,
    row: dict[str, Any] | None,
) -> dict[str, str]:
    """Ask the model for plausible values; any failure yields no guess."""
    system = (
        "You fill request parameters for a PHP web page so that a known row is rendered. "
        "Return ONLY a JSON object like {\"values\": {\"param\": \"value\"}}. "
        "Use legal, short values; numeric fields must be numbers without quotes."
    )
    user = json.dumps(
        {
            "parameters": [
                {"name": field.name, "usage": field.usage, "numeric": field.numeric} for field in fields
            ],
            "tag": tag,
            "written_row": row,
            "source_context": context[:4000],
        },
        ensure_ascii=False,
    )
    reply = await client.complete_json(system, user)
    raw = reply.get("values")
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


_WRITE_SQL_RE = re.compile(r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.IGNORECASE)


@dataclass(frozen=True)
class EntryPlan:
    """Static prior for reaching a read page.

    ``has_filter``/``mutating`` describe the request shape, they do **not** decide
    whether a candidate is allowed: exploration still tries candidates in order and
    lets the observed page accept or reject them.
    """

    method: str
    fields: list[EntryField]
    has_filter: bool
    mutating: bool


@dataclass(frozen=True)
class EntryCandidate:
    """One ordered attempt at the read page, with its evidence."""

    method: str
    values: dict[str, str]
    confidence: int
    basis: dict[str, str]


def infer_entry(source_text: str) -> EntryPlan:
    """Build the static prior for the read page."""
    has_filter = bool(re.search(r"\bwhere\b", source_text, re.IGNORECASE))
    method, fields = infer_read_entry(source_text, require_where=False)
    return EntryPlan(
        method=method,
        fields=fields,
        has_filter=has_filter,
        mutating=bool(_WRITE_SQL_RE.search(source_text)),
    )


async def entry_candidates(
    plan: EntryPlan,
    *,
    tag: str,
    row: dict[str, Any] | None,
    pk_columns: list[str],
    context: str = "",
    client: LlmClient | None = None,
    limit: int = 3,
) -> list[EntryCandidate]:
    """Ranked attempts for reaching the read page.

    Strong evidence first (row values / tag), weak but related evidence last.
    A page without a filter needs no parameters at all; a page that also writes
    is only ever probed with a read-only request shape.
    """
    if not plan.has_filter:
        return [EntryCandidate("GET", {}, 55, {"_": "no-filter"})]
    if not plan.fields:
        return [EntryCandidate("GET", {}, 40, {"_": "no-fields"})]
    method = "GET" if plan.mutating else plan.method
    values, basis = await resolve_values_with_guess(
        plan.fields,
        tag=tag,
        row=row,
        pk_columns=pk_columns,
        context=context,
        client=client,
    )
    candidates = [EntryCandidate(method, dict(values), 75, dict(basis))]
    tag_only = {field.name: tag for field in plan.fields}
    if tag_only != values:
        candidates.append(
            EntryCandidate(method, tag_only, 45, {field.name: "tag" for field in plan.fields})
        )
    if any(field.numeric for field in plan.fields):
        numeric = dict(values)
        numeric_basis = dict(basis)
        for field in plan.fields:
            if field.numeric:
                numeric[field.name] = "1"
                numeric_basis[field.name] = "numeric-min"
        candidates.append(EntryCandidate(method, numeric, 35, numeric_basis))
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    ranked: list[EntryCandidate] = []
    for candidate in candidates:
        key = (candidate.method, tuple(sorted(candidate.values.items())))
        if key in seen:
            continue
        seen.add(key)
        ranked.append(candidate)
    return ranked[: max(1, limit)]


def derive_payload_constraints(
    verify: dict[str, Any] | None,
    *,
    column: str | None,
    column_length: int | None,
    payload: str,
) -> dict[str, Any]:
    """Summarise what the inject agent needs to know about the output side.

    The trigger agent can see the sink context but not the input-side filter; the
    inject agent sees the form but not the sink. This object carries the facts
    from the trigger side to the injection side.
    """
    best = (verify or {}).get("best") or {}
    return {
        "column": column,
        "max_length": column_length,
        "payload_length": len(payload),
        "context_kind": best.get("context_kind"),
        "quoting": best.get("quoting"),
        "executable": best.get("executable"),
        "executable_reason": best.get("executable_reason"),
        "match_kind": best.get("match_kind"),
        "requires_breakout": str(best.get("quoting") or "").lower() not in ("", "none"),
        "node_path": best.get("node_path"),
    }
