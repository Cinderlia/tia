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
