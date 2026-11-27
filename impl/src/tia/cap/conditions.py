"""Read-side SQL conditions: the data a row must have before the page shows it.

A read path usually selects the row with a predicate such as
``WHERE t.testimonials_status = 1``. That predicate is part of reachability,
not of the payload: a row written by a low-privileged user does not satisfy it.
This module turns such predicates into plain, ordered facts so the flow plan can
ask for them and a replay step can satisfy them by a legal request.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SELECT = re.compile(r"\bselect\b", re.IGNORECASE)
_TABLE = re.compile(
    r"(?:from|join)\s+`?(\w+)`?(?:\s+(?:as\s+)?(\w+))?", re.IGNORECASE
)
_WHERE = re.compile(r"\bwhere\b(.{0,800})", re.IGNORECASE | re.DOTALL)
# col = 'value' | col = 123 | alias.col = 'value'
_EQUALITY = re.compile(
    r"(?:`?(\w+)`?\.)?`?(\w+)`?\s*=\s*(?:'([^']{0,80})'|\"([^\"]{0,80})\"|(\d{1,12}))"
)
# predicates that are never a fixed row value and must not become a constraint
_SKIP = re.compile(r"\b(like|regexp|is\s+null|is\s+not\s+null|in\s*\(|between)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Condition:
    """One equality the read path needs on a stored row."""

    table: str
    column: str
    value: str
    predicate: str
    at: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "table": self.table,
            "column": self.column,
            "value": self.value,
            "predicate": self.predicate,
            "at": self.at,
        }


def _strip_and(sql: str) -> list[str]:
    """Split a WHERE body on top-level AND, ignoring quoted text."""

    parts: list[str] = []
    current: list[str] = []
    quote = ""
    depth = 0
    i = 0
    while i < len(sql):
        ch = sql[i]
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif depth == 0 and sql[i : i + 3].upper() == "AND":
            parts.append("".join(current))
            current = []
            i += 3
            continue
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _statement_conditions(sql: str, tables: frozenset[str] | None) -> list[Condition]:
    found: list[Condition] = []
    for start in [match.start() for match in _SELECT.finditer(sql)]:
        statement = sql[start : start + 4000]
        aliases: dict[str, str] = {}
        for match in _TABLE.finditer(statement):
            aliases[match.group(2) or match.group(1)] = match.group(1)
        selected = tables or frozenset(aliases.values())
        if selected.isdisjoint(aliases.values()):
            continue
        where = _WHERE.search(statement)
        if where is None:
            continue
        for clause in _strip_and(where.group(1)):
            if _SKIP.search(clause):
                continue
            eq = _EQUALITY.search(clause)
            if eq is None:
                continue
            alias, column = eq.group(1), eq.group(2)
            owner = aliases.get(alias or "", "")
            if not owner:
                if len(selected) != 1:
                    continue
                owner = next(iter(selected))
            if owner not in selected:
                continue
            value = next(item for item in eq.groups()[2:] if item is not None)
            if value in {"", "null", "NULL"}:
                continue
            found.append(
                Condition(
                    table=owner,
                    column=column,
                    value=str(value),
                    predicate=clause.strip(),
                )
            )
    return found


def where_conditions(sql: str, table: str) -> list[Condition]:
    """Equality predicates the statement applies to ``table``."""

    return _statement_conditions(sql, frozenset({table}))


def statement_conditions(sql: str, at: str = "") -> list[Condition]:
    """Equality predicates of every statement, resolved to their owning tables."""

    return [
        Condition(item.table, item.column, item.value, item.predicate, at)
        for item in _statement_conditions(sql, None)
    ]


def conditions_in(source_text: str, at: str, table: str) -> list[Condition]:
    """Conditions of every statement in one source window."""

    return [
        Condition(item.table, item.column, item.value, item.predicate, at)
        for item in where_conditions(source_text, table)
    ]
