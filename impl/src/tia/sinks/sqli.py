"""SQL injection plugin (first cut).

The acceptance rules land in the SQLi phase; for now the class only declares
its channels and keeps the orchestration honest: a SQLi site is reached when
the database observable says our marker entered an executed statement, never
when the page merely contains the text.
"""

from __future__ import annotations

import re
from typing import Any

from tia.sinks.base import Observation, Outcome


class SqliSinkClass:
    name = "sqli"
    site_kinds = frozenset({"SqlInjection", "SqlRead", "SqlWriteLoose"})

    def writes_database(self) -> bool:
        return False

    def observation_channel(self) -> str:
        return "sql_probe"

    def channels(self) -> frozenset[str]:
        return frozenset({"sql_probe", "page", "timing"})

    def context(self, site: dict[str, Any], code: str) -> str:
        text = code or str(site.get("sink") or "")
        lowered = text.lower()
        if "order by" in lowered:
            return "order_by"
        if "limit" in lowered:
            return "limit"
        if "like" in lowered:
            return "like_string"
        # ``= ".$item`` / ``= $item`` concatenates unquoted: the value lands as a
        # number, so the useful candidates are numeric, not quoted strings.
        if re.search(r"=\s*[\"']?\s*\.\s*\$", text) or re.search(r"=\s*\$\w+", text):
            return "numeric"
        return "string_literal"

    def shapes(self, context: str) -> list[str]:
        if context == "numeric":
            return ["numeric_or"]
        if context == "order_by":
            return ["order_by_subquery"]
        return ["quote_and", "quote_or"]

    def render(self, shape: str, tag: str) -> str:
        marker = f"tia{tag}"
        if shape == "numeric_or":
            return f"1 OR 1=1 -- {marker}"
        if shape == "order_by_subquery":
            return f"(SELECT 1) -- {marker}"
        if shape == "quote_or":
            return f"' OR '1'='1' -- {marker}"
        return f"' AND 1=1 -- {marker}"

    def seed(
        self,
        site: dict[str, Any],
        context: str,
        tag: str,
        payload_base: str = "",
    ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for shape in self.shapes(context):
            out.append((shape, self.render(shape, tag)))
        if payload_base:
            out.append(("custom", f"{payload_base}{tag}"))
        return out

    def accept(self, observation: Observation, context: str) -> Outcome:
        sql = observation.facts.get("sql_probe")
        evidence = [str(ref) for ref in observation.evidence_refs]
        if not isinstance(sql, dict):
            return Outcome(False, "NO_DB_OBSERVATION", "no database probe evidence", 0, evidence)
        executed = bool(sql.get("executed"))
        error = str(sql.get("error") or "")
        if executed and observation.marker_seen:
            return Outcome(True, "SQLI_CONFIRMED", "marker entered an executed statement", 80, evidence)
        if error and observation.marker_seen:
            return Outcome(True, "SQLI_CONFIRMED", f"database error: {error[:120]}", 70, evidence)
        return Outcome(False, "NOT_CONFIRMED", "the marker did not reach an executed statement", 20, evidence)

    def diagnose(self, observation: Observation, outcome: Outcome) -> list[str]:
        if outcome.level == "NO_DB_OBSERVATION":
            return ["no probe output; arm the probe at the query line before sending"]
        if outcome.level == "NOT_CONFIRMED":
            return ["the value was neutralized; adjust quoting, comment style or the injection position"]
        return []

    def priority(self, site: dict[str, Any]) -> int:
        code = str(site.get("sink") or "").lower()
        return 9 if "order by" in code or "limit" in code else 6
