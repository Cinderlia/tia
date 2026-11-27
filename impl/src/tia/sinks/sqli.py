"""SQL injection plugin (first cut).

The acceptance rules land in the SQLi phase; for now the class only declares
its channels and keeps the orchestration honest: a SQLi site is reached when
the database observable says our marker entered an executed statement, never
when the page merely contains the text.
"""

from __future__ import annotations

from typing import Any

from tia.sinks.base import Observation, Outcome


class SqliSinkClass:
    name = "sqli"
    site_kinds = frozenset({"SqlInjection", "SqlRead", "SqlWriteLoose"})

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
        return "string_literal"

    def seed(self, site: dict[str, Any], context: str, tag: str) -> list[str]:
        marker = f"tia{tag}"
        if context == "numeric":
            return [f"1 OR 1=1 -- {marker}"]
        if context == "order_by":
            return [f"(SELECT 1) -- {marker}"]
        return [f"' AND 1=1 -- {marker}", f"' OR '1'='1' -- {marker}"]

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
