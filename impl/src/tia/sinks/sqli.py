"""SQL injection plugin (first cut).

The acceptance rules land in the SQLi phase; for now the class only declares
its channels and keeps the orchestration honest: a SQLi site is reached when
the database observable says our marker entered an executed statement, never
when the page merely contains the text.
"""

from __future__ import annotations

import re
from typing import Any

from tia.cap.blind import BLIND_DELAY_S
from tia.sinks.base import Observation, Outcome


class SqliSinkClass:
    name = "sqli"
    site_kinds = frozenset({"SqlInjection", "SqlRead", "SqlWriteLoose"})

    def writes_database(self) -> bool:
        return False

    def observation_channel(self) -> str:
        return "sql_probe"

    def channels(self) -> frozenset[str]:
        return frozenset({"sql_probe", "page", "timing", "blind"})

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

    def blind_pairs(self, context: str, tag: str) -> list[tuple[str, str, str]]:
        """(kind, true_payload, false_payload) candidates for blind acceptance.

        Both payloads carry the tag in a trailing comment so the probe can tell
        whether the engine executed them at all before any differential counts.
        """
        marker = f"tia{tag}"
        if context == "numeric":
            return [
                ("boolean", f"1 AND 1=1 -- {marker}", f"1 AND 1=2 -- {marker}"),
                ("time", f"1 AND SLEEP({BLIND_DELAY_S:g}) -- {marker}", f"1 AND SLEEP(0) -- {marker}"),
            ]
        return [
            ("boolean", f"' AND 1=1 -- {marker}", f"' AND 1=2 -- {marker}"),
            ("time", f"' AND SLEEP({BLIND_DELAY_S:g}) -- {marker}", f"' AND SLEEP(0) -- {marker}"),
        ]

    def accept(self, observation: Observation, context: str) -> Outcome:
        blind = observation.facts.get("blind")
        if observation.channel == "blind" and isinstance(blind, dict):
            evidence = [str(ref) for ref in observation.evidence_refs]
            if bool(blind.get("confirmed")) and bool(blind.get("diagnosis")):
                return Outcome(
                    True,
                    "SQLI_BLIND",
                    "boolean/time differential after the probe diagnosis",
                    75,
                    evidence,
                )
            return Outcome(
                False,
                "NOT_CONFIRMED",
                "no blind differential reached the engine",
                15,
                evidence,
            )
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
