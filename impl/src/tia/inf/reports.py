"""Run and case report files.

The agents already build a Markdown report per case; this module writes those
reports to disk while the run is in progress (one file per case, plus an index
for the run), so a finished run never needs a second pass over the database.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from tia.inf.runtime import peek_settings

REPORTS_ENV = "TIA_REPORTS"
TARGET_ENV = "TIA_REPORTS_TARGET"


def _safe(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in name)
    return cleaned.strip("-") or "case"


def target_name() -> str:
    """Directory that keeps one target's reports apart from every other target.

    ``TIA_REPORTS_TARGET`` wins, then the basename of the configured app root
    (``/app/PhoenixCart`` → ``PhoenixCart``), then ``default`` for plain unit
    tests that never start a runtime.
    """

    override = os.environ.get(TARGET_ENV, "").strip()
    if override:
        return _safe(override)
    app_root = os.environ.get("TIA_APP_ROOT", "").strip()
    if not app_root:
        settings = peek_settings()
        app_root = str(settings.app_root or "") if settings is not None else ""
    return _safe(Path(app_root).name) if app_root else "default"


def reports_root(store: Any) -> Path:
    """Where report files live: ``<base>/reports/<target>``.

    The base is ``TIA_REPORTS`` or ``<store dir>/reports``. Every target gets
    its own subdirectory, so a campaign that touches several applications
    never mixes their findings.
    """

    override = os.environ.get(REPORTS_ENV, "").strip()
    base = Path(override) if override else Path(store.path).parent / "reports"
    return base / target_name()


def write_case_report(store: Any, case_id: str, *, subdir: str = "cases") -> Path | None:
    """Persist the stored Markdown report of one case; returns its path."""

    row = store.get_case(case_id)
    if row is None:
        return None
    markdown = str(row.get("report") or "")
    if not markdown:
        return None
    directory = reports_root(store) / subdir
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{_safe(case_id)}.md"
    path.write_text(markdown, encoding="utf-8")
    return path


class RunReports:
    """Incremental report writer for one pipeline run."""

    def __init__(self, store: Any, run_id: str) -> None:
        self.store = store
        self.run_id = run_id
        self.directory = reports_root(store) / "runs" / _safe(run_id)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.index_path = self.directory / "index.md"
        self.rows: list[tuple[str, str, str, str]] = []
        self._write_header()

    def _write_header(self) -> None:
        line = f"# TIA run report: {self.run_id}\n\n| Stage | Case | Verdict | Slice |\n| --- | --- | --- | --- |\n"
        self.index_path.write_text(line, encoding="utf-8")

    def add(self, case_id: str, stage: str, verdict: str, label: str) -> Path | None:
        """Write the case report (if any) and append one row to the run index."""

        path = write_case_report(self.store, case_id, subdir=f"runs/{_safe(self.run_id)}/cases")
        link = f"[{case_id}](cases/{path.name})" if path is not None else case_id
        self.rows.append((stage, case_id, verdict, label))
        with self.index_path.open("a", encoding="utf-8") as handle:
            handle.write(f"| {stage} | {link} | {verdict} | {label} |\n")
        return path

    def finish(self, stop_reason: str, rounds: int, outcomes: int) -> Path:
        """Append the run summary; returns the index path."""

        counts: dict[str, int] = {}
        for _stage, _case, verdict, _label in self.rows:
            counts[verdict] = counts.get(verdict, 0) + 1
        summary = [
            "",
            "## Summary",
            "",
            f"- Stop reason: {stop_reason}",
            f"- Rounds: {rounds}",
            f"- Cases: {outcomes}",
            "",
            "| Verdict | Count |",
            "| --- | --- |",
        ]
        summary.extend(f"| {name} | {count} |" for name, count in sorted(counts.items()))
        with self.index_path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(summary) + "\n")
        return self.index_path
