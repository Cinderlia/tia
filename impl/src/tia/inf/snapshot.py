"""Table-content snapshots and restores for test campaigns.

A case may update rows the application already holds (an approval switch, a
status flag). Those updates are correct for the proof but must not survive the
campaign, so every table's rows are saved before the run and put back
afterwards. Only DML is used (DELETE + INSERT), because the case account is
granted data privileges, not DDL.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tia.inf.config import DbConfig


def _base(db: DbConfig) -> list[str]:
    return ["-h", db.host, "-P", str(db.port), "-u", db.user, f"--password={db.password}"]


def _tables(db: DbConfig) -> list[str]:
    result = subprocess.run(  # noqa: S603
        ["mysql", *_base(db), "-N", "-B", "-e", "show tables", db.name],
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "cannot list tables: " + result.stderr.decode("utf-8", "replace").strip()
        )
    return [line.strip() for line in result.stdout.decode("utf-8").splitlines() if line.strip()]


def snapshot_database(db: DbConfig, path: Path) -> Path:
    """Write the rows of every table to ``path`` (INSERT statements only)."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "mysqldump",
        *_base(db),
        "--no-create-info",
        "--skip-triggers",
        "--skip-comments",
        "--compact",
        "--skip-add-locks",
        "--skip-extended-insert",
        "--single-transaction",
        db.name,
    ]
    result = subprocess.run(command, capture_output=True, timeout=300)  # noqa: S603
    if result.returncode != 0:
        raise RuntimeError(
            "mysqldump failed: " + result.stderr.decode("utf-8", "replace").strip()
        )
    path.write_bytes(result.stdout)
    return path


def restore_database(db: DbConfig, path: Path) -> None:
    """Empty every table and put the saved rows back."""

    tables = _tables(db)
    lines = ["SET FOREIGN_KEY_CHECKS=0;"]
    lines.extend(f"DELETE FROM `{table}`;" for table in tables)
    script = "\n".join(lines).encode("utf-8") + b"\n" + Path(path).read_bytes()
    result = subprocess.run(  # noqa: S603
        ["mysql", *_base(db), db.name],
        input=script,
        capture_output=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "mysql restore failed: " + result.stderr.decode("utf-8", "replace").strip()
        )
