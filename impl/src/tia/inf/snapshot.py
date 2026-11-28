"""Table-content snapshots and restores for test campaigns.

A case may update rows the application already holds (an approval switch, a
status flag). Those updates are correct for the proof but must not survive the
campaign, so every table's rows are saved before the run and put back
afterwards. Only DML is used (DELETE + INSERT), because the case account is
granted data privileges, not DDL.

A restore only runs when the process exits normally. If it is killed (Ctrl-C
twice, OOM, a closed terminal) the database keeps whatever the run changed.
The snapshot therefore leaves a pending marker next to the dump file: the next
campaign that is given the same snapshot path restores the leftover snapshot
before it starts, and ``tia-agent db-restore`` does the same on demand.
"""

from __future__ import annotations

import json
import subprocess
import time
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


def pending_path(path: Path) -> Path:
    """Marker that says "this dump has not been restored yet"."""

    path = Path(path)
    return path.with_name(path.name + ".pending.json")


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
    pending_path(path).write_text(
        json.dumps(
            {
                "db": db.name,
                "snapshot": str(path),
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
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
    pending_path(path).unlink(missing_ok=True)


def pending_restore(path: Path) -> dict[str, str] | None:
    """Describe the snapshot a previous run left unrestored, if any."""

    marker = pending_path(path)
    if not marker.is_file():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"db": "", "snapshot": str(path), "created_at": ""}
    if not isinstance(data, dict):
        return {"db": "", "snapshot": str(path), "created_at": ""}
    return {key: str(data.get(key, "")) for key in ("db", "snapshot", "created_at")}


def restore_pending(db: DbConfig, path: Path) -> dict[str, str] | None:
    """Restore the snapshot a previous run left behind, if there is one."""

    pending = pending_restore(path)
    if pending is None:
        return None
    restore_database(db, path)
    return pending
