"""Snapshot markers: an unrestored dump is detected and restored on the next run."""

from __future__ import annotations

from pathlib import Path

from tia.inf.config import DbConfig
from tia.inf.snapshot import (
    pending_path,
    pending_restore,
    restore_database,
    restore_pending,
    snapshot_database,
)

DB = DbConfig(name="Phoenix", user="tia_Phoenix", password="tia-dev-pass")


class _FakeRun:
    def __init__(self, stdout: bytes = b"", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode
        self.commands: list[list[str]] = []
        self.inputs: list[bytes | None] = []

    def __call__(self, command, **kwargs):  # type: ignore[no-untyped-def]
        self.commands.append(list(command))
        self.inputs.append(kwargs.get("input"))
        if "show tables" in command:
            return _Result(b"testimonials\ntestimonials_description\n")
        if command[0] == "mysqldump":
            return _Result(b"INSERT INTO `testimonials` VALUES (1,1);\n")
        return _Result(b"")


class _Result:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = b""
        self.returncode = returncode


def test_snapshot_leaves_a_pending_marker(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("tia.inf.snapshot.subprocess.run", _FakeRun())
    path = tmp_path / "before.sql"

    snapshot_database(DB, path)

    assert path.read_bytes().startswith(b"INSERT INTO")
    marker = pending_path(path)
    assert marker.is_file()
    data = pending_restore(path)
    assert data is not None
    assert data["db"] == "Phoenix"
    assert data["snapshot"] == str(path)
    assert data["created_at"]


def test_restore_clears_the_marker(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    fake = _FakeRun()
    monkeypatch.setattr("tia.inf.snapshot.subprocess.run", fake)
    path = tmp_path / "before.sql"
    snapshot_database(DB, path)

    restore_database(DB, path)

    assert not pending_path(path).exists()
    assert pending_restore(path) is None
    restore_script = fake.inputs[-1] or b""
    assert b"DELETE FROM `testimonials`;" in restore_script
    assert b"INSERT INTO `testimonials` VALUES (1,1);" in restore_script


def test_a_leftover_snapshot_is_restored_before_the_next_run(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("tia.inf.snapshot.subprocess.run", _FakeRun())
    path = tmp_path / "before.sql"
    snapshot_database(DB, path)

    pending = restore_pending(DB, path)

    assert pending is not None
    assert pending["db"] == "Phoenix"
    assert not pending_path(path).exists()
    assert restore_pending(DB, path) is None


def test_no_marker_means_nothing_to_restore(tmp_path: Path) -> None:
    path = tmp_path / "before.sql"
    path.write_bytes(b"SELECT 1;")

    assert pending_restore(path) is None
