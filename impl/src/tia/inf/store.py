"""Project-local storage (sqlite).

Tables: case / change / evidence / flow / probe / session (the six tables from T04),
plus a slice table for the main agent's queue. All writes include ``case_id`` and ``observed_at``,
for report reconstruction (H10).

Connections are not shared across threads: ``Store`` opens a short-lived connection per operation (sqlite is small, fast enough),
also avoiding connection conflicts between async handlers.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_file (
    id            TEXT PRIMARY KEY,
    agent         TEXT NOT NULL,
    slice_id      TEXT,
    slice_json    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    write_targets TEXT NOT NULL DEFAULT '[]',
    notes         TEXT NOT NULL DEFAULT '{}',
    verdict       TEXT,
    verdict_ceiling TEXT,
    report        TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS change (
    id          TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL,
    agent       TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    op          TEXT NOT NULL,
    sql         TEXT NOT NULL,
    undo_sql    TEXT NOT NULL,
    affected    INTEGER NOT NULL DEFAULT 0,
    before_image TEXT NOT NULL DEFAULT '[]',
    after_image TEXT NOT NULL DEFAULT '[]',
    reverted    INTEGER NOT NULL DEFAULT 0,
    seq         INTEGER NOT NULL,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_case ON change(case_id, seq);
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    ref         TEXT NOT NULL,
    tool        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(case_id, kind, seq)
);
CREATE TABLE IF NOT EXISTS flow (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    body        TEXT NOT NULL,
    code_ver    TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS probe (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    probe_id    TEXT NOT NULL,
    mode        TEXT NOT NULL,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'armed',
    body        TEXT NOT NULL,
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session (
    id          TEXT PRIMARY KEY,
    case_id     TEXT,
    base_url    TEXT NOT NULL,
    cookies     TEXT NOT NULL DEFAULT '{}',
    headers     TEXT NOT NULL DEFAULT '{}',
    valid       INTEGER NOT NULL DEFAULT 1,
    expires_at  TEXT,
    observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS slice (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    sink_file   TEXT NOT NULL,
    sink_line   INTEGER NOT NULL,
    slice_json  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    attempts    INTEGER NOT NULL DEFAULT 0,
    verdict     TEXT,
    notes       TEXT NOT NULL DEFAULT '',
    score       INTEGER NOT NULL DEFAULT 0,
    reasons     TEXT NOT NULL DEFAULT '[]',
    digest      TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pair_hint (
    pair_id       TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    read_slice_id TEXT NOT NULL,
    write_slice_id TEXT NOT NULL,
    table_name    TEXT NOT NULL DEFAULT '',
    columns       TEXT NOT NULL DEFAULT '[]',
    confidence    INTEGER NOT NULL DEFAULT 0,
    direction     TEXT NOT NULL DEFAULT 'unknown',
    reasons       TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pair_run ON pair_hint (run_id);
CREATE TABLE IF NOT EXISTS injection_queue (
    item_id        TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL,
    rank           INTEGER NOT NULL DEFAULT 0,
    write_slice_id TEXT NOT NULL,
    read_slice_id  TEXT NOT NULL,
    pair_id        TEXT NOT NULL,
    table_name     TEXT NOT NULL DEFAULT '',
    columns        TEXT NOT NULL DEFAULT '[]',
    score          INTEGER NOT NULL DEFAULT 0,
    direction      TEXT NOT NULL DEFAULT '',
    reasons        TEXT NOT NULL DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'pending',
    verdict        TEXT NOT NULL DEFAULT '',
    case_id        TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_injection_run ON injection_queue (run_id, status, rank);
CREATE TABLE IF NOT EXISTS tool_trace (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    slice_id    TEXT,
    agent       TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    tool        TEXT NOT NULL,
    arguments   TEXT NOT NULL DEFAULT '{}',
    ok          INTEGER NOT NULL DEFAULT 1,
    cost_ms     INTEGER NOT NULL DEFAULT 0,
    summary     TEXT NOT NULL DEFAULT '{}',
    error_code  TEXT,
    raw_path    TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_trace_case ON tool_trace(case_id, seq);
CREATE INDEX IF NOT EXISTS idx_tool_trace_slice ON tool_trace(slice_id, id);
"""


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def migrate(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(slice)")}
            for name, ddl in (
                ("score", "ALTER TABLE slice ADD COLUMN score INTEGER NOT NULL DEFAULT 0"),
                ("reasons", "ALTER TABLE slice ADD COLUMN reasons TEXT NOT NULL DEFAULT '[]'"),
                ("digest", "ALTER TABLE slice ADD COLUMN digest TEXT NOT NULL DEFAULT '{}'"),
                ("order_mode", "ALTER TABLE slice ADD COLUMN order_mode TEXT NOT NULL DEFAULT 'second'"),
            ):
                if name not in columns:
                    conn.execute(ddl)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- case -------------------------------------------------------------

    def open_case(self, agent: str, slice_json: dict[str, Any], write_targets: list[dict[str, Any]]) -> str:
        case_id = f"case-{uuid.uuid4().hex[:12]}"
        slice_id = str(slice_json.get("slice_id") or "").strip() or None
        ts = now_iso()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO case_file (id, agent, slice_id, slice_json, write_targets, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (case_id, agent, slice_id, json.dumps(slice_json, ensure_ascii=False),
                 json.dumps(write_targets, ensure_ascii=False), ts, ts),
            )
        return case_id

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM case_file WHERE id=?", (case_id,)).fetchone()
        return dict(row) if row else None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM case_file ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def write_targets(self, case_id: str) -> list[dict[str, Any]]:
        case = self.get_case(case_id)
        if not case:
            return []
        loaded = json.loads(case["write_targets"])
        return [t for t in loaded if isinstance(t, dict)]

    def set_case_verdict(
        self, case_id: str, verdict: str, *, ceiling: str | None = None, report: str | None = None
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE case_file SET verdict=?, verdict_ceiling=COALESCE(?, verdict_ceiling),"
                " report=COALESCE(?, report), status='closed', updated_at=? WHERE id=?",
                (verdict, ceiling, report, now_iso(), case_id),
            )

    def set_write_targets(self, case_id: str, targets: list[dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE case_file SET write_targets=?, updated_at=? WHERE id=?",
                (json.dumps(targets, ensure_ascii=False), now_iso(), case_id),
            )

    def add_note(self, case_id: str, key: str, value: Any) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT notes FROM case_file WHERE id=?", (case_id,)).fetchone()
            if row is None:
                raise KeyError(case_id)
            notes: dict[str, Any] = json.loads(row["notes"])
            notes[key] = value
            conn.execute(
                "UPDATE case_file SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(notes, ensure_ascii=False), now_iso(), case_id),
            )
        return len(notes)

    def case_notes(self, case_id: str) -> dict[str, Any]:
        case = self.get_case(case_id)
        return json.loads(case["notes"]) if case else {}

    # -- evidence ---------------------------------------------------------

    def add_evidence(
        self, case_id: str, kind: str, tool: str, payload: Any
    ) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM evidence WHERE case_id=? AND kind=?",
                (case_id, kind),
            ).fetchone()
            seq = int(row["s"]) + 1
            ref = f"ev://{case_id}/{kind}/{seq}"
            conn.execute(
                "INSERT INTO evidence (case_id, seq, kind, ref, tool, payload, observed_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (case_id, seq, kind, ref, tool, json.dumps(payload, ensure_ascii=False, default=str), now_iso()),
            )
        return ref

    def list_evidence(self, case_id: str) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE case_id=? ORDER BY kind, seq", (case_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- change -----------------------------------------------------------

    def add_change(self, change: dict[str, Any]) -> None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM change WHERE case_id=?", (change["case_id"],)
            ).fetchone()
            seq = int(row["s"]) + 1
            conn.execute(
                "INSERT INTO change (id, case_id, agent, table_name, op, sql, undo_sql, affected,"
                " before_image, after_image, seq, observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    change["change_id"], change["case_id"], change["agent"], change["table"],
                    change["op"], change["sql"], change["undo_sql"], change["affected"],
                    json.dumps(change["before_image"], ensure_ascii=False, default=str),
                    json.dumps(change["after_image"], ensure_ascii=False, default=str),
                    seq, change["ts"],
                ),
            )

    def get_change(self, change_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM change WHERE id=?", (change_id,)).fetchone()
        return dict(row) if row else None

    def list_changes(self, case_id: str, *, pending_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM change WHERE case_id=?"
        if pending_only:
            sql += " AND reverted=0"
        sql += " ORDER BY seq"
        with self._conn() as conn:
            rows = conn.execute(sql, (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def mark_change_reverted(self, change_id: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE change SET reverted=1 WHERE id=?", (change_id,))

    # -- flow -------------------------------------------------------------

    def list_flows(
        self, kind: str | None = None, base_url: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Read flow library summary; base_url filtering is done at the Python layer, with a scan limit of 500 rows."""
        sql = "SELECT case_id, seq, kind, body, code_ver, observed_at FROM flow"
        args: list[Any] = []
        if kind:
            sql += " WHERE kind=?"
            args.append(kind)
        sql += " ORDER BY id DESC LIMIT 500"
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                body = json.loads(row["body"])
            except json.JSONDecodeError:
                continue
            if base_url and body.get("base_url") not in (None, base_url):
                continue
            result.append(
                {
                    "case_id": row["case_id"],
                    "seq": row["seq"],
                    "kind": row["kind"],
                    "base_url": body.get("base_url"),
                    "steps": body.get("steps", []),
                    "code_ver": row["code_ver"],
                    "observed_at": row["observed_at"],
                }
            )
            if len(result) >= limit:
                break
        return result

    def add_probe(
        self,
        case_id: str,
        *,
        probe_id: str,
        mode: str,
        target: dict[str, Any],
        status: str,
        body: dict[str, Any],
    ) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM probe WHERE case_id=?", (case_id,)
            ).fetchone()
            seq = int(row["s"]) + 1
            conn.execute(
                "INSERT INTO probe (case_id, seq, probe_id, mode, target, status, body, observed_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    case_id,
                    seq,
                    probe_id,
                    mode,
                    json.dumps(target, ensure_ascii=False),
                    status,
                    json.dumps(body, ensure_ascii=False),
                    now_iso(),
                ),
            )
        return seq

    # -- tool trace / slice experience -------------------------------------

    def add_tool_trace(
        self,
        *,
        case_id: str,
        slice_id: str | None,
        agent: str,
        tool: str,
        arguments: dict[str, Any],
        ok: bool,
        cost_ms: int,
        summary: dict[str, Any],
        error_code: str | None,
        observed_at: str,
    ) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM tool_trace WHERE case_id=?", (case_id,)
            ).fetchone()
            seq = int(row["s"]) + 1
            conn.execute(
                "INSERT INTO tool_trace (case_id, slice_id, agent, seq, tool, arguments, ok,"
                " cost_ms, summary, error_code, observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    case_id,
                    slice_id,
                    agent,
                    seq,
                    tool,
                    json.dumps(arguments, ensure_ascii=False),
                    1 if ok else 0,
                    cost_ms,
                    json.dumps(summary, ensure_ascii=False),
                    error_code,
                    observed_at,
                ),
            )
        return seq

    def set_tool_trace_raw(self, *, case_id: str, seq: int, raw_path: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE tool_trace SET raw_path=? WHERE case_id=? AND seq=?", (raw_path, case_id, seq)
            )

    def list_tool_trace(
        self,
        *,
        case_id: str | None = None,
        slice_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM tool_trace WHERE 1=1"
        params: list[Any] = []
        if case_id:
            query += " AND case_id=?"
            params.append(case_id)
        if slice_id:
            query += " AND slice_id=?"
            params.append(slice_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["arguments"] = json.loads(item["arguments"] or "{}")
            item["summary"] = json.loads(item["summary"] or "{}")
            item["ok"] = bool(item["ok"])
            result.append(item)
        return result

    def slice_experience(self, slice_id: str, limit: int = 12) -> list[dict[str, Any]]:
        """Summarised attempts for one slice, newest first; never the raw return."""
        rows = self.list_tool_trace(slice_id=slice_id, limit=limit)
        return [
            {
                "tool": row["tool"],
                "agent": row["agent"],
                "ok": row["ok"],
                "summary": row["summary"],
                "error": row["error_code"],
                "at": row["observed_at"],
            }
            for row in rows
        ]

    def add_flow(self, case_id: str, kind: str, body: dict[str, Any], code_ver: str = "") -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS s FROM flow WHERE case_id=?", (case_id,)
            ).fetchone()
            seq = int(row["s"]) + 1
            conn.execute(
                "INSERT INTO flow (case_id, seq, kind, body, code_ver, observed_at) VALUES (?,?,?,?,?,?)",
                (case_id, seq, kind, json.dumps(body, ensure_ascii=False), code_ver, now_iso()),
            )
        return seq

    # -- slice queue -------------------------------------------------------

    def seed_slices(
        self, run_id: str, slices: list[dict[str, Any]], *, order_mode: str = "second"
    ) -> list[str]:
        """Insert slices, de-duplicating on (sink_file, sink_line); returns the pending ids."""
        seeded: list[str] = []
        ts = now_iso()
        for raw in slices:
            raw_sink = raw.get("sink")
            sink: dict[str, Any] = raw_sink if isinstance(raw_sink, dict) else {}
            sink_file = str(sink.get("file") or raw.get("sinkFile") or "")
            sink_line = int(sink.get("line") or raw.get("sinkLine") or 0)
            if not sink_file:
                continue
            slice_id = str(raw.get("slice_id") or f"slice-{uuid.uuid4().hex[:8]}")
            with self._conn() as conn:
                exists = conn.execute(
                    "SELECT id FROM slice WHERE run_id=? AND sink_file=? AND sink_line=?"
                    " AND status IN ('pending','running')",
                    (run_id, sink_file, sink_line),
                ).fetchone()
                if exists is not None:
                    seeded.append(str(exists["id"]))
                    continue
                conn.execute(
                    "INSERT INTO slice (id, run_id, kind, sink_file, sink_line, slice_json,"
                    " order_mode, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        slice_id,
                        run_id,
                        str(raw.get("kind") or "unknown"),
                        sink_file,
                        sink_line,
                        json.dumps(raw, ensure_ascii=False),
                        order_mode,
                        ts,
                        ts,
                    ),
                )
            seeded.append(slice_id)
        return seeded

    def next_slice(
        self,
        ttl_minutes: int = 30,
        run_id: str | None = None,
        order_mode: str | None = None,
    ) -> dict[str, Any] | None:
        """Lease the next pending slice; running slices older than the TTL return to pending."""
        self.requeue_expired(ttl_minutes)
        sql = "SELECT id FROM slice WHERE status='pending'"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if order_mode:
            sql += " AND order_mode=?"
            args.append(order_mode)
        sql += " ORDER BY score DESC, attempts, kind, sink_file, sink_line LIMIT 1"
        with self._conn() as conn:
            row = conn.execute(sql, tuple(args)).fetchone()
            if row is None:
                return None
            slice_id = str(row["id"])
            conn.execute(
                "UPDATE slice SET status='running', attempts=attempts+1, updated_at=? WHERE id=?",
                (now_iso(), slice_id),
            )
            fresh = conn.execute("SELECT * FROM slice WHERE id=?", (slice_id,)).fetchone()
        loaded = dict(fresh)
        loaded["slice"] = json.loads(loaded.pop("slice_json"))
        return loaded

    def count_pending(self, run_id: str, order_mode: str | None = None) -> int:
        """Pending slices left in the run, optionally for one order mode."""
        sql = "SELECT COUNT(*) AS n FROM slice WHERE status='pending' AND run_id=?"
        args: list[Any] = [run_id]
        if order_mode:
            sql += " AND order_mode=?"
            args.append(order_mode)
        with self._conn() as conn:
            row = conn.execute(sql, tuple(args)).fetchone()
        return int(row["n"])

    def requeue_expired(self, ttl_minutes: int = 30) -> int:
        cutoff = datetime.now().astimezone().timestamp() - ttl_minutes * 60
        requeued = 0
        with self._conn() as conn:
            rows = conn.execute("SELECT id, updated_at FROM slice WHERE status='running'").fetchall()
            for row in rows:
                try:
                    updated = datetime.fromisoformat(str(row["updated_at"]))
                except ValueError:
                    continue
                if updated.timestamp() < cutoff:
                    conn.execute(
                        "UPDATE slice SET status='pending', updated_at=? WHERE id=?",
                        (now_iso(), row["id"]),
                    )
                    requeued += 1
        return requeued

    def archive_slice(self, slice_id: str, verdict: str, *, case_id: str = "", notes: str = "") -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE slice SET status='executed', verdict=?, notes=?, updated_at=? WHERE id=?",
                (verdict, notes or case_id, now_iso(), slice_id),
            )
            return cursor.rowcount > 0

    def skip_slice(self, slice_id: str, reason: str, *, status: str = "skipped") -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE slice SET status=?, notes=?, updated_at=? WHERE id=?",
                (status, reason, now_iso(), slice_id),
            )
            return cursor.rowcount > 0

    def list_slices(self, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT id, run_id, kind, sink_file, sink_line, status, attempts, verdict, notes, score FROM slice"
        args: tuple[Any, ...] = ()
        if status:
            sql += " WHERE status=?"
            args = (status,)
        sql += " ORDER BY score DESC, created_at, sink_file, sink_line, id LIMIT ?"
        args += (limit,)
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def set_slice_score(
        self, slice_id: str, score: int, reasons: list[str], digest: dict[str, Any]
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE slice SET score=?, reasons=?, digest=?, updated_at=? WHERE id=?",
                (score, json.dumps(reasons, ensure_ascii=False),
                 json.dumps(digest, ensure_ascii=False), now_iso(), slice_id),
            )

    def bump_slice_score(self, slice_id: str, delta: int) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE slice SET score=MAX(0, score + ?), updated_at=? WHERE id=?",
                (delta, now_iso(), slice_id),
            )

    def peek_slices(self, limit: int = 5, run_id: str | None = None) -> list[dict[str, Any]]:
        """Pending slices in queue order, digest only (no lease, no attempt bump)."""
        sql = (
            "SELECT id, run_id, kind, sink_file, sink_line, attempts, score, reasons, digest, order_mode"
            " FROM slice WHERE status='pending'"
        )
        args: tuple[Any, ...] = ()
        if run_id:
            sql += " AND run_id=?"
            args = (run_id,)
        sql += " ORDER BY score DESC, attempts, kind, sink_file, sink_line LIMIT ?"
        args += (max(1, min(limit, 50)),)
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        peeked: list[dict[str, Any]] = []
        for row in rows:
            item = {
                "slice_id": row["id"],
                "run_id": row["run_id"],
                "attempts": row["attempts"],
                "score": row["score"],
                "order_mode": row["order_mode"],
                "reasons": json.loads(row["reasons"] or "[]"),
                "digest": json.loads(row["digest"] or "{}"),
            }
            item["pairs"] = self._pairs_for(row["id"], limit=3)
            peeked.append(item)
        return peeked

    # -- read/write pairing ------------------------------------------------
    def replace_pairs(self, run_id: str, pairs: list[dict[str, Any]]) -> int:
        """Replace the pairing snapshot of one run; pairing is a derived prior, not evidence."""
        now = now_iso()
        with self._conn() as conn:
            conn.execute("DELETE FROM pair_hint WHERE run_id=?", (run_id,))
            for pair in pairs:
                conn.execute(
                    "INSERT INTO pair_hint (pair_id, run_id, read_slice_id, write_slice_id, table_name,"
                    " columns, confidence, direction, reasons, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        str(pair["pair_id"]),
                        run_id,
                        str(pair["read_slice_id"]),
                        str(pair["write_slice_id"]),
                        str(pair.get("table") or ""),
                        json.dumps(pair.get("columns") or [], ensure_ascii=False),
                        int(pair.get("confidence") or 0),
                        str(pair.get("direction") or "unknown"),
                        json.dumps(pair.get("reasons") or [], ensure_ascii=False),
                        now,
                    ),
                )
        return len(pairs)

    def list_pairs(self, run_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM pair_hint"
        args: tuple[Any, ...] = ()
        if run_id:
            sql += " WHERE run_id=?"
            args = (run_id,)
        sql += " ORDER BY confidence DESC LIMIT ?"
        args += (max(1, min(limit, 2000)),)
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [self._pair_row(row) for row in rows]

    def pairs_for_slice(self, slice_id: str, limit: int = 3) -> list[dict[str, Any]]:
        return self._pairs_for(slice_id, limit)

    def _pairs_for(self, slice_id: str, limit: int = 3) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM pair_hint WHERE read_slice_id=? OR write_slice_id=?"
                " ORDER BY confidence DESC LIMIT ?",
                (slice_id, slice_id, max(1, limit)),
            ).fetchall()
        pairs: list[dict[str, Any]] = []
        for row in rows:
            pair = self._pair_row(row)
            pair["side"] = "read" if pair["read_slice_id"] == slice_id else "write"
            pair["peer_slice_id"] = (
                pair["write_slice_id"] if pair["side"] == "read" else pair["read_slice_id"]
            )
            pairs.append(pair)
        return pairs

    # -- injection queue ---------------------------------------------------
    def replace_injection_queue(self, run_id: str, items: list[dict[str, Any]]) -> int:
        """Replace one run's injection queue with a ranked snapshot."""
        now = now_iso()
        with self._conn() as conn:
            conn.execute("DELETE FROM injection_queue WHERE run_id=?", (run_id,))
            for rank, item in enumerate(items):
                conn.execute(
                    "INSERT INTO injection_queue (item_id, run_id, rank, write_slice_id, read_slice_id,"
                    " pair_id, table_name, columns, score, direction, reasons, status, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)",
                    (
                        str(item["item_id"]),
                        run_id,
                        rank,
                        str(item["write_slice_id"]),
                        str(item["read_slice_id"]),
                        str(item["pair_id"]),
                        str(item.get("table") or ""),
                        json.dumps(item.get("columns") or [], ensure_ascii=False),
                        int(item.get("score") or 0),
                        str(item.get("direction") or ""),
                        json.dumps(item.get("reasons") or [], ensure_ascii=False),
                        now,
                        now,
                    ),
                )
        return len(items)

    def list_injection_queue(
        self, run_id: str | None = None, *, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM injection_queue WHERE 1=1"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY rank ASC LIMIT ?"
        args.append(max(1, min(limit, 2000)))
        with self._conn() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
        return [self._injection_row(row) for row in rows]

    def next_injection_item(self, run_id: str | None = None) -> dict[str, Any] | None:
        sql = "SELECT item_id FROM injection_queue WHERE status='pending'"
        args: tuple[Any, ...] = ()
        if run_id:
            sql += " AND run_id=?"
            args = (run_id,)
        sql += " ORDER BY rank ASC LIMIT 1"
        with self._conn() as conn:
            row = conn.execute(sql, args).fetchone()
            if row is None:
                return None
            item_id = str(row["item_id"])
            conn.execute(
                "UPDATE injection_queue SET status='running', updated_at=? WHERE item_id=?",
                (now_iso(), item_id),
            )
            fresh = conn.execute("SELECT * FROM injection_queue WHERE item_id=?", (item_id,)).fetchone()
        return self._injection_row(fresh) if fresh is not None else None

    def archive_injection_item(self, item_id: str, verdict: str, *, case_id: str = "") -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE injection_queue SET status='done', verdict=?, case_id=?, updated_at=?"
                " WHERE item_id=?",
                (verdict, case_id, now_iso(), item_id),
            )
            return cur.rowcount > 0

    @staticmethod
    def _injection_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "item_id": row["item_id"],
            "run_id": row["run_id"],
            "rank": row["rank"],
            "write_slice_id": row["write_slice_id"],
            "read_slice_id": row["read_slice_id"],
            "pair_id": row["pair_id"],
            "table": row["table_name"],
            "columns": json.loads(row["columns"] or "[]"),
            "score": row["score"],
            "direction": row["direction"],
            "reasons": json.loads(row["reasons"] or "[]"),
            "status": row["status"],
            "verdict": row["verdict"],
            "case_id": row["case_id"],
        }

    @staticmethod
    def _pair_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "pair_id": row["pair_id"],
            "read_slice_id": row["read_slice_id"],
            "write_slice_id": row["write_slice_id"],
            "table": row["table_name"],
            "columns": json.loads(row["columns"] or "[]"),
            "confidence": row["confidence"],
            "direction": row["direction"],
            "reasons": json.loads(row["reasons"] or "[]"),
        }


    def lease_slice(self, slice_id: str) -> dict[str, Any] | None:
        """Lease one specific slice (planner choice); None when it is not pending."""
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE slice SET status='running', attempts=attempts+1, updated_at=?"
                " WHERE id=? AND status='pending'",
                (now_iso(), slice_id),
            )
            if cursor.rowcount == 0:
                return None
            row = conn.execute("SELECT * FROM slice WHERE id=?", (slice_id,)).fetchone()
        loaded = dict(row)
        loaded["slice"] = json.loads(loaded.pop("slice_json"))
        return loaded

    def list_slice_rows(
        self, run_id: str | None = None, *, verdicts: tuple[str, ...] = (), limit: int = 2000
    ) -> list[dict[str, Any]]:
        """Full slice rows (with payload) filtered by run and verdict — the proven-read feed."""
        sql = "SELECT * FROM slice WHERE 1=1"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if verdicts:
            marks = ",".join("?" for _ in verdicts)
            sql += f" AND verdict IN ({marks})"
            args.extend(verdicts)
        sql += " ORDER BY score DESC, created_at LIMIT ?"
        args.append(max(1, min(limit, 5000)))
        with self._conn() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
        loaded: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["slice"] = json.loads(item.pop("slice_json"))
            loaded.append(item)
        return loaded

    def get_slice(self, slice_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM slice WHERE id=?", (slice_id,)).fetchone()
        if row is None:
            return None
        loaded = dict(row)
        loaded["slice"] = json.loads(loaded.pop("slice_json"))
        return loaded

    def verdict_history(self) -> dict[str, list[str]]:
        """Archived verdicts keyed by ``file:line`` so scoring can reuse earlier outcomes."""
        history: dict[str, list[str]] = {}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT sink_file, sink_line, verdict FROM slice"
                " WHERE verdict IS NOT NULL ORDER BY updated_at DESC LIMIT 2000"
            ).fetchall()
        for row in rows:
            key = f"{row['sink_file']}:{row['sink_line']}"
            history.setdefault(key, []).append(str(row["verdict"]))
        return history
