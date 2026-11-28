"""Project-local storage (sqlite).

Tables: case / change / evidence / flow / probe / session (the six tables from T04),
plus a slice table for the main agent's queue. All writes include ``case_id`` and ``observed_at``,
for report reconstruction (H10).

Connections are not shared across threads: ``Store`` opens a short-lived connection per operation (sqlite is small, fast enough),
also avoiding connection conflicts between async handlers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from tia.orch.identity import identity_of

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
CREATE TABLE IF NOT EXISTS login_failure (
    label      TEXT PRIMARY KEY,
    failures   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS trace (
    id           TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    file         TEXT NOT NULL,
    line_from    INTEGER NOT NULL DEFAULT 0,
    line_to      INTEGER NOT NULL DEFAULT 0,
    function     TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT 'GET',
    url          TEXT NOT NULL DEFAULT '',
    output       TEXT NOT NULL,
    raw_path     TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL DEFAULT '',
    total_lines  INTEGER NOT NULL DEFAULT 0,
    unique_lines INTEGER NOT NULL DEFAULT 0,
    truncated    INTEGER NOT NULL DEFAULT 0,
    summary      TEXT NOT NULL DEFAULT '{}',
    observed_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trace_case ON trace(case_id, observed_at);
CREATE TABLE IF NOT EXISTS pair_request (
    request_id    TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    read_slice_id TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'constraint',
    table_name    TEXT NOT NULL DEFAULT '',
    column_name   TEXT NOT NULL DEFAULT '',
    op            TEXT NOT NULL DEFAULT 'set',
    value         TEXT NOT NULL DEFAULT '',
    direction     TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    candidates    TEXT NOT NULL DEFAULT '[]',
    reason        TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pair_request_run ON pair_request(run_id, status);
CREATE TABLE IF NOT EXISTS learning (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    signature  TEXT NOT NULL,
    attribute  TEXT NOT NULL,
    value      TEXT NOT NULL,
    successes  INTEGER NOT NULL DEFAULT 0,
    failures   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(signature, attribute, value)
);
CREATE TABLE IF NOT EXISTS pair_cache (
    key        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state_plan (
    case_id          TEXT PRIMARY KEY,
    table_name       TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT '',
    plan             TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_job (
    flow_id          TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL,
    rank             INTEGER NOT NULL DEFAULT 0,
    family           TEXT NOT NULL DEFAULT 'second',
    sink_class       TEXT NOT NULL DEFAULT 'xss',
    sink_kind        TEXT NOT NULL DEFAULT 'Xss',
    target_slice_id  TEXT NOT NULL,
    writer_slice_ids TEXT NOT NULL DEFAULT '[]',
    table_name       TEXT NOT NULL DEFAULT '',
    columns          TEXT NOT NULL DEFAULT '[]',
    score            INTEGER NOT NULL DEFAULT 0,
    reasons          TEXT NOT NULL DEFAULT '[]',
    digest           TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending',
    attempts         INTEGER NOT NULL DEFAULT 0,
    verdict          TEXT NOT NULL DEFAULT '',
    case_id          TEXT NOT NULL DEFAULT '',
    probe            TEXT NOT NULL DEFAULT '{}',
    notes            TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flow_job_run ON flow_job (run_id, status, score);
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
                ("identity", "ALTER TABLE slice ADD COLUMN identity TEXT NOT NULL DEFAULT ''"),
                ("duplicate_of", "ALTER TABLE slice ADD COLUMN duplicate_of TEXT"),
                ("role", "ALTER TABLE slice ADD COLUMN role TEXT NOT NULL DEFAULT 'read'"),
                ("chain", "ALTER TABLE slice ADD COLUMN chain TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in columns:
                    conn.execute(ddl)
            queue_columns = {row["name"] for row in conn.execute("PRAGMA table_info(injection_queue)")}
            for name, ddl in (
                ("read_identity", "ALTER TABLE injection_queue ADD COLUMN read_identity TEXT NOT NULL DEFAULT ''"),
                ("write_identity", "ALTER TABLE injection_queue ADD COLUMN write_identity TEXT NOT NULL DEFAULT ''"),
                ("alternates", "ALTER TABLE injection_queue ADD COLUMN alternates TEXT NOT NULL DEFAULT '[]'"),
            ):
                if name not in queue_columns:
                    conn.execute(ddl)
            session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(session)")}
            for name, ddl in (
                ("label", "ALTER TABLE session ADD COLUMN label TEXT NOT NULL DEFAULT ''"),
                ("roles", "ALTER TABLE session ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'"),
                ("username", "ALTER TABLE session ADD COLUMN username TEXT NOT NULL DEFAULT ''"),
                ("description", "ALTER TABLE session ADD COLUMN description TEXT NOT NULL DEFAULT ''"),
                ("login_url", "ALTER TABLE session ADD COLUMN login_url TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in session_columns:
                    conn.execute(ddl)
            conn.execute(
                "CREATE TABLE IF NOT EXISTS conclusion ("
                " pair_key TEXT PRIMARY KEY, read_identity TEXT NOT NULL,"
                " write_identity TEXT NOT NULL, verdict TEXT NOT NULL,"
                " case_id TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)"
            )

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

    def get_pair_cache(self, key: str) -> Any | None:
        """Cached pure-function result (window parse, slice model, pair decision)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload FROM pair_cache WHERE key=?", (key,)
            ).fetchone()
        return json.loads(row["payload"]) if row is not None else None

    def set_pair_cache(self, key: str, kind: str, payload: Any) -> None:
        now = now_iso()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO pair_cache (key, kind, payload, updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     kind=excluded.kind, payload=excluded.payload, updated_at=excluded.updated_at""",
                (key, kind, json.dumps(payload, ensure_ascii=False, default=str), now),
            )

    def prune_pair_cache(self, keep: int = 50000) -> int:
        """Drop the oldest keys beyond ``keep``; returns the number of rows removed."""
        with self._conn() as conn:
            total = int(conn.execute("SELECT COUNT(*) AS n FROM pair_cache").fetchone()["n"])
            extra = max(0, total - keep)
            if extra:
                conn.execute(
                    "DELETE FROM pair_cache WHERE key IN ("
                    " SELECT key FROM pair_cache ORDER BY updated_at ASC LIMIT ?)",
                    (extra,),
                )
        return extra

    def save_state_plan(self, case_id: str, plan: dict[str, Any]) -> None:
        """Store the latest state probe plan for a case (one row per case)."""
        now = now_iso()
        payload = json.dumps(plan, ensure_ascii=False, default=str)
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO state_plan (case_id, table_name, status, plan, created_at, updated_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(case_id) DO UPDATE SET
                     table_name=excluded.table_name, status=excluded.status,
                     plan=excluded.plan, updated_at=excluded.updated_at""",
                (
                    case_id,
                    str(plan.get("table") or ""),
                    str(plan.get("status") or ""),
                    payload,
                    now,
                    now,
                ),
            )

    def get_state_plan(self, case_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT plan FROM state_plan WHERE case_id=?", (case_id,)
            ).fetchone()
        return json.loads(row["plan"]) if row is not None else None

    def merge_case_notes(self, case_id: str, notes: dict[str, Any]) -> None:
        """Merge structured notes into the case (JSON-safe, best effort)."""
        with self._conn() as conn:
            row = conn.execute("SELECT notes FROM case_file WHERE id=?", (case_id,)).fetchone()
            if row is None:
                return
            current: dict[str, Any] = json.loads(row["notes"])
            current.update(notes)
            conn.execute(
                "UPDATE case_file SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(current, ensure_ascii=False, default=str), now_iso(), case_id),
            )

    def set_case_report(self, case_id: str, report: str) -> None:
        """Store the Markdown report generated at the end of a case."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE case_file SET report=?, updated_at=? WHERE id=?",
                (report, now_iso(), case_id),
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

    def add_trace(
        self,
        *,
        trace_id: str,
        case_id: str,
        file: str,
        line_from: int,
        line_to: int,
        function: str,
        method: str,
        url: str,
        output: str,
        raw_path: str,
        sha256: str,
        total_lines: int,
        unique_lines: int,
        truncated: bool,
        summary: dict[str, Any],
        observed_at: str,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO trace (id, case_id, file, line_from, line_to, function,"
                " method, url, output, raw_path, sha256, total_lines, unique_lines, truncated,"
                " summary, observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    trace_id,
                    case_id,
                    file,
                    line_from,
                    line_to,
                    function,
                    method,
                    url,
                    output,
                    raw_path,
                    sha256,
                    total_lines,
                    unique_lines,
                    1 if truncated else 0,
                    json.dumps(summary, ensure_ascii=False),
                    observed_at,
                ),
            )

    def get_trace(self, trace_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM trace WHERE id=?", (trace_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["summary"] = json.loads(item["summary"] or "{}")
        item["truncated"] = bool(item["truncated"])
        return item

    def list_traces(self, case_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, case_id, file, line_from, line_to, total_lines, unique_lines,"
                " observed_at FROM trace WHERE case_id=? ORDER BY observed_at DESC LIMIT ?",
                (case_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

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

    # -- pairing requests ------------------------------------------------

    def add_pair_request(
        self,
        *,
        run_id: str,
        read_slice_id: str,
        kind: str = "constraint",
        table: str = "",
        column: str = "",
        op: str = "set",
        value: Any = "",
        direction: str = "",
    ) -> str:
        """Ask the pairing agent for write slices; answered asynchronously."""
        request_id = f"pr-{uuid.uuid4().hex[:12]}"
        ts = now_iso()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO pair_request (request_id, run_id, read_slice_id, kind, table_name,"
                " column_name, op, value, direction, status, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)",
                (request_id, run_id, read_slice_id, kind, table, column, op,
                 json.dumps(value, ensure_ascii=False), direction, ts, ts),
            )
        return request_id

    def get_pair_request(self, request_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM pair_request WHERE request_id=?", (request_id,)
            ).fetchone()
        return self._pair_request_row(row) if row else None

    def list_pair_requests(
        self, *, run_id: str = "", status: str = "", limit: int = 50
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if run_id:
            clauses.append("run_id=?")
            args.append(run_id)
        if status:
            clauses.append("status=?")
            args.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM pair_request{where} ORDER BY created_at, request_id LIMIT ?",
                (*args, max(1, min(limit, 500))),
            ).fetchall()
        return [self._pair_request_row(row) for row in rows]

    def respond_pair_request(
        self,
        request_id: str,
        *,
        candidates: list[dict[str, Any]],
        reason: str = "",
        status: str = "answered",
    ) -> bool:
        with self._conn() as conn:
            changed = conn.execute(
                "UPDATE pair_request SET status=?, candidates=?, reason=?, updated_at=?"
                " WHERE request_id=? AND status='pending'",
                (status, json.dumps(candidates, ensure_ascii=False), reason,
                 now_iso(), request_id),
            ).rowcount
        return bool(changed)

    @staticmethod
    def _pair_request_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        with suppress(json.JSONDecodeError):
            payload["value"] = json.loads(payload.get("value") or '""')
        payload["candidates"] = json.loads(payload.get("candidates") or "[]")
        return payload

    def bump_learning(self, signature: str, attribute: str, value: str, success: bool) -> None:
        """Accumulate one observation for a site signature; shared by both families."""
        now = now_iso()
        hit, miss = (1, 0) if success else (0, 1)
        with self._conn() as conn:
            changed = conn.execute(
                "UPDATE learning SET successes=successes+?, failures=failures+?, updated_at=? "
                "WHERE signature=? AND attribute=? AND value=?",
                (hit, miss, now, signature, attribute, value),
            ).rowcount
            if not changed:
                conn.execute(
                    "INSERT INTO learning (signature, attribute, value, successes, failures, updated_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (signature, attribute, value, hit, miss, now),
                )

    def learning_rows(self, signature: str) -> list[dict[str, Any]]:
        if not signature:
            return []
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT signature, attribute, value, successes, failures FROM learning WHERE signature=?",
                (signature,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_session(
        self,
        *,
        label: str,
        base_url: str,
        cookies: dict[str, str],
        roles: list[str],
        username: str = "",
        description: str = "",
        login_url: str = "",
        case_id: str | None = None,
        expires_at: str | None = None,
    ) -> str:
        """Persist one logged-in session; only cookies, never the password."""

        session_id = "sess-" + hashlib.sha1(
            f"{label}|{base_url}|{now_iso()}".encode()
        ).hexdigest()[:10]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO session (id, case_id, base_url, cookies, valid, expires_at,"
                " observed_at, label, roles, username, description, login_url)"
                " VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    case_id,
                    base_url,
                    json.dumps(cookies, ensure_ascii=False),
                    expires_at,
                    now_iso(),
                    label,
                    json.dumps(list(roles), ensure_ascii=False),
                    username,
                    description,
                    login_url,
                ),
            )
        return session_id

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM session WHERE id = ?", (session_id,)).fetchone()
        return self._session_row(row) if row is not None else None

    def find_session(self, label: str, base_url: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM session WHERE label = ? AND base_url = ? AND valid = 1"
                " ORDER BY observed_at DESC LIMIT 1",
                (label, base_url),
            ).fetchone()
        return self._session_row(row) if row is not None else None

    def list_sessions(self, base_url: str = "") -> list[dict[str, Any]]:
        sql = "SELECT * FROM session"
        args: tuple[Any, ...] = ()
        if base_url:
            sql += " WHERE base_url = ?"
            args = (base_url,)
        sql += " ORDER BY observed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [self._session_row(row) for row in rows]

    def invalidate_session(self, session_id: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE session SET valid = 0 WHERE id = ?", (session_id,))

    def login_failures(self, label: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT failures FROM login_failure WHERE label = ?", (label,)
            ).fetchone()
        return int(row["failures"]) if row is not None else 0

    def bump_login_failure(self, label: str) -> int:
        now = now_iso()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO login_failure(label, failures, updated_at) VALUES (?, 1, ?)"
                " ON CONFLICT(label) DO UPDATE SET failures = failures + 1, updated_at = excluded.updated_at",
                (label, now),
            )
            row = conn.execute(
                "SELECT failures FROM login_failure WHERE label = ?", (label,)
            ).fetchone()
        return int(row["failures"]) if row is not None else 1

    def reset_login_failure(self, label: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM login_failure WHERE label = ?", (label,))

    @staticmethod
    def _session_row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        try:
            data["cookies"] = json.loads(data.get("cookies") or "{}")
        except json.JSONDecodeError:
            data["cookies"] = {}
        try:
            data["roles"] = json.loads(data.get("roles") or "[]")
        except json.JSONDecodeError:
            data["roles"] = []
        data["valid"] = bool(data.get("valid"))
        return data

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
            identity = identity_of(raw, order_mode)
            with self._conn() as conn:
                exists = conn.execute(
                    "SELECT id FROM slice WHERE run_id=? AND sink_file=? AND sink_line=?"
                    " AND status IN ('pending','running')",
                    (run_id, sink_file, sink_line),
                ).fetchone()
                if exists is not None:
                    seeded.append(str(exists["id"]))
                    continue
                canonical = conn.execute(
                    "SELECT id FROM slice WHERE run_id=? AND identity=? AND duplicate_of IS NULL"
                    " AND status IN ('pending','running') ORDER BY id LIMIT 1",
                    (run_id, identity),
                ).fetchone()
                duplicate_of = str(canonical["id"]) if canonical is not None else None
                conn.execute(
                    "INSERT INTO slice (id, run_id, kind, sink_file, sink_line, slice_json,"
                    " order_mode, identity, duplicate_of, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        slice_id,
                        run_id,
                        str(raw.get("kind") or "unknown"),
                        sink_file,
                        sink_line,
                        json.dumps(raw, ensure_ascii=False),
                        order_mode,
                        identity,
                        duplicate_of,
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
        sql += (
            " ORDER BY (duplicate_of IS NULL) DESC, score DESC, attempts, kind,"
            " sink_file, sink_line LIMIT 1"
        )
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
            "SELECT id, run_id, kind, sink_file, sink_line, attempts, score, reasons, digest,"
            " order_mode, slice_json FROM slice WHERE status='pending'"
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
                "kind": row["kind"],
                "sink_file": row["sink_file"],
                "sink_line": row["sink_line"],
                "attempts": row["attempts"],
                "score": row["score"],
                "order_mode": row["order_mode"],
                "reasons": json.loads(row["reasons"] or "[]"),
                "digest": json.loads(row["digest"] or "{}"),
                "slice": json.loads(row["slice_json"] or "{}"),
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
                    " pair_id, table_name, columns, score, direction, reasons, status,"
                    " read_identity, write_identity, alternates, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?,?)",
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
                        str(item.get("read_identity") or ""),
                        str(item.get("write_identity") or ""),
                        json.dumps(item.get("alternates") or [], ensure_ascii=False),
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
            "read_identity": row["read_identity"],
            "write_identity": row["write_identity"],
            "alternates": json.loads(row["alternates"] or "[]"),
        }

    # -- identity-level conclusions --------------------------------------

    def record_conclusion(
        self, read_identity: str, write_identity: str, verdict: str, case_id: str = ""
    ) -> None:
        key = f"{read_identity}||{write_identity}"
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO conclusion (pair_key, read_identity, write_identity, verdict,"
                " case_id, updated_at) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(pair_key) DO UPDATE SET verdict=excluded.verdict,"
                " case_id=excluded.case_id, updated_at=excluded.updated_at",
                (key, read_identity, write_identity, verdict, case_id, now_iso()),
            )

    def get_conclusion(self, read_identity: str, write_identity: str) -> dict[str, Any] | None:
        key = f"{read_identity}||{write_identity}"
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM conclusion WHERE pair_key=?", (key,)).fetchone()
        return dict(row) if row is not None else None

    def close_identity_group(self, identity: str, verdict: str, case_id: str, keep: str = "") -> int:
        """Close every still-open slice that shares an identity with a concluded one."""

        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE slice SET status='executed', verdict=?, notes=?, updated_at=?"
                " WHERE identity=? AND status IN ('pending','running') AND id<>?",
                (verdict, f"group closed by {case_id}", now_iso(), identity, keep),
            )
            return int(cursor.rowcount or 0)

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

    # -- flow queue --------------------------------------------------------

    def insert_site(
        self,
        run_id: str,
        raw: dict[str, Any],
        *,
        family: str = "second",
        chain: str = "",
        role: str = "read",
        identity: str = "",
        score: int = 0,
        reasons: list[str] | None = None,
        digest: dict[str, Any] | None = None,
    ) -> str | None:
        """Insert one static site; de-duplicates on (file, line, role) inside a run.

        A source line can be a read point in one chain and a write point in
        another, so the role is part of the key — unlike :meth:`seed_slices`,
        which serves the legacy single-family queue.
        """
        raw_sink = raw.get("sink")
        sink: dict[str, Any] = raw_sink if isinstance(raw_sink, dict) else {}
        sink_file = str(sink.get("file") or raw.get("sinkFile") or "")
        sink_line = int(sink.get("line") or raw.get("sinkLine") or 0)
        if not sink_file:
            return None
        slice_id = str(raw.get("slice_id") or f"site-{uuid.uuid4().hex[:10]}")
        ts = now_iso()
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT id FROM slice WHERE run_id=? AND sink_file=? AND sink_line=? AND role=?"
                " AND status IN ('pending','running','executed')",
                (run_id, sink_file, sink_line, role),
            ).fetchone()
            if exists is not None:
                return str(exists["id"])
            conn.execute(
                "INSERT INTO slice (id, run_id, kind, sink_file, sink_line, slice_json, order_mode,"
                " identity, role, chain, score, reasons, digest, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    slice_id,
                    run_id,
                    str(raw.get("kind") or "unknown"),
                    sink_file,
                    sink_line,
                    json.dumps(raw, ensure_ascii=False),
                    family,
                    identity,
                    role,
                    chain,
                    score,
                    json.dumps(reasons or [], ensure_ascii=False),
                    json.dumps(digest or {}, ensure_ascii=False),
                    ts,
                    ts,
                ),
            )
        return slice_id

    def seed_flows(self, run_id: str, flows: list[dict[str, Any]]) -> int:
        ts = now_iso()
        with self._conn() as conn:
            for index, flow in enumerate(flows):
                flow_id_value = str(flow["flow_id"])
                existing = conn.execute(
                    "SELECT created_at FROM flow_job WHERE flow_id=?", (flow_id_value,)
                ).fetchone()
                created_at = str(existing["created_at"]) if existing is not None else ts
                conn.execute(
                    "INSERT OR REPLACE INTO flow_job (flow_id, run_id, rank, family, sink_class,"
                    " sink_kind, target_slice_id, writer_slice_ids, table_name, columns, score,"
                    " reasons, digest, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        flow_id_value,
                        run_id,
                        int(flow.get("rank") or index),
                        str(flow.get("family") or "second"),
                        str(flow.get("sink_class") or "xss"),
                        str(flow.get("sink_kind") or "Xss"),
                        str(flow["target_slice_id"]),
                        json.dumps(flow.get("writer_slice_ids") or [], ensure_ascii=False),
                        str(flow.get("table") or ""),
                        json.dumps(flow.get("columns") or [], ensure_ascii=False),
                        int(flow.get("score") or 0),
                        json.dumps(flow.get("reasons") or [], ensure_ascii=False),
                        json.dumps(flow.get("digest") or {}, ensure_ascii=False),
                        created_at,
                        ts,
                    ),
                )
        return len(flows)

    def _flow_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ("writer_slice_ids", "columns", "reasons", "digest", "probe", "notes"):
            raw = item.get(key)
            try:
                item[key] = json.loads(raw) if raw else ([] if key in {"writer_slice_ids", "columns", "reasons"} else {})
            except json.JSONDecodeError:
                item[key] = [] if key in {"writer_slice_ids", "columns", "reasons"} else {}
        return item

    def next_flow(self, run_id: str | None = None, ttl_minutes: int = 30) -> dict[str, Any] | None:
        self.requeue_expired_flows(ttl_minutes)
        sql = "SELECT flow_id FROM flow_job WHERE status='pending'"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        sql += " ORDER BY score DESC, rank, created_at LIMIT 1"
        with self._conn() as conn:
            row = conn.execute(sql, tuple(args)).fetchone()
            if row is None:
                return None
            flow_id_value = str(row["flow_id"])
            conn.execute(
                "UPDATE flow_job SET status='running', attempts=attempts+1, updated_at=? WHERE flow_id=?",
                (now_iso(), flow_id_value),
            )
            fresh = conn.execute("SELECT * FROM flow_job WHERE flow_id=?", (flow_id_value,)).fetchone()
        return self._flow_row(fresh)

    def requeue_expired_flows(self, ttl_minutes: int = 30) -> int:
        cutoff = datetime.now().astimezone().timestamp() - ttl_minutes * 60
        with self._conn() as conn:
            rows = conn.execute("SELECT flow_id, updated_at FROM flow_job WHERE status='running'").fetchall()
            count = 0
            for row in rows:
                try:
                    updated = datetime.fromisoformat(str(row["updated_at"]))
                except ValueError:
                    continue
                if updated.timestamp() < cutoff:
                    conn.execute(
                        "UPDATE flow_job SET status='pending', updated_at=? WHERE flow_id=?",
                        (now_iso(), row["flow_id"]),
                    )
                    count += 1
        return count

    def archive_flow(
        self,
        flow_id_value: str,
        status: str,
        verdict: str = "",
        *,
        case_id: str = "",
        notes: dict[str, Any] | None = None,
    ) -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE flow_job SET status=?, verdict=?, case_id=?, notes=?, updated_at=? WHERE flow_id=?",
                (
                    status,
                    verdict,
                    case_id,
                    json.dumps(notes or {}, ensure_ascii=False, default=str),
                    now_iso(),
                    flow_id_value,
                ),
            )
            return cursor.rowcount > 0

    def set_flow_probe(self, flow_id_value: str, probe: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE flow_job SET probe=?, updated_at=? WHERE flow_id=?",
                (json.dumps(probe, ensure_ascii=False, default=str), now_iso(), flow_id_value),
            )

    def get_flow(self, flow_id_value: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM flow_job WHERE flow_id=?", (flow_id_value,)).fetchone()
        return self._flow_row(row) if row else None

    def list_flow_jobs(
        self, run_id: str | None = None, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM flow_job WHERE 1=1"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY score DESC, rank, created_at LIMIT ?"
        args.append(max(1, min(limit, 500)))
        with self._conn() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
        return [self._flow_row(row) for row in rows]

    def count_pending_flows(self, run_id: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM flow_job WHERE status='pending' AND run_id=?", (run_id,)
            ).fetchone()
        return int(row["n"])

    def peek_flows(self, run_id: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
        sql = "SELECT * FROM flow_job WHERE status='pending'"
        args: list[Any] = []
        if run_id:
            sql += " AND run_id=?"
            args.append(run_id)
        sql += " ORDER BY score DESC, rank, created_at LIMIT ?"
        args.append(max(1, min(limit, 50)))
        with self._conn() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
        return [self._flow_row(row) for row in rows]

