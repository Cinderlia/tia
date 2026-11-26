"""Pairing agent: model database operations, pair read/write slices, rank the injection queue.

Structure mirrors the main agent (staged, budgeted, one run id), and the
matching step follows STaint's "Match Database Operations" idea: a database
operation is modelled as a ``(table, column)`` key and reads are matched
against writes on the same key (Ji, Cao, He; ASE 2025 NIER track).

Differences from STaint, on purpose:

* modelling is static first (SQL literals, bind parameters, bounded source
  windows) and the LLM modeler is optional, off by default, and only used for
  entries the static pass could not resolve;
* pairing is a *prior*, not a verdict: it ranks injection candidates and the
  runtime probe plus ``verify_tag`` decide whether a pair holds;
* everything is bounded so the stage survives 200–2000 slices: slice cap,
  source-read budget, per-write fan-out cap, queue cap.

Stages: R0 load → R1 static extract → R2 model (source window / optional LLM)
→ R3 pair and score → R4 rank and persist the injection queue.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from tia.orch.identity import identity_of
from tia.orch.identity import write_identity as write_identity_of
from tia.orch.pairing import (
    DbOp,
    Reader,
    SliceEntry,
    build_pairs,
    extract_ops,
    group_by_slice,
    merge_ops,
    resolve_entry,
)
from tia.orch.slicing import score_slice

_SUCCESS_VERDICTS = frozenset({"EXECUTABLE", "EXECUTED"})

Modeler = Callable[[str], list[DbOp]]


class DbOpModeler(Protocol):
    """Optional LLM modeler: source window text in, database operations out."""

    def __call__(self, window: str) -> list[DbOp]: ...


@dataclass(frozen=True)
class PairingConfig:
    """Bounds for one pairing run; defaults keep a 2000-slice input tractable."""

    max_slices: int = 2000
    source_window: int = 60
    max_source_reads: int = 400
    min_confidence: int = 20
    per_write_fanout: int = 3
    queue_cap: int = 10
    llm_batch: int = 20
    quality_threshold: int = 55
    allow_column_only: bool = False


@dataclass
class PairingStage:
    stage: str
    ok: bool
    note: str


@dataclass
class PairingResult:
    run_id: str
    stages: list[PairingStage] = field(default_factory=list)
    n_slices: int = 0
    n_modeled: int = 0
    n_source_reads: int = 0
    n_pairs: int = 0
    queue: list[dict[str, Any]] = field(default_factory=list)
    seeded_ids: list[str] = field(default_factory=list)
    capped: bool = False
    notes: dict[str, Any] = field(default_factory=dict)


def _entry_text(raw: dict[str, Any]) -> str:
    chunks: list[str] = []
    for key in ("sinkCode", "sink"):
        value = raw.get(key)
        if isinstance(value, str):
            chunks.append(value)
    for node in raw.get("nodes") or []:
        if isinstance(node, dict) and isinstance(node.get("code"), str):
            chunks.append(str(node["code"]))
    return "\n".join(chunks)


def _needs_modelling(entry: SliceEntry) -> bool:
    """Entries with no ops, an unknown table, or no columns need source context.

    A write slice often carries only its ``bindParam`` line inline; the table
    lives in a nearby ``INSERT`` statement that the source window supplies.
    """
    if not entry.ops:
        return True
    if any(not op.table for op in entry.ops):
        return True
    return all(not op.columns for op in entry.ops)


def _has_sink(raw: dict[str, Any]) -> bool:
    sink = raw.get("sink")
    return bool(
        str(raw.get("sinkFile") or (sink.get("file") if isinstance(sink, dict) else "") or "").strip()
    )


def build_pairing_queue(
    store: Any,
    run_id: str,
    write_slices: list[dict[str, Any]],
    proven_reads: list[dict[str, Any]],
    *,
    reader: Reader | None = None,
    modeler: DbOpModeler | None = None,
    config: PairingConfig | None = None,
) -> PairingResult:
    """Pair proven trigger slices with injection slices; persists a ranked queue.

    The read side is what the trigger agent already proved reachable: pairing
    never takes the cartesian product of every trigger slice and every
    injection slice. ``proven_reads`` are full slice rows produced by the
    trigger stage; their ids are reused so evidence stays linked.
    """
    cfg = config or PairingConfig()
    result = PairingResult(run_id=run_id)

    # R0: the trigger proof is the precondition; no proof means no queue.
    if not proven_reads:
        store.replace_injection_queue(run_id, [])
        result.stages.append(
            PairingStage("R0", False, "no trigger slice proved reachable; queue left empty")
        )
        return result
    usable = [raw for raw in write_slices if _has_sink(raw)][: cfg.max_slices]
    result.capped = len(write_slices) > cfg.max_slices
    seeded_ids = store.seed_slices(run_id, usable)
    result.n_slices = len(seeded_ids)
    result.seeded_ids = list(seeded_ids)
    result.stages.append(
        PairingStage(
            "R0",
            True,
            f"trigger proof {len(proven_reads)}, injection slices {len(usable)}"
            + (f" (capped at {cfg.max_slices})" if result.capped else ""),
        )
    )

    # R1: static extraction; read ids come from the trigger run, write ids from this run.
    entries: list[SliceEntry] = []
    for error_index, row in enumerate(proven_reads):
        entry = resolve_entry(dict(row["slice"]), error_index, reader=None)
        entry.slice_id = str(row["id"])
        entries.append(entry)
    read_count = len(entries)
    for index, raw in enumerate(usable):
        entry = resolve_entry(raw, index, reader=None)
        entries.append(entry)
    for slice_id, entry in zip(seeded_ids, entries[read_count:], strict=False):
        entry.slice_id = slice_id
    static_hits = sum(1 for entry in entries if entry.ops)
    result.stages.append(
        PairingStage(
            "R1",
            True,
            f"static pass resolved {static_hits}/{len(entries)} entries"
            f" ({read_count} proven reads, {len(entries) - read_count} writes)",
        )
    )

    # R2: bounded source windows, then the optional LLM modeler for what is left.
    if reader is not None and entries:
        pending = [entry for entry in entries if _needs_modelling(entry)]
        budget = min(len(pending), cfg.max_source_reads)
        modelled = 0
        for entry in pending[:budget]:
            if not entry.file or entry.line <= 0:
                continue
            window = reader(entry.file, max(1, entry.line - cfg.source_window), entry.line + 10)
            result.n_source_reads += 1
            if not window:
                continue
            text = "\n".join(line for _, line in window)
            ops = extract_ops(text)
            if not ops and modeler is not None:
                try:
                    ops = list(modeler(text))
                except Exception:  # noqa: BLE001 - the modeler is best-effort
                    ops = []
            if ops:
                entry.ops = merge_ops(ops, entry.ops)
                modelled += 1
        result.n_modeled = modelled
        skipped = len(pending) - budget
        note = f"source windows {result.n_source_reads}, modelled {modelled}"
        if skipped > 0:
            note += f", {skipped} deferred by the read budget"
        if modeler is not None:
            note += ", LLM fallback enabled"
        result.stages.append(PairingStage("R2", True, note))
    else:
        result.stages.append(PairingStage("R2", True, "no source reader; static ops only"))

    # R3: bidirectional pairing and slice scores.
    pairs = build_pairs(
        entries,
        min_confidence=cfg.min_confidence,
        allow_column_only=cfg.allow_column_only,
    )
    result.n_pairs = len(pairs)
    grouped = group_by_slice(pairs)
    for slice_id, raw in zip(seeded_ids, usable, strict=False):
        scored = score_slice(raw, paired=bool(grouped.get(slice_id)))
        store.set_slice_score(slice_id, scored.score, scored.reasons, scored.digest)
    result.stages.append(
        PairingStage(
            "R3",
            True,
            f"{len(pairs)} pairs across {len(grouped)} slices"
            f" (min confidence {cfg.min_confidence})",
        )
    )

    # R4: fold duplicate slices into one candidate each, keep the rest as
    # alternates, then rank and cap the queue.
    write_identity: dict[str, str] = {}
    write_raw: dict[str, dict[str, Any]] = {}
    for slice_id, raw in zip(seeded_ids, usable, strict=False):
        write_identity[slice_id] = identity_of(raw, "second")
        write_raw[slice_id] = raw
    read_identity: dict[str, str] = {}
    read_raw_by_id: dict[str, dict[str, Any]] = {}
    for row in proven_reads:
        slice_id = str(row.get("id") or "")
        raw_value = row.get("slice")
        read_raw: dict[str, Any] = raw_value if isinstance(raw_value, dict) else row
        if slice_id:
            read_identity[slice_id] = identity_of(read_raw, "second")
            read_raw_by_id[slice_id] = read_raw

    groups: dict[str, dict[str, Any]] = {}
    skipped_concluded = 0
    for pair in pairs:
        write_id = str(pair["write_slice_id"])
        read_id = str(pair["read_slice_id"])
        # Only a proven trigger slice may stand on the read side, and only a
        # seeded injection slice on the write side.
        if read_id not in read_identity or write_id not in write_identity:
            continue
        rid = read_identity.get(read_id) or identity_of(
            read_raw_by_id.get(read_id, {}), "second"
        )
        wid = write_identity.get(write_id) or write_identity_of(
            write_raw.get(write_id, {"sinkFile": write_id})
        )
        key = f"{rid}||{wid}"
        candidate = {
            "pair_id": str(pair["pair_id"]),
            "read_slice_id": read_id,
            "write_slice_id": write_id,
            "table": str(pair.get("table") or ""),
            "columns": list(pair.get("columns") or []),
            "score": int(pair.get("confidence") or 0),
            "direction": str(pair.get("direction") or ""),
            "reasons": list(pair.get("reasons") or []),
        }
        existing = groups.get(key)
        if existing is None:
            conclusion = store.get_conclusion(rid, wid)
            if conclusion is not None and str(conclusion.get("verdict")) in _SUCCESS_VERDICTS:
                skipped_concluded += 1
                continue
            groups[key] = {"primary": candidate, "alternates": [], "read_identity": rid,
                           "write_identity": wid}
        else:
            if candidate["score"] > existing["primary"]["score"]:
                existing["alternates"].append(existing["primary"])
                existing["primary"] = candidate
            else:
                existing["alternates"].append(candidate)

    ranked: list[dict[str, Any]] = []
    per_write: dict[str, int] = {}
    for key, group in groups.items():
        primary = group["primary"]
        write_id = str(primary["write_slice_id"])
        if per_write.get(write_id, 0) >= cfg.per_write_fanout:
            continue
        per_write[write_id] = per_write.get(write_id, 0) + 1
        digest = hashlib.sha1(f"{run_id}|{key}".encode()).hexdigest()[:10]
        ranked.append(
            {
                "item_id": f"iq-{digest}",
                "write_slice_id": write_id,
                "read_slice_id": str(primary["read_slice_id"]),
                "pair_id": str(primary["pair_id"]),
                "table": str(primary["table"]),
                "columns": list(primary["columns"]),
                "score": int(primary["score"]),
                "direction": str(primary["direction"]),
                "reasons": list(primary["reasons"]),
                "read_identity": group["read_identity"],
                "write_identity": group["write_identity"],
                "alternates": [
                    {
                        "read_slice_id": alt["read_slice_id"],
                        "write_slice_id": alt["write_slice_id"],
                        "pair_id": alt["pair_id"],
                        "score": alt["score"],
                    }
                    for alt in group["alternates"][:5]
                ],
            }
        )
    ranked.sort(key=lambda item: (-int(item["score"]), item["item_id"]))
    # Adaptive bar: with plenty of good candidates the queue keeps only
    # confident pairs; when the supply is thin, lower-scored pairs are kept
    # rather than leaving the inject agent with an empty queue.
    qualified = [item for item in ranked if int(item["score"]) >= cfg.quality_threshold]
    floor = max(2, cfg.queue_cap // 2)
    if len(qualified) >= floor:
        queue = qualified[: cfg.queue_cap]
        basis = "quality"
    else:
        queue = ranked[: cfg.queue_cap]
        basis = "relative"
    dropped = max(0, len(ranked) - len(queue))
    store.replace_injection_queue(run_id, queue)
    result.queue = queue
    result.stages.append(
        PairingStage(
            "R4",
            True,
            f"queued {len(queue)} injection candidates"
            + (f"; {dropped} below the {basis} bar of {cfg.queue_cap}" if dropped else ""),
        )
    )
    result.notes = {
        "capped": result.capped,
        "dropped": dropped,
        "queue_basis": basis,
        "source_reads": result.n_source_reads,
        "modeled": result.n_modeled,
        "deduped_pairs": len(pairs) - len(groups),
        "skipped_concluded": skipped_concluded,
    }
    return result
