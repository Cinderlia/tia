"""Flows: the unit the main agent schedules.

A *site* is one static sink (read point, write point or state write). A *flow*
is one attack: a target site plus the ordered write sites needed to reach it.
Grouping explicitly allows the same site to appear in several flows (a write
point can feed many read points) and keeps read/write roles distinct even when
the same source line shows up in two NAVI chains.

Flow building is class-agnostic: it only groups by database identity. The
vulnerability class rides along (``sink_class``) and is interpreted by the
``SinkClass`` plugins.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from tia.sinks.registry import sink_class_for

READ = "read"
WRITE = "write"
STATE = "state"

#: Chain → site role; chain names are authoritative, slice features never are.
_WRITE_CHAINS = {"sqlwrite-direct", "read-to-write", "sqlwrite-second-order"}
_STATE_CHAINS = {"statewrite"}


def site_role(chain: str, family: str) -> str:
    if chain in _WRITE_CHAINS:
        return WRITE
    if chain in _STATE_CHAINS:
        return STATE
    return READ


@dataclass
class Site:
    slice_id: str
    raw: dict[str, Any]
    family: str = "second"
    chain: str = ""
    role: str = READ
    kind: str = "Xss"
    file: str = ""
    line: int = 0
    table: str = ""
    columns: tuple[str, ...] = ()
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def identity(self) -> str:
        return f"{self.file}:{self.line}|{self.role}|{self.table}|{','.join(self.columns)}"


@dataclass
class FlowSpec:
    flow_id: str
    family: str
    sink_class: str
    sink_kind: str
    target_slice_id: str
    writer_slice_ids: list[str] = field(default_factory=list)
    table: str = ""
    columns: tuple[str, ...] = ()
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    digest: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "family": self.family,
            "sink_class": self.sink_class,
            "sink_kind": self.sink_kind,
            "target_slice_id": self.target_slice_id,
            "writer_slice_ids": list(self.writer_slice_ids),
            "table": self.table,
            "columns": list(self.columns),
            "score": self.score,
            "reasons": list(self.reasons),
            "digest": dict(self.digest),
        }


def flow_identity(target: Site, writers: list[Site]) -> str:
    parts = [target.file, str(target.line), target.role]
    for writer in writers:
        parts.append(f"{writer.file}:{writer.line}")
    return "|".join(parts)


def flow_id(identity: str) -> str:
    return f"flow-{hashlib.sha1(identity.encode('utf-8')).hexdigest()[:10]}"


def _matches(read: Site, write: Site) -> tuple[bool, bool]:
    """Return (same target, exact column match)."""
    if not read.table or not write.table:
        return False, False
    if read.table.lower() != write.table.lower():
        return False, False
    if not read.columns or not write.columns:
        return True, False
    return True, bool(set(read.columns) & set(write.columns))


def build_flows(sites: list[Site], *, max_writers: int = 5) -> list[FlowSpec]:
    """Group read sites with the write sites that can feed them."""
    reads = [site for site in sites if site.role == READ]
    writes = [site for site in sites if site.role == WRITE]
    flows: list[FlowSpec] = []
    for read in reads:
        paired: list[Site] = []
        if read.family == "second":
            for write in writes:
                same, exact = _matches(read, write)
                if same:
                    paired.append(write)
            paired.sort(key=lambda site: (site.score, -site.line), reverse=True)
            paired = paired[:max_writers]
        reasons: list[str] = [f"target {read.kind} at {read.file}:{read.line}"]
        score = read.score
        if paired:
            exact_any = any(_matches(read, write)[1] for write in paired)
            score += 8 if exact_any else 4
            reasons.append(f"{len(paired)} write site(s) feed table {read.table or '?'}")
        elif read.family == "second":
            reasons.append("no write site matched yet; the prover may still find one")
        table = read.table
        columns = read.columns
        if not table and paired:
            table = next((site.table for site in paired if site.table), "")
            shared = [col for col in read.columns for site in paired if col in site.columns]
            columns = tuple(dict.fromkeys(shared)) or read.columns
            if table:
                reasons.append(f"table {table} inferred from the paired write site")
        sink_class = sink_class_for(read.kind)
        ident = flow_identity(read, paired)
        flows.append(
            FlowSpec(
                flow_id=flow_id(ident),
                family=read.family,
                sink_class=sink_class.name,
                sink_kind=read.kind,
                target_slice_id=read.slice_id,
                writer_slice_ids=[site.slice_id for site in paired],
                table=table,
                columns=columns,
                score=score,
                reasons=reasons,
                digest={
                    "target": {
                        "file": read.file,
                        "line": read.line,
                        "kind": read.kind,
                        "table": read.table,
                        "columns": list(read.columns),
                    },
                    "writers": [
                        {"file": site.file, "line": site.line, "table": site.table,
                         "columns": list(site.columns)}
                        for site in paired
                    ],
                },
            )
        )
    return flows
