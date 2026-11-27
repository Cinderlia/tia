"""Adapter for the NAVI chain contract (six chains, one graph file per chain).

The contract is defined by ``docs/NAVI-CHAIN-CONTRACT.md`` in the NAVI
repository.  Downstream consumers must:

* read one chain per directory (``navi/<chain>/taint-analysis-graphs.json``),
* never merge chains (the chain name carries the semantics),
* count by sink line, not by path,
* ignore the debug artifacts (``joined/``, ``1-*``, ``2-*``, slices/flows),
* treat a ``{"sinkSize": 0, "sinks": []}`` file as a legal empty chain,
* re-read source code from ``at`` instead of trusting the truncated sink text.

TIA maps the two XSS chains onto its slice families.  The four SQL chains are
reserved: they are loaded only when explicitly requested (the SQL acceptance
path is not implemented yet).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Chain names from the contract, in contract order.
NAVI_CHAINS: tuple[str, ...] = (
    "xss-direct",
    "xss-second-order",
    "sqlwrite-direct",
    "read-to-write",
    "sqlread-direct",
    "sqlwrite-second-order",
)

#: XSS chains and the TIA slice family they feed.
FAMILY_OF_CHAIN: dict[str, str] = {
    "xss-direct": "direct",
    "xss-second-order": "second",
}

#: SQL chains, reserved until the SQL acceptance path lands.
SQL_CHAINS: frozenset[str] = frozenset(NAVI_CHAINS) - frozenset(FAMILY_OF_CHAIN)

#: Convenience groups for CLI callers.
CHAINS_OF_FAMILY: dict[str, tuple[str, ...]] = {
    "direct": ("xss-direct",),
    "second": ("xss-second-order",),
    # Write slices are SQL write sites; they only serve pairing for now.
    "write": ("sqlwrite-direct",),
}

_GRAPH_NAME = "taint-analysis-graphs.json"
_DEBUG_DIRS = ("joined", "result", "slices", "flows")
_CHAIN_RE = re.compile(r"^\d+-")


class NaviContractError(ValueError):
    """The given path does not follow the chain layout."""


@dataclass(slots=True)
class ChainSink:
    """One sink entry, already normalized to TIA's slice shape."""

    chain: str
    family: str
    file: str
    line: int
    code: str
    kind: str = "Xss"
    params: list[str] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)

    def to_slice(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "chain": self.chain,
            "family": self.family,
            "navi_contract": 2,
            "sink": {"file": self.file, "line": self.line, "code": self.code},
            "sinkFile": self.file,
            "sinkLine": self.line,
            "sinkCode": self.code,
            "params": list(self.params),
            "nodes": [dict(node) for node in self.nodes],
            "edges": [dict(edge) for edge in self.edges],
            "optionalGuards": list(self.guards),
        }


def split_sink_ref(text: str) -> tuple[str, int, str]:
    """Split ``"<file>:<line>  <code>"`` into file, line and code.

    The contract uses two spaces between the location and the source line, but
    source text is truncated and may be missing.  Template sinks are wrapped in
    ``<template ...>``; the wrapper is stripped because it is not a file path.
    """

    raw = text.strip()
    if raw.startswith("<template "):
        wrapper_end = raw.find(">")
        if wrapper_end > len("<template "):
            raw = raw[len("<template ") : wrapper_end].strip()
    head, sep, tail = raw.partition(":")
    if not sep:
        return raw, 0, ""
    match = re.match(r"\s*(\d+)", tail)
    if match is None:
        return head.strip(), 0, tail.strip()
    rest = tail[match.end() :].lstrip(" \t")
    return head.strip(), int(match.group(1)), rest


def chain_file(root: Path, chain: str) -> Path:
    """Return the graph file for ``chain`` under a NAVI output root."""

    if root.name == chain and root.is_dir():
        return root / _GRAPH_NAME
    if root.name == _GRAPH_NAME:
        return root
    if (root / "navi" / chain / _GRAPH_NAME).is_file():
        return root / "navi" / chain / _GRAPH_NAME
    return root / chain / _GRAPH_NAME


def is_debug_artifact(path: Path) -> bool:
    """True for NAVI debug output that downstream must not depend on."""

    return any(part in _DEBUG_DIRS or _CHAIN_RE.match(part) for part in path.parts)


def load_chain(root: Path, chain: str) -> list[dict[str, Any]]:
    """Load and normalize the sinks of one chain (empty chain is legal)."""

    path = chain_file(root, chain)
    if not path.is_file():
        if is_debug_artifact(path):
            raise NaviContractError(f"{path} is a debug artifact; use {_GRAPH_NAME}")
        raise NaviContractError(f"missing chain file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise NaviContractError(f"{path} is not valid JSON: {exc}") from exc
    sinks = payload.get("sinks") if isinstance(payload, dict) else None
    if not isinstance(sinks, list):
        raise NaviContractError(f"{path} has no sinks list")

    family = FAMILY_OF_CHAIN.get(chain, "sql")
    out: list[dict[str, Any]] = []
    for raw in sinks:
        if not isinstance(raw, dict):
            continue
        file, line, code = split_sink_ref(str(raw.get("sink") or ""))
        if not file or line <= 0:
            # A malformed sink line cannot be replayed; keep the chain valid.
            continue
        nodes: list[dict[str, Any]] = []
        for node in raw.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            node_file, node_line, node_code = split_sink_ref(str(node.get("at") or ""))
            if not node_file or node_line <= 0:
                continue
            nodes.append(
                {
                    "file": node_file,
                    "line": node_line,
                    "code": str(node.get("code") or node_code),
                }
            )
        params = [str(item) for item in raw.get("params") or [] if str(item)]
        edges = [dict(edge) for edge in raw.get("edges") or [] if isinstance(edge, dict)]
        guards = [str(item) for item in raw.get("optionalGuards") or [] if str(item)]
        sink = ChainSink(
            chain=chain,
            family=family,
            file=file,
            line=line,
            code=code,
            kind=str(raw.get("kind") or ("Xss" if family != "sql" else "SqlWriteLoose")),
            params=params,
            nodes=nodes,
            edges=edges,
            guards=guards,
        )
        out.append(sink.to_slice())
    return out


def load_navi(
    root: Path,
    *,
    chains: tuple[str, ...] | None = None,
    include_sql: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Load a NAVI output root into slices grouped by TIA family.

    Returns ``{"direct": [...], "second": [...], "sql": [...]}``.  Unknown
    chains are rejected so a typo never silently produces an empty run.
    """

    if chains is None:
        selected = tuple(present_chains(root))
        if not selected:
            raise NaviContractError(f"no chain files under {root}")
    else:
        selected = chains
    unknown = [chain for chain in selected if chain not in NAVI_CHAINS]
    if unknown:
        raise NaviContractError(f"unknown chain(s): {', '.join(unknown)}")

    grouped: dict[str, list[dict[str, Any]]] = {"direct": [], "second": [], "sql": []}
    for chain in selected:
        family = FAMILY_OF_CHAIN.get(chain)
        if family is None:
            if not include_sql:
                continue
            family = "sql"
        grouped[family].extend(load_chain(root, chain))
    return grouped


def present_chains(root: Path) -> list[str]:
    """Chains that have a graph file under ``root`` (empty chain included)."""

    return [chain for chain in NAVI_CHAINS if chain_file(root, chain).is_file()]


def family_slices(root: Path, family: str) -> list[dict[str, Any]]:
    """Slices of one TIA family from a NAVI root (``direct``/``second``/``write``)."""

    chains = CHAINS_OF_FAMILY.get(family)
    if chains is None:
        raise NaviContractError(f"unknown family: {family}")
    return load_navi(root, chains=chains, include_sql=True)[
        "sql" if family == "write" else family
    ]
