"""Slice digests and heuristic scores (main agent M1: pick).

The score is a cheap, explainable prior computed from the slice itself plus the
verdict history of earlier runs. It only *orders* the queue: the LLM planner can
still lease any slice it wants, and the score never decides a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tia.orch.learning import score_delta

REFLECTION = ("echo", "print", "printf", "print_r", "var_dump")
EXECUTION = ("eval", "system", "exec", "passthru", "shell_exec", "popen", "assert")
WRITE_MARKERS = ("bindparam", "bindvalue", "insert into", "update ", "delete from")


@dataclass
class SliceScore:
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    digest: dict[str, Any] = field(default_factory=dict)


def slice_digest(raw: dict[str, Any]) -> dict[str, Any]:
    """Small, stable projection of a navi slice: enough for a planner to rank it."""
    sink_value = raw.get("sink")
    sink: dict[str, Any] = sink_value if isinstance(sink_value, dict) else {}
    file_ = str(sink.get("file") or raw.get("sinkFile") or "")
    line = int(sink.get("line") or raw.get("sinkLine") or 0)
    code = str(sink.get("code") or raw.get("sinkCode") or "").strip()
    sources_value = raw.get("sources")
    sources: list[Any] = sources_value if isinstance(sources_value, list) else []
    params = sorted(
        {str(item.get("param")) for item in sources if isinstance(item, dict) and item.get("param")}
    )
    probe_value = raw.get("sqlProbe")
    probe: dict[str, Any] = probe_value if isinstance(probe_value, dict) else {}
    guards = raw.get("optionalGuards") or raw.get("guards") or []
    return {
        "kind": str(raw.get("kind") or "unknown"),
        "sink": {"file": file_, "line": line, "code": code[:160]},
        "params": params,
        "probe": bool(probe.get("extensionConfig")),
        "guards": [str(g) for g in guards][:5] if isinstance(guards, list) else [],
        "nodes": int(raw.get("nodeCount") or len(raw.get("nodes") or [])),
        "slice_id": raw.get("slice_id"),
    }


def score_slice(
    raw: dict[str, Any],
    *,
    paired: bool = False,
    history: list[str] | None = None,
    order_mode: str = "second",
    learning: dict[str, Any] | None = None,
) -> SliceScore:
    """Heuristic prior in [0, 100]; every adjustment carries a readable reason."""
    digest = slice_digest(raw)
    code = str(digest["sink"]["code"]).lower()
    score = 50
    reasons = ["base 50"]

    def add(delta: int, reason: str) -> None:
        nonlocal score
        score += delta
        reasons.append(f"{'+' if delta > 0 else ''}{delta} {reason}")

    kind = str(digest["kind"]).lower()
    if order_mode == "direct":
        # First-order: the input and the sink sit on one request path, no
        # cross-page write/read round trip is needed.
        add(8, "first-order: input and sink are on the same request path")
        if digest.get("params"):
            add(4, "first-order: source parameter is known")
        if any(word in code for word in ("shell_exec", "system(", "exec(", "passthru", "popen")):
            add(-8, "first-order: sink executes a command, side effects are risky")
    if "xss" in kind:
        add(5, "XSS sink: output evidence is observable")
    elif any(word in kind for word in ("sql", "command", "code", "exec")):
        add(-10, f"{digest['kind']} sink: needs a stronger executable predicate")

    if any(marker in code for marker in REFLECTION):
        add(8, "reflection sink (echo/print)")
    if any(marker in code for marker in EXECUTION):
        add(-10, "execution sink (eval/system)")

    if digest["probe"]:
        add(8, "navi sqlProbe present: DB read is observable")
    else:
        add(-3, "no sqlProbe: DB observation relies on the generic probe tool")

    if digest["params"]:
        add(8, f"source parameters known: {', '.join(digest['params'])}")
    else:
        add(-6, "source parameters missing: must be recovered from source")

    if digest["guards"]:
        guard_text = " ".join(digest["guards"]).lower()
        sanitizers = (
            "htmlspecialchars",
            "htmlentities",
            "strip_tags",
            "filter_var",
            "mysqli_real_escape",
            "addslashes",
            "intval",
            "preg_replace",
        )
        if any(name in guard_text for name in sanitizers):
            add(-8, f"sanitizer on path: {', '.join(digest['guards'])}")
        else:
            add(-4, f"branch conditions on path: {', '.join(digest['guards'])}")

    nodes = int(digest["nodes"])
    if 0 < nodes <= 8:
        add(4, "short taint path")
    elif nodes >= 30:
        add(-6, "long taint path")

    file_ = str(digest["sink"]["file"])
    if file_.endswith(".php") and not any(part in file_ for part in ("/lib/", "/includes/", "/cli/")):
        add(4, "web-reachable PHP entry")

    if any(marker in code for marker in WRITE_MARKERS):
        add(6, "write sink fingerprint")
    if paired:
        add(10, "same file also carries the opposite direction (paired read/write)")

    for verdict in history or []:
        if verdict in {"EXECUTABLE", "EXECUTED"}:
            add(10, f"earlier run produced {verdict}")
        elif verdict in {"READ_NOT_REFLECTED", "WRITTEN_NOT_VISIBLE", "NOT_EXECUTABLE"}:
            add(-6, f"earlier run produced {verdict}")
        elif verdict in {"BLOCKED_CSP", "NO_HTTP_ENTRY", "PATH_UNREACHABLE"}:
            add(-12, f"earlier run produced {verdict}")

    if learning:
        delta, learned = score_delta(learning)
        for reason in learned:
            add(delta, reason)

    return SliceScore(score=max(0, min(100, score)), reasons=reasons, digest=digest)


def is_write_slice(raw: dict[str, Any]) -> bool:
    code = str(slice_digest(raw)["sink"]["code"]).lower()
    return any(marker in code for marker in WRITE_MARKERS)


def pair_files(slices: list[dict[str, Any]]) -> set[str]:
    """Files that hold both a write-side and a read-side slice."""
    read_files = {str(slice_digest(raw)["sink"]["file"]) for raw in slices if not is_write_slice(raw)}
    write_files = {str(slice_digest(raw)["sink"]["file"]) for raw in slices if is_write_slice(raw)}
    return read_files & write_files
