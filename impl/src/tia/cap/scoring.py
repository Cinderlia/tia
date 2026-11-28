"""LLM prior for ordering work in the queues.

The local code does not decide a score by itself. It extracts the facts the
model needs (the full slice plus history, learning and what the pairing step
matched), batches them under a token budget, validates the answer and clamps
it. A confirmed-executable identity is the only score the harness sets on its
own: that site really ran, so it gets 100 and never costs a model call.

Execution feedback adjusts scores later (see ``apply_feedback``); a score is a
prior for the queue, never a verdict.
"""

from __future__ import annotations

import json
from typing import Any

from tia.inf.pair_cache import fingerprint

RUBRIC_VERSION = "slice-score-v1"
MAX_ITEMS = 25
MAX_CHARS = 30_000
MAX_RECORD_CHARS = 6_000
MAX_STRING = 400
MAX_LIST = 12
MAX_REASON = 300

BANDS: tuple[tuple[int, str], ...] = (
    (90, "confirmed"),
    (70, "likely"),
    (50, "possible"),
    (30, "weak"),
    (0, "unlikely"),
)

CONFIRMED_SCORE = 100

RUBRIC = """You score vulnerability-verification candidates for an automated queue.

The score is a prior in 0-100. It orders work; it is never a verdict.

Anchors:
- 100: the harness already ran this exact site in an earlier campaign. Only the harness sets 100.
- 70-99: likely to execute: executable sink, reachable input, no sanitizer, no strong prerequisite.
- 50-69: possible: needs a state, a login, a specific branch, or the read side is uncertain.
- 30-49: weak: sanitizer or encoding on the path, long path, or several prerequisites.
- 0-29: unlikely: dead code, unreachable entry, admin-only path without a legitimate account.

Rules:
- Judge the evidence only. Never add or remove points because a slice is first-order or
  second-order; the run order is not evidence.
- Reward: executable sink context, direct input, a DB observation channel, a write path that
  can carry the payload, short paths, prior successes on the same site.
- Penalize: sanitizers, encodings, long paths, missing parameters, prerequisites the tool
  cannot satisfy.
- A candidate that needs pairing is not worse for that reason alone.
"""

SLICE_PROMPT = """Score every slice below. Reply with JSON only:
{"scores":[{"slice_id":"...","score":0,"band":"confirmed|likely|possible|weak|unlikely","reason":"one short sentence"}]}
Use the full slice and the context given; do not invent context.
"""

CANDIDATE_PROMPT = """Score every pairing candidate below: one proven read slice plus the write
slice or chain that could carry the payload into it. Reply with JSON only:
{"scores":[{"candidate_id":"...","score":0,"band":"confirmed|likely|possible|weak|unlikely","reason":"one short sentence"}]}
A candidate is strong when the write path accepts the payload and the read path renders it.
Judge evidence, not run order.
"""


def band_of(score: int) -> str:
    """Map a 0-100 score onto the anchor bands."""
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "unlikely"


def clamp_score(value: Any) -> int | None:
    """Accept an int/float in range; anything else is not a score."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0, min(CONFIRMED_SCORE, int(round(value))))


def compact(value: Any, *, depth: int = 0) -> Any:
    """Shrink a raw slice for the prompt without inventing or dropping context kind."""
    if depth > 6:
        return "…"
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING else value[:MAX_STRING] + "…"
    if isinstance(value, list):
        head = [compact(item, depth=depth + 1) for item in value[:MAX_LIST]]
        if len(value) > MAX_LIST:
            head.append(f"… {len(value) - MAX_LIST} more")
        return head
    if isinstance(value, dict):
        if "nodes" in value and isinstance(value["nodes"], list) and len(value["nodes"]) > MAX_LIST:
            trimmed = {key: compact(item, depth=depth + 1) for key, item in value.items() if key != "nodes"}
            trimmed["nodes"] = f"{len(value['nodes'])} nodes (trimmed)"
            return trimmed
        return {str(key): compact(item, depth=depth + 1) for key, item in value.items()}
    return value


def record_chars(record: dict[str, Any]) -> int:
    return len(json.dumps(record, ensure_ascii=False))


def batches(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split on both limits: at most MAX_ITEMS and MAX_CHARS of prompt JSON."""
    out: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 0
    for record in records:
        cost = record_chars(record)
        if current and (len(current) >= MAX_ITEMS or size + cost > MAX_CHARS):
            out.append(current)
            current = []
            size = 0
        current.append(record)
        size += cost
    if current:
        out.append(current)
    return out


def _confirmed(history: list[str]) -> bool:
    return any(verdict in {"EXECUTED", "EXECUTABLE"} for verdict in history)


async def score_records(
    model: Any,
    records: list[dict[str, Any]],
    *,
    prompt: str = SLICE_PROMPT,
    cache: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """Ask the model for a score per record; validated, clamped, cached.

    ``records`` entries carry ``id``, ``prompt`` (the payload shown to the model)
    and ``fallback`` (local prior used when the model is silent). Returns a map
    ``id -> {score, band, reason, source}``; missing ids fall back locally.
    """
    results: dict[str, dict[str, Any]] = {}
    pending: list[dict[str, Any]] = []
    for record in records:
        record_id = str(record.get("id") or "")
        if not record_id:
            continue
        key = fingerprint(RUBRIC_VERSION, prompt, record_chars(record), json.dumps(record["prompt"], sort_keys=True, ensure_ascii=False))
        if cache is not None:
            cached = cache.get("score", key)
            if isinstance(cached, dict) and "score" in cached:
                results[record_id] = dict(cached)
                continue
        record["_key"] = key
        pending.append(record)

    for chunk in batches(pending):
        payload = {
            "rubric_version": RUBRIC_VERSION,
            "candidates": [record["prompt"] for record in chunk],
        }
        try:
            data = await model.complete_json(RUBRIC + "\n" + prompt, json.dumps(payload, ensure_ascii=False))
        except Exception:  # noqa: BLE001 - the prior is best effort
            data = {}
        raw_scores = data.get("scores") if isinstance(data, dict) else None
        by_id: dict[str, dict[str, Any]] = {}
        if isinstance(raw_scores, list):
            for item in raw_scores:
                if not isinstance(item, dict):
                    continue
                item_id = str(item.get("slice_id") or item.get("candidate_id") or "")
                score = clamp_score(item.get("score"))
                if not item_id or score is None:
                    continue
                reason = str(item.get("reason") or "")[:MAX_REASON]
                by_id[item_id] = {
                    "score": score,
                    "band": str(item.get("band") or band_of(score)),
                    "reason": reason,
                    "source": "llm",
                }
        for record in chunk:
            record_id = str(record.get("id") or "")
            value = by_id.get(record_id)
            if value is None:
                fallback = record.get("fallback") or {}
                score = clamp_score(fallback.get("score")) or 0
                value = {
                    "score": score,
                    "band": band_of(score),
                    "reason": str(fallback.get("reason") or "model returned no score; local prior kept"),
                    "source": "local_prior",
                }
            results[record_id] = value
            if cache is not None and record_id in by_id:
                cache.put("score", str(record.get("_key") or ""), value)
    return results


def confirmed_result() -> dict[str, Any]:
    return {
        "score": CONFIRMED_SCORE,
        "band": "confirmed",
        "reason": "this site already executed in an earlier run",
        "source": "confirmed",
    }
