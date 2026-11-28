"""The score is the model's prior; the harness only pins confirmed sites."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tia.cap.scoring import CONFIRMED_SCORE, band_of, batches, score_records
from tia.dom.pipeline import _score_seeded_slices


class FakeModel:
    def __init__(self, mapping: dict[str, Any] | None = None) -> None:
        self.mapping = mapping or {}
        self.calls = 0
        self.sizes: list[int] = []

    async def complete_json(self, system: str, user: str) -> dict[str, Any]:
        self.calls += 1
        payload = json.loads(user)
        candidates = payload["candidates"]
        self.sizes.append(len(candidates))
        scores = []
        for candidate in candidates:
            key = str(candidate.get("slice_id") or candidate.get("candidate_id") or "")
            if key in self.mapping:
                scores.append(
                    {
                        "slice_id": key,
                        "score": self.mapping[key],
                        "band": "likely",
                        "reason": "model reason",
                    }
                )
        return {"scores": scores}


class FakeStore:
    def __init__(self, rows: list[dict[str, Any]], history: dict[str, list[str]] | None = None) -> None:
        self.rows = rows
        self.history = history or {}
        self.scores: dict[str, tuple[int, list[str]]] = {}

    def list_slice_rows(self, run_id: str | None = None, **_kwargs: Any) -> list[dict[str, Any]]:
        return list(self.rows)

    def verdict_history(self) -> dict[str, list[str]]:
        return dict(self.history)

    def learning_rows(self, key: str) -> list[dict[str, Any]]:
        return []

    def set_slice_score(
        self, slice_id: str, score: int, reasons: list[str], digest: dict[str, Any]
    ) -> None:
        self.scores[slice_id] = (score, reasons)

    def get_slice(self, slice_id: str) -> dict[str, Any] | None:
        for row in self.rows:
            if row["id"] == slice_id:
                return row
        return None


def _record(index: int, *, pad: int = 0) -> dict[str, Any]:
    prompt = {"slice_id": f"s{index}", "note": "x" * pad}
    return {
        "id": f"s{index}",
        "prompt": prompt,
        "fallback": {"score": 40, "reason": "prior"},
    }


def _raw(file: str = "a.php", line: int = 1) -> dict[str, Any]:
    return {
        "kind": "Xss",
        "sinkFile": file,
        "sinkLine": line,
        "sink": {"file": file, "line": line, "code": "echo $_GET['x'];"},
        "sources": [{"param": "x"}],
    }


def test_band_anchors() -> None:
    assert band_of(100) == "confirmed"
    assert band_of(85) == "likely"
    assert band_of(60) == "possible"
    assert band_of(35) == "weak"
    assert band_of(10) == "unlikely"


def test_batches_respect_item_and_char_limits() -> None:
    small = [_record(index) for index in range(30)]
    chunks = batches(small)
    assert [len(chunk) for chunk in chunks] == [25, 5]

    huge = _record(99, pad=31_000)
    chunks = batches([_record(1), huge, _record(2)])
    assert [len(chunk) for chunk in chunks] == [1, 1, 1]


@pytest.mark.asyncio
async def test_score_is_clamped_and_missing_ids_fall_back() -> None:
    model = FakeModel({"a": 140, "b": "not-a-number", "ghost": 50})
    records = [_record(1), _record(2), _record(3)]
    for record, key in zip(records, ["a", "b", "c"], strict=True):
        record["id"] = key
        record["prompt"]["slice_id"] = key
    results = await score_records(model, records)
    assert results["a"]["score"] == CONFIRMED_SCORE
    assert results["b"]["source"] == "local_prior"
    assert results["b"]["score"] == 40
    assert results["c"]["source"] == "local_prior"
    assert "ghost" not in results


@pytest.mark.asyncio
async def test_confirmed_site_is_pinned_without_a_model_call() -> None:
    store = FakeStore(
        [{"id": "s1", "slice": _raw("vulnerabilities/stored_xss/home.php", 61), "status": "pending", "order_mode": "second"}],
        {"vulnerabilities/stored_xss/home.php:61": ["EXECUTABLE"]},
    )
    model = FakeModel()
    scored = await _score_seeded_slices(store, "run-1", scorer=model)
    assert scored == 0
    assert model.calls == 0
    assert store.scores["s1"][0] == CONFIRMED_SCORE


@pytest.mark.asyncio
async def test_pending_slice_takes_the_model_score() -> None:
    store = FakeStore(
        [{"id": "s1", "slice": _raw(), "status": "pending", "order_mode": "second"}],
    )
    model = FakeModel({"s1": 77})
    scored = await _score_seeded_slices(store, "run-1", scorer=model)
    assert scored == 1
    assert model.calls == 1
    assert store.scores["s1"][0] == 77
    assert "77 (likely)" in store.scores["s1"][1][0]
