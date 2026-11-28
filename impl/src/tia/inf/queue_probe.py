"""Record the queue lengths at every change while a campaign runs.

Concurrency tuning needs a trace of how the three queues move: the slice
queue the consumers lease from, and the high/low injection lanes the inject
workers drain. The probe never mutates anything; it polls a cheap count and
only appends a line when the numbers differ from the previous snapshot.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
from pathlib import Path
from typing import Any

QUEUE_LOG_ENV = "TIA_QUEUE_LOG"


def _stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _render(stats: dict[str, dict[str, int]]) -> str:
    slices = stats.get("slices") or {}
    injections = stats.get("injections") or {}
    slice_text = " ".join(f"{name}={count}" for name, count in sorted(slices.items()))
    inject_text = " ".join(f"{name}={count}" for name, count in sorted(injections.items()))
    return f"slices[{slice_text}] injections[{inject_text}]"


class QueueProbe:
    """Append one line per queue change: timestamp plus every lane length."""

    def __init__(
        self,
        store: Any,
        path: Path | str,
        run_id: str | None = None,
        *,
        interval: float = 0.5,
    ) -> None:
        self.store = store
        self.path = Path(path)
        self.run_id = run_id
        self.interval = max(0.05, interval)
        self.lines = 0

    def snapshot(self) -> str:
        return _render(self.store.queue_stats(self.run_id))

    def record(self, reason: str = "change") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(f"{_stamp()} {reason} {self.snapshot()}\n")
        self.lines += 1

    async def run(self, stop: asyncio.Event) -> None:
        self.record("start")
        last = self.snapshot()
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.interval)
            current = self.snapshot()
            if current != last:
                self.record("change")
                last = current
        self.record("stop")
