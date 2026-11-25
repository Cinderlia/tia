"""Evaluate queue ordering: how quickly does the queue reach executable slices?

Usage (inside the test container)::

    uv run python scripts/eval_queue.py \
        --slices /home/so/share/xvwa-flow/navi/trigger/joined/taint-analysis-slices.json \
        --base-url http://127.0.0.1/xvwa/vulnerabilities/stored_xss/ \
        --limit 12 --run-id eval-pairs

Pairing can be ablated with ``TIA_PAIRING=0`` to compare the ordering prior.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from tia.dom.main import run_queue, seed_queue
from tia.inf.config import Settings
from tia.inf.runtime import configure
from tia.inf.store import Store


def _load(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    for key in ("slices", "sinks"):
        items = document.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the slice queue ordering")
    parser.add_argument("--slices", required=True)
    parser.add_argument("--inject-slices", default="")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--run-id", default="eval")
    parser.add_argument("--store", default="")
    parser.add_argument("--peek", type=int, default=10)
    parser.add_argument("--payload", default="<script>alert(1)</script>")
    args = parser.parse_args(argv)

    settings = Settings.load("main")
    store_path = Path(args.store) if args.store else Path(settings.store_path).with_name(
        f"{args.run_id}.db"
    )
    if store_path.exists():
        store_path.unlink()
    settings = replace(settings, store_path=store_path)
    configure(settings)
    store: Store = configure(settings).store

    slices = _load(Path(args.slices))
    if args.inject_slices:
        slices.extend(_load(Path(args.inject_slices)))
    print(f"pairing={'on' if os.environ.get('TIA_PAIRING', '1') != '0' else 'off'}")
    print(f"loaded {len(slices)} slices")

    seed_queue(store, args.run_id, slices)
    print("\ntop candidates:")
    for item in store.peek_slices(args.peek, run_id=args.run_id):
        print(f"  {item['score']:3d} {item['slice_id']} {item['digest'].get('kind')} "
              f"{item['digest']['sink']['file']}:{item['digest']['sink']['line']}")
        for pair in item.get("pairs") or []:
            print(f"      pair {pair['confidence']:3d} {pair['direction']} "
                  f"{pair['table']}({','.join(pair['columns'])}) peer={pair['peer_slice_id']}")

    def url_for(raw: dict[str, Any]) -> str:
        sink_file = str(raw.get("sinkFile") or "")
        parent = str(Path(sink_file).parent).strip(".")
        if not parent:
            return args.base_url
        return args.base_url.rstrip("/") + "/" + parent.strip("/") + "/"

    result = asyncio.run(
        run_queue(
            store,
            base_url=args.base_url,
            run_id=args.run_id,
            limit=args.limit,
            payload_base=args.payload,
            url_for=url_for,
        )
    )
    print("\nrun:")
    successes = 0
    first_success = 0
    for rank, outcome in enumerate(result.outcomes, start=1):
        if outcome.verdict in {"EXECUTABLE", "EXECUTED"}:
            successes += 1
            first_success = first_success or rank
        print(f"  {rank:2d} {outcome.verdict:22s} {outcome.slice_id} ({outcome.duration_ms} ms)")
    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "attempted": len(result.outcomes),
                "successes": successes,
                "first_success_rank": first_success,
                "stop_reason": result.stop_reason,
                "pairing": os.environ.get("TIA_PAIRING", "1") != "0",
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
