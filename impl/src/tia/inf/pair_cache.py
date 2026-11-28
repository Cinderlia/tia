"""Cache for pairing's pure-function results.

Pairing re-derives the same facts on every run: which columns a source window
writes/reads, and which slice pairs with which. Those are pure functions of
the source text and the slice content, so they can be cached by content
fingerprint and reused across runs.

Two layers:

* an in-process LRU (small, no I/O) for the hot path within one process;
* a ``pair_cache`` table in the project store for cold reuse across runs.

Keys are *content* hashes, never paths: a changed file produces a new key and
the stale entry is simply never read again. Nothing here is a verdict — the
probe still decides whether a pair holds.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections import OrderedDict
from typing import Any

#: In-process LRU size; tiny compared with the store, big enough for a run.
LOCAL_LIMIT = 2048
#: Store rows to keep; pruning happens lazily.
STORE_KEEP = 50000


def fingerprint(*parts: object) -> str:
    """Stable content key: sha1 over the parts joined with a separator."""
    digest = hashlib.sha1()
    for part in parts:
        digest.update(str(part).encode("utf-8", "replace"))
        digest.update(b"\x00")
    return digest.hexdigest()


class PairCache:
    """LRU over a project store; both layers are optional-but-best-effort."""

    def __init__(self, store: Any | None = None, *, local_limit: int = LOCAL_LIMIT) -> None:
        self._store = store
        self._local: OrderedDict[str, Any] = OrderedDict()
        self._local_limit = max(16, local_limit)
        self.hits = 0
        self.misses = 0

    def _key(self, kind: str, key: str) -> str:
        return f"{kind}:{key}"

    def get(self, kind: str, key: str) -> Any | None:
        full = self._key(kind, key)
        if full in self._local:
            self._local.move_to_end(full)
            self.hits += 1
            return self._local[full]
        if self._store is not None:
            with contextlib.suppress(Exception):  # the cache is optional
                value = self._store.get_pair_cache(full)
            if value is not None:
                self._remember(full, value)
                self.hits += 1
                return value
        self.misses += 1
        return None

    def put(self, kind: str, key: str, payload: Any) -> None:
        full = self._key(kind, key)
        self._remember(full, payload)
        if self._store is not None:
            with contextlib.suppress(Exception):  # never break pairing for a cache
                self._store.set_pair_cache(full, kind, payload)

    def _remember(self, full: str, payload: Any) -> None:
        self._local[full] = payload
        self._local.move_to_end(full)
        while len(self._local) > self._local_limit:
            self._local.popitem(last=False)

    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "local_size": len(self._local)}


def dumps(payload: Any) -> str:
    """JSON form for cache values (tuples arrive back as lists)."""
    return json.dumps(payload, ensure_ascii=False, default=str)
