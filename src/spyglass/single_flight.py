"""Async single-flight cache.

The first miss on a key starts the underlying fetch; concurrent missers await
the same in-flight `asyncio.Task` instead of issuing their own call. A
successful result stays cached so a repeat lookup does not refetch. A failed
fetch is evicted rather than cached, so a later lookup retries cleanly and one
failure cannot poison the key.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

type Fetch[V] = Callable[[], Awaitable[V]]


class SingleFlight[K, V]:
    """Deduplicating, caching async map from key to fetched value."""

    def __init__(self) -> None:
        self._tasks: dict[K, asyncio.Task[V]] = {}

    async def do(self, key: K, fetch: Fetch[V]) -> V:
        """Return the value for `key`, fetching at most once per key.

        Concurrent callers on a missing key share one in-flight task. Successful
        results are retained; a failed fetch is evicted so the next call retries.
        """
        task = self._tasks.get(key)
        if task is None:
            task = asyncio.ensure_future(fetch())
            self._tasks[key] = task
        try:
            return await task
        except BaseException:
            # Evict the failed task so it never poisons a later retry, taking
            # care not to clobber a fresh task another caller may have started.
            if self._tasks.get(key) is task:
                del self._tasks[key]
            raise
