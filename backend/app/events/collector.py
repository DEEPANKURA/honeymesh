from __future__ import annotations

import time
from collections import defaultdict

from app.events.normalizer import EventNormalizer, RawEvent
from app.events.schema import SecurityEvent
from app.pipeline import Pipeline


class RateLimitExceededError(Exception):
    pass


class EventCollector:
    """Receives sensor events, enforces ingest rate limits, forwards to the pipeline."""

    def __init__(self, pipeline: Pipeline, rate_limit_per_minute: int = 6000) -> None:
        self._pipeline = pipeline
        self._limit = max(1, rate_limit_per_minute)
        self._buckets: dict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))
        self.normalizer = EventNormalizer()
        self.collected_total = 0

    def _check_rate(self, source_ip: str) -> None:
        now = time.monotonic()
        window_start, count = self._buckets[source_ip]
        if now - window_start >= 60.0:
            window_start, count = now, 0
        count += 1
        self._buckets[source_ip] = (window_start, count)
        if count > self._limit:
            raise RateLimitExceededError(f"rate limit exceeded for {source_ip}")

    def reset(self) -> None:
        self._buckets.clear()

    async def collect(self, raw: RawEvent) -> SecurityEvent:
        self._check_rate(raw.source_ip)
        event = await self._pipeline.process(raw)
        self.collected_total += 1
        return event
