from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

TOPICS = (
    "security_event",
    "attacker_updated",
    "behavior_changed",
    "deception_changed",
    "risk_changed",
)

DEFAULT_QUEUE_SIZE = 2000


class EventBus:
    """Bounded async pub/sub bus. Slow consumers drop oldest messages (DoS safe)."""

    def __init__(self, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self._queue_size = queue_size
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def subscribe(self, topic: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers[topic].append(queue)
        return queue

    def subscribe_many(self, topics: tuple[str, ...]) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        for topic in topics:
            self._subscribers[topic].append(queue)
        return queue

    def unsubscribe_many(
        self, topics: tuple[str, ...], queue: asyncio.Queue[dict[str, Any]]
    ) -> None:
        for topic in topics:
            self.unsubscribe(topic, queue)

    def unsubscribe(self, topic: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        subscribers = self._subscribers.get(topic, [])
        if queue in subscribers:
            subscribers.remove(queue)

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))

    def publish_nowait(self, topic: str, message: dict[str, Any]) -> int:
        delivered = 0
        for queue in list(self._subscribers.get(topic, [])):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                try:
                    queue.put_nowait(message)
                except asyncio.QueueFull:
                    continue
                delivered += 1
                continue
            delivered += 1
        return delivered

    async def publish(self, topic: str, message: dict[str, Any]) -> int:
        return self.publish_nowait(topic, message)
