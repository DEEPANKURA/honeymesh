from __future__ import annotations

import asyncio

import pytest

from app.events.bus import EventBus


@pytest.mark.asyncio
async def test_publish_subscribe() -> None:
    bus = EventBus()
    queue = bus.subscribe("security_event")
    bus.publish_nowait("security_event", {"type": "security_event", "data": 1})
    message = await asyncio.wait_for(queue.get(), timeout=1)
    assert message["data"] == 1
    assert bus.subscriber_count("security_event") == 1


@pytest.mark.asyncio
async def test_slow_consumer_drops_oldest() -> None:
    bus = EventBus(queue_size=3)
    queue = bus.subscribe("security_event")
    for index in range(10):
        bus.publish_nowait("security_event", {"index": index})
    received = [await queue.get() for _ in range(3)]
    assert [item["index"] for item in received] == [7, 8, 9]


@pytest.mark.asyncio
async def test_subscribe_many_receives_all_topics() -> None:
    bus = EventBus()
    queue = bus.subscribe_many(("security_event", "risk_changed"))
    bus.publish_nowait("security_event", {"a": 1})
    bus.publish_nowait("risk_changed", {"b": 2})
    first = await asyncio.wait_for(queue.get(), timeout=1)
    second = await asyncio.wait_for(queue.get(), timeout=1)
    assert first == {"a": 1}
    assert second == {"b": 2}
    bus.unsubscribe_many(("security_event", "risk_changed"), queue)
    assert bus.subscriber_count("security_event") == 0
