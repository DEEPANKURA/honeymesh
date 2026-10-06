from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.events.bus import TOPICS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws")


@router.websocket("/events")
async def websocket_events(websocket: WebSocket) -> None:
    await websocket.accept()
    context = getattr(websocket.app.state, "honeymesh", None)
    if context is None:
        await websocket.close(code=1013, reason="service is starting")
        return

    queue = context.bus.subscribe_many(TOPICS)
    await websocket.send_json(
        {"type": "connected", "data": {"topics": list(TOPICS), "subscribers": 1}}
    )

    async def sender() -> None:
        while True:
            message = await queue.get()
            await websocket.send_json(message)

    async def receiver() -> None:
        while True:
            text = await websocket.receive_text()
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

    tasks = [asyncio.create_task(sender()), asyncio.create_task(receiver())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        for task in tasks:
            task.cancel()
        context.bus.unsubscribe_many(TOPICS, queue)
