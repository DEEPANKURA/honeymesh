from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from app.events.normalizer import RawEvent

logger = logging.getLogger(__name__)

EmitFn = Callable[[RawEvent], Awaitable[Any]]


class Sensor(Protocol):
    name: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...


class SensorBase:
    name = "sensor"

    def __init__(self, emit: EmitFn) -> None:
        self._emit = emit
        self.emitted = 0

    async def emit_event(
        self,
        event_type: str,
        source_ip: str,
        *,
        severity: str | None = None,
        metadata: dict[str, object] | None = None,
        session_id: str | None = None,
        service: str | None = None,
        username: str | None = None,
        host_id: str | None = None,
        destination: str | None = None,
    ) -> None:
        raw = RawEvent(
            sensor=self.name,
            event_type=event_type,
            source_ip=source_ip,
            severity=severity,
            metadata=metadata or {},
            session_id=session_id,
            service=service,
            username=username,
            host_id=host_id,
            destination=destination,
        )
        try:
            await self._emit(raw)
            self.emitted += 1
        except Exception:
            logger.exception("sensor %s failed to emit %s", self.name, event_type)
