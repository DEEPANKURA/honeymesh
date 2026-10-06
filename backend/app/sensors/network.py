from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque

from app.config import NetworkSensorConfig
from app.sensors.base import EmitFn, SensorBase

logger = logging.getLogger(__name__)

SCAN_WINDOW_SECONDS = 15.0
SCAN_THRESHOLD = 8
SCAN_REPORT_COOLDOWN = 30.0
IDLE_READ_TIMEOUT = 1.0


class NetworkSensor(SensorBase):
    """Decoy TCP listener that records connection attempts and burst scanning."""

    name = "honeynet"

    def __init__(self, config: NetworkSensorConfig, emit: EmitFn) -> None:
        super().__init__(emit)
        self.config = config
        self._server: asyncio.Server | None = None
        self._recent: dict[str, deque[float]] = defaultdict(deque)
        self._last_scan_alert: dict[str, float] = {}

    async def start(self) -> None:
        if not self.config.enabled or self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle, self.config.host, self.config.port)
        logger.info("network sensor listening on %s:%s", self.config.host, self.config.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "0.0.0.0"
        await self.emit_event(
            "connection_attempt",
            client_ip,
            service="decoy-listener",
            metadata={"port": self.config.port, "service": "unknown", "protocol": "tcp"},
        )
        await self._track_scan(client_ip)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=IDLE_READ_TIMEOUT)
        except (TimeoutError, ConnectionError):
            data = b""
        if data:
            await self.emit_event(
                "service_banner",
                client_ip,
                service="decoy-listener",
                metadata={
                    "port": self.config.port,
                    "bytes": len(data),
                    "preview": data[:80].decode(errors="replace"),
                },
            )
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def _track_scan(self, client_ip: str) -> None:
        now = time.monotonic()
        window = self._recent[client_ip]
        window.append(now)
        while window and now - window[0] > SCAN_WINDOW_SECONDS:
            window.popleft()
        if len(window) < SCAN_THRESHOLD:
            return
        last_alert = self._last_scan_alert.get(client_ip, 0.0)
        if now - last_alert < SCAN_REPORT_COOLDOWN:
            return
        self._last_scan_alert[client_ip] = now
        window.clear()
        await self.emit_event(
            "service_enumeration",
            client_ip,
            severity="medium",
            service="decoy-listener",
            metadata={
                "count": SCAN_THRESHOLD,
                "window_seconds": SCAN_WINDOW_SECONDS,
                "port": self.config.port,
                "detail": "burst of connection attempts from a single source",
            },
        )
