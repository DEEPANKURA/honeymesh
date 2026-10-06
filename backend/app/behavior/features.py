from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.events.schema import SecurityEvent

CONNECTION_TYPES = {"connection_attempt", "port_probe", "session_start"}
AUTH_FAILURE_TYPES = {"authentication_attempt"}
AUTH_SUCCESS_TYPES = {"authentication_success"}
ASSET_TYPES = {"asset_access", "session_command"}


@dataclass
class Features:
    window_seconds: int = 300
    connection_count: int = 0
    unique_ports: int = 0
    unique_services: int = 0
    authentication_failures: int = 0
    authentication_successes: int = 0
    unique_usernames: int = 0
    request_rate: float = 0.0
    unique_http_paths: int = 0
    unique_hosts: int = 0
    session_duration: float = 0.0
    asset_interactions: int = 0
    suspicious_inputs: int = 0
    service_enumeration: int = 0
    cross_host_attempts: int = 0
    persistence_events: int = 0
    total_events: int = 0

    def as_dict(self) -> dict[str, float]:
        return {
            "connection_count": float(self.connection_count),
            "unique_ports": float(self.unique_ports),
            "unique_services": float(self.unique_services),
            "authentication_failures": float(self.authentication_failures),
            "authentication_successes": float(self.authentication_successes),
            "unique_usernames": float(self.unique_usernames),
            "request_rate": self.request_rate,
            "unique_http_paths": float(self.unique_http_paths),
            "unique_hosts": float(self.unique_hosts),
            "session_duration": self.session_duration,
            "asset_interactions": float(self.asset_interactions),
            "suspicious_inputs": float(self.suspicious_inputs),
            "service_enumeration": float(self.service_enumeration),
            "cross_host_attempts": float(self.cross_host_attempts),
            "persistence_events": float(self.persistence_events),
            "total_events": float(self.total_events),
        }


@dataclass
class _AttackerWindow:
    events: deque[tuple[datetime, SecurityEvent]] = field(default_factory=deque)


class FeatureExtractor:
    """Sliding-window feature extraction per attacker."""

    def __init__(self, window_seconds: int = 300, max_events: int = 5000) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._window_seconds = window_seconds
        self._max_events = max_events
        self._windows: dict[str, _AttackerWindow] = defaultdict(
            lambda: _AttackerWindow(deque(maxlen=max_events))
        )

    def observe(self, event: SecurityEvent) -> None:
        window = self._windows[event.source_id]
        window.events.append((event.timestamp, event))

    def forget(self, attacker_id: str) -> None:
        self._windows.pop(attacker_id, None)

    def extract(self, attacker_id: str, now: datetime | None = None) -> Features:
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        cutoff = now - self._window
        entries = [item for item in self._windows[attacker_id].events if item[0] >= cutoff]
        events = [event for _, event in entries]

        ports: set[str] = set()
        services: set[str] = set()
        usernames: set[str] = set()
        paths: set[str] = set()
        hosts: set[str] = set()
        failures = successes = connections = assets = suspicious = enumeration = 0
        cross_host = persistence = 0
        entry_sensors = {event.sensor for event in events}

        for event in events:
            meta = event.metadata
            if event.event_type in CONNECTION_TYPES:
                connections += 1
                if meta.get("port") is not None:
                    ports.add(str(meta["port"]))
            if event.event_type in AUTH_FAILURE_TYPES:
                failures += 1
            if event.event_type in AUTH_SUCCESS_TYPES:
                successes += 1
            if event.event_type in ASSET_TYPES:
                assets += 1
            if event.event_type in {"http_suspicious_input", "path_enumeration"}:
                suspicious += 1
            if event.event_type == "service_enumeration":
                enumeration += 1
            if event.event_type == "persistence_attempt":
                persistence += 1
            if event.username:
                usernames.add(event.username)
            if meta.get("username"):
                usernames.add(str(meta["username"]))
            if meta.get("path"):
                paths.add(str(meta["path"]))
            service = event.service or meta.get("service") or event.sensor
            if service:
                services.add(str(service))
            target_host = event.host_id or meta.get("target_host")
            if target_host:
                hosts.add(str(target_host))
                if str(target_host) not in entry_sensors and event.event_type in CONNECTION_TYPES:
                    cross_host += 1

        span = 0.0
        if len(entries) >= 2:
            span = (entries[-1][0] - entries[0][0]).total_seconds()
        minutes = max(self._window_seconds / 60.0, 1e-6)

        return Features(
            window_seconds=self._window_seconds,
            connection_count=connections,
            unique_ports=len(ports),
            unique_services=len(services),
            authentication_failures=failures,
            authentication_successes=successes,
            unique_usernames=len(usernames),
            request_rate=round(len(events) / minutes, 4),
            unique_http_paths=len(paths),
            unique_hosts=len(hosts),
            session_duration=span,
            asset_interactions=assets,
            suspicious_inputs=suspicious,
            service_enumeration=enumeration,
            cross_host_attempts=cross_host,
            persistence_events=persistence,
            total_events=len(events),
        )
