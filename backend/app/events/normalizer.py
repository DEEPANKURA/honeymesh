from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.events.schema import SecurityEvent, Severity, default_severity


class RawEvent(BaseModel):
    """Event as produced by a sensor or received by the ingest endpoint."""

    model_config = ConfigDict(extra="forbid")

    sensor: str
    event_type: str
    source_ip: str
    severity: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    destination: str | None = None
    service: str | None = None
    username: str | None = None
    host_id: str | None = None
    timestamp: datetime | None = None

    @field_validator("source_ip")
    @classmethod
    def _non_empty_ip(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("source_ip must not be empty")
        return value.strip()


class EventNormalizer:
    """Validates raw sensor events and assigns canonical identity fields."""

    def normalize(self, raw: RawEvent, source_id: str = "") -> SecurityEvent:
        if raw.severity in {"info", "low", "medium", "high", "critical"}:
            severity = cast(Severity, raw.severity)
        else:
            severity = default_severity(raw.event_type)
        timestamp = raw.timestamp
        if timestamp is None:
            timestamp = datetime.now(UTC)
        elif timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return SecurityEvent(
            event_id=f"evt-{uuid4().hex[:16]}",
            timestamp=timestamp,
            source_id=source_id,
            source_ip=raw.source_ip,
            sensor=raw.sensor,
            event_type=raw.event_type,
            severity=severity,
            metadata=raw.metadata,
            session_id=raw.session_id,
            destination=raw.destination,
            service=raw.service,
            username=raw.username,
            host_id=raw.host_id,
        )
