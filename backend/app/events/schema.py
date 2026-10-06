from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class SecurityEvent(BaseModel):
    """Normalized, strongly typed security event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    source_id: str
    source_ip: str
    sensor: str
    event_type: str
    severity: Severity
    metadata: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    destination: str | None = None
    service: str | None = None
    username: str | None = None
    host_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


EVENT_TYPES: dict[str, Severity] = {
    "connection_attempt": "info",
    "port_probe": "low",
    "service_banner": "info",
    "authentication_attempt": "medium",
    "authentication_success": "high",
    "session_start": "medium",
    "session_end": "info",
    "session_command": "medium",
    "http_request": "info",
    "http_suspicious_input": "high",
    "path_enumeration": "medium",
    "asset_access": "medium",
    "credential_harvest": "high",
    "service_enumeration": "medium",
    "deception_action": "info",
    "system": "info",
}


def default_severity(event_type: str) -> Severity:
    return EVENT_TYPES.get(event_type, "info")
