from __future__ import annotations

from datetime import datetime

from app.events.normalizer import EventNormalizer, RawEvent
from app.events.schema import SecurityEvent


def test_normalize_assigns_identity_fields() -> None:
    normalizer = EventNormalizer()
    raw = RawEvent(
        sensor="honeyssh",
        event_type="authentication_attempt",
        source_ip="10.0.0.5",
        metadata={"username": "admin"},
    )
    event = normalizer.normalize(raw, source_id="A-001")
    assert event.event_id.startswith("evt-")
    assert event.source_id == "A-001"
    assert event.severity == "medium"
    assert event.timestamp.tzinfo is not None
    assert event.metadata["username"] == "admin"


def test_normalize_defaults_severity_by_event_type() -> None:
    normalizer = EventNormalizer()
    raw = RawEvent(sensor="honeyweb", event_type="http_suspicious_input", source_ip="10.0.0.5")
    assert normalizer.normalize(raw).severity == "high"


def test_normalize_keeps_explicit_severity() -> None:
    normalizer = EventNormalizer()
    raw = RawEvent(
        sensor="honeynet",
        event_type="connection_attempt",
        source_ip="10.0.0.5",
        severity="low",
    )
    assert normalizer.normalize(raw).severity == "low"


def test_naive_timestamp_treated_as_utc() -> None:
    normalizer = EventNormalizer()
    raw = RawEvent(
        sensor="honeyweb",
        event_type="http_request",
        source_ip="10.0.0.5",
        timestamp=datetime(2026, 10, 6, 12, 0, 0),
    )
    event = normalizer.normalize(raw)
    assert event.timestamp.isoformat().endswith("+00:00")


def test_rejects_empty_source_ip() -> None:
    import pytest

    with pytest.raises(ValueError):
        RawEvent(sensor="x", event_type="y", source_ip="   ")


def test_security_event_rejects_unknown_severity() -> None:
    import pytest

    with pytest.raises(ValueError):
        SecurityEvent(
            event_id="evt-1",
            timestamp=datetime.utcnow(),
            source_id="A-001",
            source_ip="10.0.0.5",
            sensor="x",
            event_type="y",
            severity="extreme",  # type: ignore[arg-type]
        )
