from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.behavior.features import FeatureExtractor
from app.events.normalizer import EventNormalizer, RawEvent


def _event(
    event_type: str,
    ip: str = "10.0.0.7",
    sensor: str = "honeyssh",
    username: str | None = None,
    metadata: dict | None = None,
    host_id: str | None = None,
    ts: datetime | None = None,
):
    raw = RawEvent(
        sensor=sensor,
        event_type=event_type,
        source_ip=ip,
        username=username,
        metadata=metadata or {},
        host_id=host_id,
        timestamp=ts,
    )
    return EventNormalizer().normalize(raw, source_id="A-001")


def test_window_counts_and_uniques() -> None:
    extractor = FeatureExtractor(window_seconds=300)
    for port in (22, 80, 443, 3306):
        extractor.observe(_event("connection_attempt", metadata={"port": port}))
    for user in ("admin", "root", "test"):
        extractor.observe(
            _event("authentication_attempt", username=user, metadata={"username": user})
        )
    extractor.observe(_event("session_command", metadata={"command": "netstat -tlnp"}))

    features = extractor.extract("A-001")
    assert features.connection_count == 4
    assert features.unique_ports == 4
    assert features.authentication_failures == 3
    assert features.unique_usernames == 3
    assert features.total_events == 8


def test_old_events_fall_out_of_window() -> None:
    extractor = FeatureExtractor(window_seconds=60)
    old = datetime.now(UTC) - timedelta(seconds=120)
    extractor.observe(_event("connection_attempt", ts=old))
    extractor.observe(_event("connection_attempt"))
    features = extractor.extract("A-001")
    assert features.connection_count == 1
    assert features.total_events == 1


def test_cross_host_and_asset_tracking() -> None:
    extractor = FeatureExtractor(window_seconds=300)
    extractor.observe(_event("connection_attempt", host_id="finance-srv"))
    extractor.observe(_event("asset_access", sensor="honeyweb", host_id="finance-srv"))
    features = extractor.extract("A-001")
    assert features.unique_hosts == 1
    assert features.asset_interactions == 1
    assert features.cross_host_attempts == 1
