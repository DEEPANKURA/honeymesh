from __future__ import annotations

import pytest

from app.behavior.profiler import AttackerProfiler, next_stage


def test_profiler_creates_and_updates() -> None:
    profiler = AttackerProfiler()
    profile = profiler.update("A-001", source_ip="10.0.0.5", scores={"recon": 0.6})
    assert profile.attacker_id == "A-001"
    assert profile.source_ip == "10.0.0.5"
    assert profile.first_seen is not None
    updated = profiler.update("A-001", scores={"recon": 0.9}, risk_score=0.55, risk_band="HIGH")
    assert updated.first_seen is not None
    assert updated.last_seen is not None
    assert updated.last_seen >= updated.first_seen
    assert updated.risk_band == "HIGH"
    assert profiler.get("A-001") is updated


def test_profile_serialization() -> None:
    profiler = AttackerProfiler()
    profile = profiler.update("A-002", scores={"credential": 0.8}, event_count=12)
    data = profile.as_dict()
    assert data["attacker_id"] == "A-002"
    assert data["scores"]["credential"] == 0.8
    assert data["event_count"] == 12
    assert data["first_seen"]


@pytest.mark.parametrize(
    ("scores", "expected"),
    [
        ({}, "UNKNOWN"),
        ({"recon": 0.9}, "RECON"),
        ({"recon": 0.9, "credential": 0.9}, "INITIAL_ACCESS"),
        ({"recon": 0.9, "credential": 0.9, "discovery": 0.9}, "DISCOVERY"),
        (
            {
                "recon": 0.9,
                "credential": 0.9,
                "discovery": 0.9,
                "lateral": 0.9,
                "persistence": 0.9,
            },
            "PERSISTENCE_LIKE",
        ),
    ],
)
def test_stage_progression(scores: dict[str, float], expected: str) -> None:
    profiler = AttackerProfiler()
    profile = profiler.update("A-003", scores=scores)
    assert profile.stage == expected


def test_stage_advances_on_direct_evidence() -> None:
    assert next_stage("UNKNOWN", {"discovery": 0.9}) == "DISCOVERY"
