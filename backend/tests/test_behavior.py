from __future__ import annotations

from app.behavior.classifier import BehaviorClassifier
from app.behavior.features import Features
from app.behavior.profiler import next_stage
from app.behavior.scoring import RiskScorer, band_for


def test_classifier_scores_are_normalized() -> None:
    classifier = BehaviorClassifier()
    features = Features(
        connection_count=100,
        unique_ports=50,
        authentication_failures=100,
        unique_usernames=50,
        unique_http_paths=100,
        asset_interactions=100,
        unique_hosts=50,
        persistence_events=100,
        suspicious_inputs=50,
        service_enumeration=50,
        request_rate=1000.0,
    )
    scores = classifier.classify(features)
    assert set(scores) == {"recon", "credential", "web", "discovery", "lateral", "persistence"}
    assert all(0.0 <= value <= 1.0 for value in scores.values())
    assert scores["recon"] == 1.0
    assert scores["credential"] == 1.0
    assert scores["persistence"] == 1.0


def test_classifier_quiet_baseline() -> None:
    classifier = BehaviorClassifier()
    scores = classifier.classify(Features())
    assert all(value == 0.0 for value in scores.values())
    assert classifier.triggered(scores) == []


def test_min_events_gate() -> None:
    classifier = BehaviorClassifier()
    assert not classifier.qualifies(Features(total_events=2))
    assert classifier.qualifies(Features(total_events=10))


def test_risk_score_normalized_and_banded() -> None:
    scorer = RiskScorer()
    score, band = scorer.score(
        {
            "recon": 1.0,
            "credential": 1.0,
            "web": 1.0,
            "discovery": 1.0,
            "lateral": 1.0,
            "persistence": 1.0,
        },
        Features(request_rate=1000.0, window_seconds=300),
    )
    assert 0.0 <= score <= 1.0
    assert band in {"HIGH", "CRITICAL"}

    score_low, band_low = scorer.score(
        {
            "recon": 0.0,
            "credential": 0.0,
            "web": 0.0,
            "discovery": 0.0,
            "lateral": 0.0,
            "persistence": 0.0,
        },
        Features(window_seconds=300),
    )
    assert score_low == 0.0
    assert band_low == "LOW"


def test_band_boundaries() -> None:
    bands = {"low": 0.25, "moderate": 0.5, "high": 0.75}
    assert band_for(0.10, bands) == "LOW"
    assert band_for(0.30, bands) == "MODERATE"
    assert band_for(0.60, bands) == "HIGH"
    assert band_for(0.90, bands) == "CRITICAL"


def test_stage_machine_advances_with_evidence() -> None:
    assert next_stage("UNKNOWN", {}) == "UNKNOWN"
    assert next_stage("UNKNOWN", {"recon": 0.8}) == "RECON"
    assert next_stage("RECON", {"recon": 0.8, "credential": 0.9}) == "INITIAL_ACCESS"
    assert (
        next_stage(
            "INITIAL_ACCESS",
            {"recon": 0.8, "credential": 0.9, "discovery": 0.9, "lateral": 0.9},
        )
        == "LATERAL_ACTIVITY"
    )


def test_stage_machine_never_regresses() -> None:
    assert next_stage("DISCOVERY", {"recon": 0.9}) == "DISCOVERY"
