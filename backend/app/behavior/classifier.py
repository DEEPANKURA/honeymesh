from __future__ import annotations

from app.behavior.features import Features
from app.config import DetectionConfig

TRIGGER_THRESHOLD = 0.5


def _sat(value: float, ceiling: float) -> float:
    if ceiling <= 0:
        return 0.0
    return max(0.0, min(1.0, value / ceiling))


class BehaviorClassifier:
    """Rule-based behavioral classifier. Scores are normalized to 0.0 - 1.0."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def classify(self, features: Features) -> dict[str, float]:
        cfg = self.config
        recon = max(
            _sat(features.connection_count, cfg.scan_threshold),
            _sat(features.unique_ports, 10),
            _sat(features.service_enumeration, 4),
        )
        credential = max(
            _sat(features.authentication_failures, cfg.brute_force_threshold),
            _sat(features.unique_usernames, 8),
        )
        web = max(
            _sat(features.unique_http_paths, cfg.web_probe_threshold),
            _sat(features.suspicious_inputs, 5),
            _sat(features.request_rate, 60.0),
        )
        discovery = max(
            _sat(features.asset_interactions, cfg.discovery_threshold),
            _sat(features.service_enumeration, cfg.discovery_threshold),
        )
        lateral = max(
            _sat(features.unique_hosts, cfg.lateral_threshold),
            _sat(features.cross_host_attempts, cfg.lateral_threshold),
        )
        persistence = _sat(features.persistence_events, cfg.persistence_threshold)

        return {
            "recon": round(recon, 4),
            "credential": round(credential, 4),
            "web": round(web, 4),
            "discovery": round(discovery, 4),
            "lateral": round(lateral, 4),
            "persistence": round(persistence, 4),
        }

    def triggered(self, scores: dict[str, float]) -> list[str]:
        return [name for name, score in scores.items() if score >= TRIGGER_THRESHOLD]

    def qualifies(self, features: Features) -> bool:
        return features.total_events >= self.config.min_events_for_classification
