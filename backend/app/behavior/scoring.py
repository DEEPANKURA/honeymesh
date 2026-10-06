from __future__ import annotations

from app.behavior.features import Features
from app.config import RiskConfig

EVENTS_PER_MINUTE_REF = 40.0

BAND_ORDER = ("LOW", "MODERATE", "HIGH", "CRITICAL")


def band_for(score: float, bands: dict[str, float]) -> str:
    if score >= bands.get("high", 0.75):
        return "CRITICAL"
    if score >= bands.get("moderate", 0.50):
        return "HIGH"
    if score >= bands.get("low", 0.25):
        return "MODERATE"
    return "LOW"


class RiskScorer:
    """Weighted, normalized (0.0 - 1.0) risk model. Weights come from config.

    The behavioral component is averaged over behaviors that actually show
    evidence, so a single strong behavior can still produce a high band.
    A velocity factor blends in event rate. Documented in docs/adaptive-engine.md.
    """

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def score(self, behavior_scores: dict[str, float], features: Features) -> tuple[float, str]:
        weights = self.config.weights
        active = [
            name for name in weights if behavior_scores.get(name, 0.0) > 0.0 and weights[name] > 0.0
        ]
        if active:
            weight_sum = sum(weights[name] for name in active) or 1.0
            base = (
                sum(
                    weights[name] * min(1.0, max(0.0, behavior_scores.get(name, 0.0)))
                    for name in active
                )
                / weight_sum
            )
        else:
            base = 0.0

        velocity = max(0.0, min(1.0, (features.request_rate or 0.0) / EVENTS_PER_MINUTE_REF))
        velocity_weight = max(0.0, min(1.0, self.config.velocity_weight))

        risk = base * (1.0 - velocity_weight) + velocity * velocity_weight
        risk = max(0.0, min(1.0, risk))
        return round(risk, 4), band_for(risk, self.config.bands)
