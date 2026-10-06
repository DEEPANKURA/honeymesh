from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

STAGE_ORDER = (
    "UNKNOWN",
    "RECON",
    "INITIAL_ACCESS",
    "DISCOVERY",
    "LATERAL_ACTIVITY",
    "PERSISTENCE_LIKE",
)

STAGE_EVIDENCE: dict[str, tuple[str, float]] = {
    "RECON": ("recon", 0.50),
    "INITIAL_ACCESS": ("credential", 0.60),
    "DISCOVERY": ("discovery", 0.60),
    "LATERAL_ACTIVITY": ("lateral", 0.60),
    "PERSISTENCE_LIKE": ("persistence", 0.55),
}


@dataclass
class AttackerProfile:
    attacker_id: str
    source_ip: str = ""
    scores: dict[str, float] = field(default_factory=dict)
    stage: str = "UNKNOWN"
    risk_score: float = 0.0
    risk_band: str = "LOW"
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    strategies: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attacker_id": self.attacker_id,
            "source_ip": self.source_ip,
            "scores": dict(self.scores),
            "current_stage": self.stage,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "strategies": list(self.strategies),
        }


def next_stage(current: str, scores: dict[str, float]) -> str:
    """Advance (never regress) through the experimental attacker state machine.

    A stage is reached when its own evidence threshold is met; missing evidence
    for earlier stages does not block progress (recon may simply be unobserved).
    """
    order = list(STAGE_ORDER)
    if current not in order:
        current = "UNKNOWN"
    current_index = order.index(current)
    target_index = current_index
    for index, stage in enumerate(order):
        if index == 0:
            continue
        metric, threshold = STAGE_EVIDENCE[stage]
        if scores.get(metric, 0.0) >= threshold and index > target_index:
            target_index = index
    return order[target_index]


class AttackerProfiler:
    def __init__(self) -> None:
        self._profiles: dict[str, AttackerProfile] = {}

    def get(self, attacker_id: str) -> AttackerProfile | None:
        return self._profiles.get(attacker_id)

    def all(self) -> list[AttackerProfile]:
        return list(self._profiles.values())

    def remove(self, attacker_id: str) -> None:
        self._profiles.pop(attacker_id, None)

    def update(
        self,
        attacker_id: str,
        *,
        source_ip: str = "",
        scores: dict[str, float] | None = None,
        risk_score: float = 0.0,
        risk_band: str = "LOW",
        event_count: int = 0,
        seen_at: datetime | None = None,
    ) -> AttackerProfile:
        seen_at = seen_at or datetime.now(UTC)
        profile = self._profiles.setdefault(attacker_id, AttackerProfile(attacker_id=attacker_id))
        if source_ip:
            profile.source_ip = source_ip
        if scores:
            profile.scores = dict(scores)
            profile.stage = next_stage(profile.stage, scores)
        profile.risk_score = risk_score
        profile.risk_band = risk_band
        profile.event_count = event_count
        if profile.first_seen is None:
            profile.first_seen = seen_at
        profile.last_seen = seen_at
        return profile
