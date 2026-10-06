from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.behavior.classifier import BehaviorClassifier
from app.behavior.features import FeatureExtractor
from app.behavior.profiler import AttackerProfiler, next_stage
from app.behavior.scoring import RiskScorer
from app.config import Settings
from app.database.repository import Repository
from app.deception.engine import DeceptionEngine
from app.events.bus import EventBus
from app.events.normalizer import EventNormalizer, RawEvent
from app.events.schema import SecurityEvent

logger = logging.getLogger(__name__)

SCORE_PERSIST_INTERVAL_SECONDS = 5.0


class Pipeline:
    """Event -> features -> behavior -> profile -> risk -> deception."""

    def __init__(
        self,
        settings: Settings,
        repository: Repository,
        bus: EventBus,
        extractor: FeatureExtractor,
        classifier: BehaviorClassifier,
        scorer: RiskScorer,
        profiler: AttackerProfiler,
        engine: DeceptionEngine,
        normalizer: EventNormalizer | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.bus = bus
        self.extractor = extractor
        self.classifier = classifier
        self.scorer = scorer
        self.profiler = profiler
        self.engine = engine
        self.normalizer = normalizer or EventNormalizer()
        self._last_score_save: dict[str, float] = {}
        self._last_triggered: dict[str, frozenset[str]] = {}
        self._last_band: dict[str, str] = {}

    async def process(self, raw: RawEvent) -> SecurityEvent:
        attacker = await self.repository.resolve_attacker(raw.source_ip)
        event = self.normalizer.normalize(raw, source_id=attacker.id)

        if event.event_type == "session_start" and event.session_id:
            await self.repository.open_session(event.session_id, event.sensor, attacker.id)
        elif event.event_type == "session_end" and event.session_id:
            await self.repository.close_session(event.session_id)

        await self.repository.record_event(event)
        self.bus.publish_nowait(
            "security_event", {"type": "security_event", "data": event.as_dict()}
        )

        self.extractor.observe(event)
        now = datetime.now(UTC)
        features = self.extractor.extract(attacker.id, now)
        scores = self.classifier.classify(features)
        risk_score, risk_band = self.scorer.score(scores, features)

        profile = self.profiler.update(
            attacker.id,
            source_ip=attacker.source_ip,
            scores=scores,
            risk_score=risk_score,
            risk_band=risk_band,
            event_count=attacker.event_count,
            seen_at=event.timestamp,
        )

        await self._persist_scores(attacker.id, scores, risk_score, risk_band, profile.stage)
        self.bus.publish_nowait(
            "attacker_updated",
            {"type": "attacker_updated", "data": profile.as_dict()},
        )

        if self._last_band.get(attacker.id) not in (None, risk_band):
            self.bus.publish_nowait(
                "risk_changed",
                {
                    "type": "risk_changed",
                    "data": {
                        "attacker_id": attacker.id,
                        "risk_score": risk_score,
                        "risk_band": risk_band,
                        "previous_band": self._last_band.get(attacker.id),
                    },
                },
            )
        self._last_band[attacker.id] = risk_band

        triggered = frozenset(self.classifier.triggered(scores))
        previous = self._last_triggered.get(attacker.id)
        if previous is not None and triggered != previous:
            self.bus.publish_nowait(
                "behavior_changed",
                {
                    "type": "behavior_changed",
                    "data": {
                        "attacker_id": attacker.id,
                        "behaviors": sorted(triggered),
                        "previous": sorted(previous),
                        "scores": scores,
                    },
                },
            )
        self._last_triggered[attacker.id] = triggered

        if self.classifier.qualifies(features):
            await self._run_deception(profile, features.total_events)

        return event

    async def _persist_scores(
        self,
        attacker_id: str,
        scores: dict[str, float],
        risk_score: float,
        risk_band: str,
        stage: str,
    ) -> None:
        await self.repository.update_attacker(
            attacker_id, risk_score=risk_score, risk_band=risk_band, stage=stage
        )
        last = self._last_score_save.get(attacker_id, 0.0)
        now = datetime.now(UTC).timestamp()
        if now - last < SCORE_PERSIST_INTERVAL_SECONDS:
            return
        self._last_score_save[attacker_id] = now
        await self.repository.save_behavior_scores(attacker_id, scores)

    async def _run_deception(self, profile: Any, event_count: int) -> None:
        try:
            decisions = await self.engine.evaluate(
                profile, extra_scores={"event_count": float(event_count)}
            )
        except Exception:
            logger.exception("deception evaluation failed for %s", profile.attacker_id)
            return
        for decision in decisions:
            stored = await self.repository.record_deception_action(decision.as_dict())
            self.bus.publish_nowait(
                "deception_changed",
                {"type": "deception_changed", "data": stored},
            )

    async def evaluate_profiles(self) -> int:
        """Periodic adaptive re-evaluation for all known profiles."""
        total = 0
        for profile in self.profiler.all():
            decisions = await self.engine.evaluate(profile)
            for decision in decisions:
                stored = await self.repository.record_deception_action(decision.as_dict())
                self.bus.publish_nowait(
                    "deception_changed",
                    {"type": "deception_changed", "data": stored},
                )
                total += 1
        return total


__all__ = ["Pipeline", "next_stage"]
