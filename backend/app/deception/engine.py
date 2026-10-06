from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.behavior.profiler import AttackerProfile
from app.config import Settings
from app.deception.credentials import SyntheticCredentialStore
from app.deception.orchestrator import DecoyOrchestrator, UnknownDecoyError
from app.deception.policies import MatchResult, PolicyEngine
from app.deception.state import DeceptionState

logger = logging.getLogger(__name__)

DECOY_ACTIONS: dict[str, str] = {
    "activate_finance_srv": "finance-srv",
    "activate_hr_srv": "hr-srv",
    "activate_backup_srv": "backup-srv",
}

FLAG_ACTIONS: dict[str, str] = {
    "increase_auth_telemetry": "auth_telemetry",
    "increase_web_telemetry": "web_telemetry",
    "increase_cross_host_correlation": "cross_host_correlation",
    "activate_admin_portal": "admin_portal",
    "deploy_persistence_decoy": "persistence_decoy",
}

TELEMETRY_ACTIONS = {"increase_telemetry"}
CREDENTIAL_ACTIONS = {"deploy_fake_credentials"}
LEVEL_ACTION = "escalate_level"

ALLOWED_ACTIONS = (
    set(DECOY_ACTIONS) | set(FLAG_ACTIONS) | TELEMETRY_ACTIONS | CREDENTIAL_ACTIONS | {LEVEL_ACTION}
)


@dataclass
class DeceptionDecision:
    action: str
    target: str
    reason: str
    confidence: float
    policy: str = ""
    attacker_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    previous_state: dict[str, Any] = field(default_factory=dict)
    new_state: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attacker_id": self.attacker_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "confidence": round(self.confidence, 4),
            "policy": self.policy,
            "timestamp": self.timestamp.isoformat(),
            "previous_state": self.previous_state,
            "new_state": self.new_state,
        }


class DeceptionEngine:
    """Selects deception policy actions from attacker behavior scores."""

    def __init__(
        self,
        settings: Settings,
        orchestrator: DecoyOrchestrator,
        credentials: SyntheticCredentialStore,
        state: DeceptionState | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.settings = settings
        self.orchestrator = orchestrator
        self.credentials = credentials
        self.state = state or DeceptionState()
        self.policy_engine = policy_engine or PolicyEngine(settings.policies)
        self._last_decision_at: datetime | None = None

    @property
    def adaptive(self) -> bool:
        return self.settings.deception.adaptive_mode

    def _in_cooldown(self, now: datetime) -> bool:
        if self._last_decision_at is None:
            return False
        elapsed = (now - self._last_decision_at).total_seconds()
        return elapsed < self.settings.deception.cooldown_seconds

    def _already_effective(self, action: str) -> bool:
        state = self.state
        if action in TELEMETRY_ACTIONS:
            return state.telemetry_level != "normal"
        if action in CREDENTIAL_ACTIONS:
            return self.credentials.enabled
        if action in FLAG_ACTIONS:
            return FLAG_ACTIONS[action] in state.flags
        decoy = DECOY_ACTIONS.get(action)
        if decoy is not None:
            return self.orchestrator.is_active(decoy) or decoy in state.active_decoys
        return True  # unknown actions are never executed

    @staticmethod
    def _reason(match: MatchResult) -> str:
        evidence = ", ".join(
            f"{key}={match.policy.conditions[key]} (observed {value:.2f})"
            for key, value in match.evidence.items()
        )
        description = f" - {match.policy.description}" if match.policy.description else ""
        return f"policy '{match.policy.name}' matched: {evidence}{description}"

    async def _apply(
        self, action: str, match: MatchResult, attacker_id: str | None
    ) -> DeceptionDecision | None:
        if action not in ALLOWED_ACTIONS:
            logger.warning("skipping unknown deception action: %s", action)
            return None

        previous = self.state.snapshot()
        target = ""
        reason = self._reason(match)

        if action in DECOY_ACTIONS:
            decoy = DECOY_ACTIONS[action]
            target = decoy
            try:
                await self.orchestrator.activate(decoy)
            except UnknownDecoyError as exc:
                logger.error("decoy activation rejected: %s", exc)
                return None
            self.state.active_decoys.add(decoy)
        elif action in FLAG_ACTIONS:
            flag = FLAG_ACTIONS[action]
            target = flag
            self.state.flags.add(flag)
            if "telemetry" in action:
                self.state.telemetry_level = "high"
        elif action in TELEMETRY_ACTIONS:
            target = "telemetry"
            self.state.telemetry_level = "high"
        elif action in CREDENTIAL_ACTIONS:
            target = "synthetic_credentials"
            if not self.credentials.enabled:
                self.credentials.seed_credentials()

        self.state.applied_actions.add(action)
        self.state.strategy = match.policy.name
        self.state.updated_at = datetime.now(UTC)
        return DeceptionDecision(
            action=action,
            target=target,
            reason=reason,
            confidence=match.confidence,
            policy=match.policy.name,
            attacker_id=attacker_id,
            previous_state=previous,
            new_state=self.state.snapshot(),
        )

    async def evaluate(
        self, profile: AttackerProfile, extra_scores: dict[str, float] | None = None
    ) -> list[DeceptionDecision]:
        if not self.adaptive:
            return []
        now = datetime.now(UTC)
        if self._in_cooldown(now):
            return []
        if not profile.scores:
            return []

        extra = dict(extra_scores or {})
        extra.setdefault("risk_score", profile.risk_score)
        matches = self.policy_engine.evaluate(profile.scores, extra)
        if not matches:
            return []

        decisions: list[DeceptionDecision] = []
        for match in matches:
            for action in match.policy.actions:
                if self._already_effective(action):
                    continue
                decision = await self._apply(action, match, profile.attacker_id)
                if decision is not None:
                    decisions.append(decision)

        target_level = min(
            self.settings.deception.max_level,
            max((m.policy.escalate_to_level for m in matches), default=self.state.level),
        )
        if target_level > self.state.level:
            previous = self.state.snapshot()
            self.state.level = target_level
            self.state.updated_at = now
            decisions.append(
                DeceptionDecision(
                    action=LEVEL_ACTION,
                    target=f"level-{target_level}",
                    reason=(
                        f"policy '{matches[0].policy.name}' requires deception level "
                        f"{target_level} (max {self.settings.deception.max_level})"
                    ),
                    confidence=matches[0].confidence,
                    policy=matches[0].policy.name,
                    attacker_id=profile.attacker_id,
                    previous_state=previous,
                    new_state=self.state.snapshot(),
                )
            )

        if decisions:
            self._last_decision_at = now
        return decisions
