from __future__ import annotations

import re
from dataclasses import dataclass

from app.config import PolicyConfig

CONDITION_PATTERN = re.compile(r"^(>=|<=|==|>|<)?\s*(-?\d+(?:\.\d+)?)$")


@dataclass(frozen=True)
class MatchResult:
    policy: PolicyConfig
    confidence: float
    evidence: dict[str, float]
    threshold: float = 0.0


class PolicyConditionError(ValueError):
    pass


def evaluate_condition(expression: str, value: float) -> bool:
    match = CONDITION_PATTERN.match(expression.strip())
    if not match:
        raise PolicyConditionError(f"unsupported condition: {expression!r}")
    operator = match.group(1) or ">="
    threshold = float(match.group(2))
    if operator == ">":
        return value > threshold
    if operator == "<":
        return value < threshold
    if operator == ">=":
        return value >= threshold
    if operator == "<=":
        return value <= threshold
    return abs(value - threshold) < 1e-9


def resolve_value(key: str, scores: dict[str, float], extra: dict[str, float]) -> float | None:
    if key in extra:
        return extra[key]
    if key.endswith("_score"):
        base = key[: -len("_score")]
        if base in scores:
            return scores[base]
    if key in scores:
        return scores[key]
    return None


class PolicyEngine:
    """Declarative policy matcher. Conditions are strings like '>0.70'."""

    def __init__(self, policies: list[PolicyConfig]) -> None:
        self.policies = list(policies)

    def evaluate(
        self, scores: dict[str, float], extra: dict[str, float] | None = None
    ) -> list[MatchResult]:
        extra = extra or {}
        matches: list[MatchResult] = []
        for policy in self.policies:
            if not policy.conditions:
                continue
            evidence: dict[str, float] = {}
            thresholds: list[float] = []
            ok = True
            for key, expression in policy.conditions.items():
                value = resolve_value(key, scores, extra)
                if value is None:
                    ok = False
                    break
                try:
                    if not evaluate_condition(expression, value):
                        ok = False
                        break
                except PolicyConditionError:
                    ok = False
                    break
                evidence[key] = value
                match = CONDITION_PATTERN.match(expression.strip())
                if match:
                    thresholds.append(float(match.group(2)))
            if ok:
                confidence = max(evidence.values(), default=0.0)
                matches.append(
                    MatchResult(
                        policy=policy,
                        confidence=confidence,
                        evidence=evidence,
                        threshold=max(thresholds, default=0.0),
                    )
                )
        matches.sort(key=lambda item: (item.confidence, item.threshold), reverse=True)
        return matches
