from __future__ import annotations

import pytest

from app.config import PolicyConfig
from app.deception.policies import PolicyConditionError, PolicyEngine, evaluate_condition


def test_condition_operators() -> None:
    assert evaluate_condition(">0.70", 0.71)
    assert not evaluate_condition(">0.70", 0.70)
    assert evaluate_condition(">=0.70", 0.70)
    assert evaluate_condition("<0.3", 0.2)
    assert evaluate_condition("<=0.3", 0.3)
    assert evaluate_condition("==1.0", 1.0)


def test_invalid_condition_rejected() -> None:
    with pytest.raises(PolicyConditionError):
        evaluate_condition("__import__('os')", 1.0)


def test_policy_engine_matches_score_keys() -> None:
    policy = PolicyConfig(
        name="credential_attack",
        conditions={"credential_score": ">0.70"},
        actions=["deploy_fake_credentials"],
        escalate_to_level=2,
    )
    engine = PolicyEngine([policy])
    assert engine.evaluate({"credential": 0.91})
    assert not engine.evaluate({"credential": 0.20})


def test_policy_engine_supports_risk_score_extra() -> None:
    policy = PolicyConfig(name="risk", conditions={"risk_score": ">0.80"})
    engine = PolicyEngine([policy])
    assert engine.evaluate({}, extra={"risk_score": 0.9})
    assert not engine.evaluate({}, extra={"risk_score": 0.1})


def test_matches_sorted_by_confidence() -> None:
    low = PolicyConfig(name="low", conditions={"recon_score": ">0.4"})
    high = PolicyConfig(name="high", conditions={"recon_score": ">0.8"})
    engine = PolicyEngine([low, high])
    matches = engine.evaluate({"recon": 0.95})
    assert [m.policy.name for m in matches] == ["high", "low"]
    assert matches[0].confidence == 0.95
