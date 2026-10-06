from __future__ import annotations

import pytest
from helpers import free_port

from app.behavior.profiler import AttackerProfile
from app.deception.credentials import SYNTHETIC_MARKER, SyntheticCredentialStore
from app.deception.engine import ALLOWED_ACTIONS, DeceptionEngine
from app.deception.orchestrator import DecoyOrchestrator, DecoySpec, UnknownDecoyError


def _orchestrator() -> DecoyOrchestrator:
    specs = {
        name: DecoySpec(name=name, type="http", port=free_port(), deception_level=3)
        for name in ("finance-srv", "hr-srv", "backup-srv")
    }
    return DecoyOrchestrator(specs)


def _profile(**scores: float) -> AttackerProfile:
    return AttackerProfile(attacker_id="A-001", source_ip="10.0.0.5", scores=scores)


@pytest.fixture
def engine(settings) -> DeceptionEngine:
    return DeceptionEngine(settings, _orchestrator(), SyntheticCredentialStore(seed=1))


@pytest.mark.asyncio
async def test_credential_policy_selects_bait_credentials(engine: DeceptionEngine) -> None:
    decisions = await engine.evaluate(_profile(credential=0.91))
    actions = {decision.action for decision in decisions}
    assert "deploy_fake_credentials" in actions
    assert "increase_auth_telemetry" in actions
    assert engine.credentials.enabled
    assert engine.state.telemetry_level == "high"
    assert engine.state.level == 2
    for decision in decisions:
        assert decision.reason
        assert decision.confidence >= 0.7
        assert decision.previous_state and decision.new_state


@pytest.mark.asyncio
async def test_discovery_policy_activates_enterprise_hosts(engine: DeceptionEngine) -> None:
    decisions = await engine.evaluate(_profile(discovery=0.8))
    assert engine.orchestrator.is_active("finance-srv")
    assert engine.orchestrator.is_active("hr-srv")
    assert engine.orchestrator.is_active("backup-srv")
    assert engine.state.level == 3
    assert {d.target for d in decisions if d.action.startswith("activate_")} >= {
        "finance-srv",
        "hr-srv",
        "backup-srv",
    }


@pytest.mark.asyncio
async def test_decisions_are_idempotent(engine: DeceptionEngine) -> None:
    first = await engine.evaluate(_profile(credential=0.91))
    assert first
    second = await engine.evaluate(_profile(credential=0.91))
    assert second == []


@pytest.mark.asyncio
async def test_cooldown_blocks_immediate_redecisions(settings) -> None:
    settings.deception.cooldown_seconds = 60.0
    engine = DeceptionEngine(settings, _orchestrator(), SyntheticCredentialStore(seed=1))
    assert await engine.evaluate(_profile(credential=0.91))
    blocked = await engine.evaluate(
        AttackerProfile(
            attacker_id="A-002",
            scores={"credential": 0.99, "discovery": 0.99, "recon": 0.99},
        )
    )
    assert blocked == []


@pytest.mark.asyncio
async def test_max_level_is_enforced(settings) -> None:
    settings.deception.max_level = 2
    engine = DeceptionEngine(settings, _orchestrator(), SyntheticCredentialStore(seed=1))
    await engine.evaluate(_profile(persistence=0.9, discovery=0.9))
    assert engine.state.level <= 2


@pytest.mark.asyncio
async def test_unknown_action_is_not_executed(engine: DeceptionEngine) -> None:
    engine.policy_engine.policies[0].actions = ["drop_tables", "format_disk"]
    decisions = await engine.evaluate(_profile(credential=0.99, recon=0.99, discovery=0.99))
    assert all(d.action in ALLOWED_ACTIONS for d in decisions)
    assert engine.state.applied_actions <= ALLOWED_ACTIONS


@pytest.mark.asyncio
async def test_orchestrator_rejects_non_allowlisted_decoy() -> None:
    orchestrator = _orchestrator()
    with pytest.raises(UnknownDecoyError):
        await orchestrator.activate("prod-database")
    with pytest.raises(UnknownDecoyError):
        await orchestrator.deactivate("prod-database")


@pytest.mark.asyncio
async def test_orchestrator_is_idempotent_and_stoppable(engine: DeceptionEngine) -> None:
    assert await engine.orchestrator.activate("finance-srv") is True
    assert await engine.orchestrator.activate("finance-srv") is False
    assert await engine.orchestrator.deactivate("finance-srv") is True
    assert not engine.orchestrator.is_active("finance-srv")


@pytest.mark.asyncio
async def test_synthetic_credentials_are_marked(engine: DeceptionEngine) -> None:
    await engine.evaluate(_profile(credential=0.91))
    credentials = engine.credentials.credentials
    assert credentials
    assert all(
        SYNTHETIC_MARKER in value or "Simulation" in value or "LabOnly" in value
        for value in credentials.values()
    )
    user, password = next(iter(credentials.items()))
    assert engine.credentials.accept(user, password)
    assert not engine.credentials.accept(user, "wrong")
    assert not engine.credentials.accept("nobody", password)
