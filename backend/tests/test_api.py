from __future__ import annotations

import pytest


async def _login(client) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "unit-test-password-123"},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_health(client) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_login_and_me(client) -> None:
    token = await _login(client)
    response = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"username": "admin", "role": "admin"}


@pytest.mark.asyncio
async def test_login_rejects_bad_password(client) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_action_requires_token(client) -> None:
    response = await client.post("/api/v1/deception/decoys/finance-srv/activate")
    assert response.status_code == 401

    token = await _login(client)
    response = await client.post(
        "/api/v1/deception/decoys/finance-srv/activate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "finance-srv"


@pytest.mark.asyncio
async def test_unknown_decoy_activate_is_404(client) -> None:
    token = await _login(client)
    response = await client.post(
        "/api/v1/deception/decoys/not-a-real-host/activate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_ingest_and_query_events(client) -> None:
    payload = {
        "sensor": "honeyssh",
        "event_type": "authentication_attempt",
        "source_ip": "10.10.0.9",
        "metadata": {"username": "admin", "result": "failure"},
    }
    response = await client.post("/api/v1/ingest/events", json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 1
    event_id = body["event_ids"][0]

    single = await client.get(f"/api/v1/events/{event_id}")
    assert single.status_code == 200
    assert single.json()["source_ip"] == "10.10.0.9"

    listing = await client.get("/api/v1/events", params={"sensor": "honeyssh"})
    assert listing.status_code == 200
    data = listing.json()
    assert data["total"] >= 1
    assert all(item["sensor"] == "honeyssh" for item in data["items"])

    missing = await client.get("/api/v1/events/evt-does-not-exist")
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_ingest_batch(client) -> None:
    events = [
        {
            "sensor": "honeyweb",
            "event_type": "http_request",
            "source_ip": "10.10.0.11",
            "metadata": {"path": "/login", "status": 200},
        }
        for _ in range(5)
    ]
    response = await client.post("/api/v1/ingest/events", json={"events": events})
    assert response.status_code == 200
    assert response.json()["accepted"] == 5


@pytest.mark.asyncio
async def test_ingest_rejects_invalid_event(client) -> None:
    response = await client.post(
        "/api/v1/ingest/events", json={"sensor": "honeyssh", "event_type": "x"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_overview_and_metrics(client) -> None:
    overview = await client.get("/api/v1/overview")
    assert overview.status_code == 200
    body = overview.json()
    for key in (
        "total_events",
        "total_attackers",
        "deception_level",
        "active_decoys",
        "adaptive_mode",
    ):
        assert key in body

    metrics = await client.get("/api/v1/metrics")
    assert metrics.status_code == 200
    assert "events_processed_total" in metrics.json()


@pytest.mark.asyncio
async def test_deception_state_shape(client) -> None:
    response = await client.get("/api/v1/deception/state")
    body = response.json()
    assert body["level"] >= 1
    assert isinstance(body["active_decoys"], list)
    assert body["max_level"] <= 5


@pytest.mark.asyncio
async def test_ingest_token_enforced_when_configured(settings, tmp_path) -> None:
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    settings.ingest.token = "s3cret-ingest-token"
    application = create_app(settings)
    async with (
        application.router.lifespan_context(application),
        AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client,
    ):
        payload = {
            "sensor": "honeyssh",
            "event_type": "connection_attempt",
            "source_ip": "10.10.0.12",
        }
        denied = await client.post("/api/v1/ingest/events", json=payload)
        assert denied.status_code == 401
        allowed = await client.post(
            "/api/v1/ingest/events",
            json=payload,
            headers={"X-Ingest-Token": "s3cret-ingest-token"},
        )
        assert allowed.status_code == 200
