from __future__ import annotations

import pytest

CREDENTIAL_EVENTS = [
    {
        "sensor": "honeyssh",
        "event_type": "authentication_attempt",
        "source_ip": "10.20.0.99",
        "username": username,
        "metadata": {"username": username, "result": "failure"},
    }
    for username in ("admin", "root", "admin", "test", "oracle", "admin", "root", "backup")
]

DISCOVERY_EVENTS = [
    {
        "sensor": "honeyweb",
        "event_type": "asset_access",
        "source_ip": "10.20.0.99",
        "host_id": "finance-srv",
        "metadata": {"path": "/finance", "target_host": "finance-srv"},
    }
    for _ in range(10)
]


@pytest.mark.asyncio
async def test_credential_flood_creates_profile_and_adapts(client) -> None:
    response = await client.post("/api/v1/ingest/events", json={"events": CREDENTIAL_EVENTS})
    assert response.status_code == 200, response.text

    attackers = await client.get("/api/v1/attackers")
    body = attackers.json()
    assert body["total"] == 1
    attacker = body["items"][0]
    attacker_id = attacker["attacker_id"]
    assert attacker["source_ip"] == "10.20.0.99"
    assert attacker["event_count"] == len(CREDENTIAL_EVENTS)
    assert attacker["risk_band"] in {"MODERATE", "HIGH", "CRITICAL"}
    assert attacker["current_stage"] == "INITIAL_ACCESS"

    detail = await client.get(f"/api/v1/attackers/{attacker_id}")
    scores = detail.json()["live_scores"]
    assert scores["credential"] >= 0.7

    state = await client.get("/api/v1/deception/state")
    state_body = state.json()
    assert state_body["level"] >= 2
    assert state_body["telemetry_level"] == "high"

    actions = await client.get("/api/v1/deception/actions")
    action_items = actions.json()["items"]
    assert action_items
    assert all(item["reason"] for item in action_items)
    assert any(item["action"] == "deploy_fake_credentials" for item in action_items)

    timeline = await client.get(f"/api/v1/attackers/{attacker_id}/timeline")
    assert timeline.status_code == 200
    labels = {item["label"] for item in timeline.json()["items"]}
    assert any("authentication_attempt" in label for label in labels)


@pytest.mark.asyncio
async def test_discovery_behavior_activates_enterprise_decoys(client) -> None:
    await client.post("/api/v1/ingest/events", json={"events": DISCOVERY_EVENTS})

    state = await client.get("/api/v1/deception/state")
    assert state.json()["level"] >= 3

    decoys = await client.get("/api/v1/deception/decoys")
    active = {item["name"] for item in decoys.json()["items"] if item["active"]}
    assert {"finance-srv", "hr-srv", "backup-srv"} <= active

    actions = await client.get("/api/v1/deception/actions")
    names = {item["action"] for item in actions.json()["items"]}
    assert "activate_finance_srv" in names


@pytest.mark.asyncio
async def test_report_json_and_html(client) -> None:
    await client.post("/api/v1/ingest/events", json={"events": CREDENTIAL_EVENTS})
    attackers = await client.get("/api/v1/attackers")
    attacker_id = attackers.json()["items"][0]["attacker_id"]

    report = await client.get(f"/api/v1/reports/{attacker_id}")
    assert report.status_code == 200
    data = report.json()
    assert set(data) >= {
        "case",
        "period",
        "attacker",
        "timeline",
        "behavioral_classification",
        "risk",
        "deception_changes",
        "indicators",
        "summary",
    }
    assert data["indicators"]["source_ip"] == "10.20.0.99"
    assert data["engagement"]["engagement_score"] >= 0

    html = await client.get(f"/api/v1/reports/{attacker_id}?format=html")
    assert html.status_code == 200
    assert "text/html" in html.headers["content-type"]
    assert "HoneyMesh investigation report" in html.text


@pytest.mark.asyncio
async def test_report_404_for_unknown_attacker(client) -> None:
    response = await client.get("/api/v1/reports/A-999")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_engagement_endpoint(client) -> None:
    events = CREDENTIAL_EVENTS + DISCOVERY_EVENTS
    await client.post("/api/v1/ingest/events", json={"events": events})
    attackers = await client.get("/api/v1/attackers")
    attacker_id = attackers.json()["items"][0]["attacker_id"]
    response = await client.get(f"/api/v1/attackers/{attacker_id}/engagement")
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["engagement_score"] <= 100
    assert set(body["components"]) == set(body["weights"])


@pytest.mark.asyncio
async def test_behavior_history_endpoint(client) -> None:
    await client.post("/api/v1/ingest/events", json={"events": CREDENTIAL_EVENTS})
    attackers = await client.get("/api/v1/attackers")
    attacker_id = attackers.json()["items"][0]["attacker_id"]
    response = await client.get(f"/api/v1/attackers/{attacker_id}/behavior")
    assert response.status_code == 200
    body = response.json()
    assert body["history"]
    assert "credential" in body["live_scores"]


@pytest.mark.asyncio
async def test_session_and_risk_transitions_recorded(client) -> None:
    events = [
        {
            "sensor": "honeyssh",
            "event_type": "session_start",
            "source_ip": "10.30.0.4",
            "session_id": "sess-abc",
        },
        {
            "sensor": "honeyssh",
            "event_type": "session_end",
            "source_ip": "10.30.0.4",
            "session_id": "sess-abc",
        },
    ]
    response = await client.post("/api/v1/ingest/events", json={"events": events})
    assert response.status_code == 200
    metrics = await client.get("/api/v1/metrics")
    assert metrics.json()["events_processed_total"] >= 2
