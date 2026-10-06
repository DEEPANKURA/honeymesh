from __future__ import annotations

from helpers import build_settings
from starlette.testclient import TestClient

from app.main import create_app


def test_websocket_streams_events(tmp_path) -> None:
    settings = build_settings(tmp_path)
    application = create_app(settings)
    with TestClient(application) as client, client.websocket_connect("/ws/events") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "connected"
        ws.send_json({"type": "ping"})
        pong = ws.receive_json()
        assert pong["type"] == "pong"

        client.post(
            "/api/v1/ingest/events",
            json={
                "sensor": "honeyssh",
                "event_type": "authentication_attempt",
                "source_ip": "10.99.0.1",
                "metadata": {"username": "admin", "result": "failure"},
            },
        )
        message = ws.receive_json()
        assert message["type"] == "security_event"
        assert message["data"]["source_ip"] == "10.99.0.1"
