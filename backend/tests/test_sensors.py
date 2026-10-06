from __future__ import annotations

import asyncio

import httpx
import paramiko
import pytest
from helpers import free_port

from app.config import NetworkSensorConfig, SSHSensorConfig, WebSensorConfig
from app.deception.credentials import SyntheticCredentialStore
from app.events.normalizer import RawEvent
from app.sensors.network import NetworkSensor
from app.sensors.ssh import HoneySSHSensor
from app.sensors.web import HoneyWebSensor


class Collector:
    def __init__(self) -> None:
        self.events: list[RawEvent] = []

    async def __call__(self, raw: RawEvent) -> None:
        self.events.append(raw)

    def types(self) -> list[str]:
        return [event.event_type for event in self.events]


@pytest.mark.asyncio
async def test_honeyweb_serves_pages_and_records_telemetry() -> None:
    collector = Collector()
    port = free_port()
    sensor = HoneyWebSensor(
        WebSensorConfig(host="127.0.0.1", port=port), SyntheticCredentialStore(seed=2), collector
    )
    await sensor.start()
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as client:
            home = await client.get("/")
            assert home.status_code == 200
            assert "HoneyMesh" in home.text or "Northgate" in home.text

            login = await client.get("/login")
            assert login.status_code == 200
            assert "<form" in login.text

            probe = await client.get("/.env")
            assert probe.status_code == 404

            traversal = await client.get("/login?file=../../etc/passwd")
            assert traversal.status_code in {200, 404}
    finally:
        await sensor.stop()

    types = collector.types()
    assert "session_start" in types
    assert "http_request" in types
    assert "path_enumeration" in types
    assert "http_suspicious_input" in types
    assert "session_start" in types


@pytest.mark.asyncio
async def test_honeyweb_login_with_synthetic_credentials() -> None:
    collector = Collector()
    store = SyntheticCredentialStore(seed=3)
    store.seed_credentials()
    user, password = next(iter(store.credentials.items()))
    port = free_port()
    sensor = HoneyWebSensor(WebSensorConfig(host="127.0.0.1", port=port), store, collector)
    await sensor.start()
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{port}", timeout=10, follow_redirects=False
        ) as client:
            denied = await client.post("/login", data={"username": user, "password": "wrong"})
            assert denied.status_code == 200
            assert "Invalid" in denied.text

            allowed = await client.post("/login", data={"username": user, "password": password})
            assert allowed.status_code == 302

            dashboard = await client.get(
                "/dashboard", cookies={"hm_sid": "web-fixedsession0001", "hm_auth": "1"}
            )
            assert dashboard.status_code == 200
    finally:
        await sensor.stop()

    types = collector.types()
    assert "authentication_attempt" in types
    assert "authentication_success" in types
    assert "credential_harvest" in types
    assert "asset_access" in types


@pytest.mark.asyncio
async def test_honeyweb_admin_portal_gated_by_deception_flags() -> None:
    collector = Collector()
    port = free_port()
    enabled = False

    def state_provider():
        class _State:
            flags = {"admin_portal"} if enabled else set()

        return _State()

    sensor = HoneyWebSensor(
        WebSensorConfig(host="127.0.0.1", port=port),
        SyntheticCredentialStore(seed=4),
        collector,
        state_provider=lambda: state_provider(),
    )
    await sensor.start()
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as client:
            hidden = await client.get("/admin")
            assert hidden.status_code == 404
            enabled = True
            revealed = await client.get("/admin")
            assert revealed.status_code == 200
            assert "Admin Console" in revealed.text
    finally:
        await sensor.stop()
    assert "path_enumeration" in collector.types()
    assert "asset_access" in collector.types()


@pytest.mark.asyncio
async def test_network_sensor_detects_burst_scanning() -> None:
    collector = Collector()
    port = free_port()
    sensor = NetworkSensor(NetworkSensorConfig(host="127.0.0.1", port=port), collector)
    await sensor.start()
    try:
        for _ in range(10):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            await reader.read(64)
            writer.close()
            await writer.wait_closed()
    finally:
        await sensor.stop()

    assert collector.types().count("connection_attempt") == 10
    assert "service_enumeration" in collector.types()


@pytest.mark.asyncio
async def test_honeyssh_rejects_wrong_password_and_accepts_bait() -> None:
    collector = Collector()
    store = SyntheticCredentialStore(seed=5)
    store.seed_credentials()
    user, password = next(iter(store.credentials.items()))
    port = free_port()
    sensor = HoneySSHSensor(
        SSHSensorConfig(host="127.0.0.1", port=port),
        store,
        collector,
    )
    await sensor.start()
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with pytest.raises(paramiko.AuthenticationException):
            client.connect(
                "127.0.0.1",
                port=port,
                username=user,
                password="wrong-password",
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

        client.connect(
            "127.0.0.1",
            port=port,
            username=user,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command("whoami", timeout=10)
        output = stdout.read().decode().strip()
        assert output == "svc_backup"
        client.close()
    finally:
        await sensor.stop()

    await asyncio.sleep(0.3)
    types = collector.types()
    assert "connection_attempt" in types
    assert "authentication_attempt" in types
    assert "authentication_success" in types
    assert "session_command" in types
    assert "session_end" in types
