from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from helpers import build_settings

from app.config import HoneyMeshSettings


@pytest.fixture
def settings(tmp_path: Path) -> HoneyMeshSettings:
    return build_settings(tmp_path)


@pytest.fixture
async def app_pair(settings: HoneyMeshSettings):
    from app.main import create_app

    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver", timeout=30.0
        ) as client:
            yield client, application


@pytest.fixture
async def client(app_pair):
    return app_pair[0]


@pytest.fixture
async def context(app_pair):
    return app_pair[1].state.honeymesh
