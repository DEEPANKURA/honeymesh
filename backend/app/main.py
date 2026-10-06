from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.auth import AuthService
from app.api.routes_attackers import router as attackers_router
from app.api.routes_auth import router as auth_router
from app.api.routes_deception import router as deception_router
from app.api.routes_events import router as events_router
from app.api.routes_ingest import router as ingest_router
from app.api.routes_reports import router as reports_router
from app.api.routes_system import router as system_router
from app.api.ws import router as ws_router
from app.config import Settings, load_settings
from app.context import AppContext, create_context, start_sensors

logger = logging.getLogger(__name__)

DESCRIPTION = """
HoneyMesh - adaptive cyber deception network.

All credentials, hosts, files, and enterprise data exposed by this service are
synthetic and confined to an isolated lab environment.
"""


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    )


async def _adaptive_loop(context: AppContext) -> None:
    interval = max(0.2, context.settings.deception.decision_interval_seconds)
    while True:
        await asyncio.sleep(interval)
        try:
            await context.pipeline.evaluate_profiles()
        except asyncio.CancelledError:  # pragma: no cover
            raise
        except Exception:
            logger.exception("adaptive evaluation loop failed")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    setup_logging(settings.logging.level)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        context = await create_context(settings)
        app.state.honeymesh = context
        auth = AuthService.create(settings.auth)
        app.state.auth = auth
        if auth.generated_password:
            logger.warning(
                "generated admin password for user '%s': %s "
                "(set HONEYMESH_ADMIN_PASSWORD to pin a value)",
                settings.auth.admin_username,
                auth.generated_password,
            )
        await start_sensors(context)
        adaptive_task = asyncio.create_task(_adaptive_loop(context))
        app.state.adaptive_task = adaptive_task
        logger.info(
            "HoneyMesh started (mode=%s, adaptive=%s, max_level=%s)",
            settings.environment.mode,
            settings.deception.adaptive_mode,
            settings.deception.max_level,
        )
        try:
            yield
        finally:
            adaptive_task.cancel()
            with suppress(asyncio.CancelledError):
                await adaptive_task
            await context.shutdown()
            logger.info("HoneyMesh stopped")

    app = FastAPI(
        title="HoneyMesh",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )

    app.include_router(events_router, prefix="/api/v1")
    app.include_router(attackers_router, prefix="/api/v1")
    app.include_router(deception_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(ingest_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(system_router, prefix="/api/v1")
    app.include_router(ws_router)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    dashboard_dist = Path("dashboard/dist")
    if dashboard_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(dashboard_dist), html=True), name="dashboard")

    return app


app = create_app()


def run() -> None:  # pragma: no cover
    import uvicorn

    settings = load_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.service.host,
        port=settings.service.port,
        reload=False,
    )


if __name__ == "__main__":  # pragma: no cover
    run()
