from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from app.api.deps import get_context, require_read
from app.context import AppContext

router = APIRouter(tags=["system"])


@router.get("/overview", dependencies=[Depends(require_read)])
async def overview(context: AppContext = Depends(get_context)) -> dict[str, object]:
    counts = await context.repository.overview()
    state = context.engine.state
    engagement_top = None
    attackers, _ = await context.repository.list_attackers(limit=1, status=None)
    if attackers:
        from app.metrics import engagement_metrics

        engagement_top = (
            await engagement_metrics(context.repository, attackers[0]["attacker_id"])
        )["engagement_score"]
    return {
        **counts,
        "deception_level": state.level,
        "deception_strategy": state.strategy,
        "telemetry_level": state.telemetry_level,
        "active_decoys": sorted(state.active_decoys),
        "engagement_score": engagement_top,
        "uptime_seconds": round(time.time() - context.started_at.timestamp(), 1),
        "adaptive_mode": context.settings.deception.adaptive_mode,
    }


@router.get("/metrics")
async def metrics(context: AppContext = Depends(get_context)) -> dict[str, object]:
    counts = await context.repository.overview()
    return {
        "events_received_total": context.collector.collected_total,
        "events_emitted_by_sensor": sum(
            getattr(sensor, "emitted", 0) for sensor in context.sensors
        ),
        "events_processed_total": counts["total_events"],
        "active_attackers": counts["total_attackers"],
        "active_decoys": counts["active_decoys"],
        "deception_actions_total": len(await context.repository.list_deception_actions(limit=1000)),
        "profiles_in_memory": len(context.profiler.all()),
        "uptime_seconds": round(time.time() - context.started_at.timestamp(), 1),
        "websocket_subscribers": context.bus.subscriber_count("security_event"),
    }
