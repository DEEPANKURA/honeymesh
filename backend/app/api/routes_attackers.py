from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_context, require_read
from app.behavior.profiler import STAGE_ORDER
from app.context import AppContext
from app.metrics import engagement_metrics

router = APIRouter(prefix="/attackers", tags=["attackers"], dependencies=[Depends(require_read)])


@router.get("")
async def list_attackers(
    context: AppContext = Depends(get_context),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = None,
) -> dict[str, object]:
    items, total = await context.repository.list_attackers(
        limit=limit, offset=offset, status=status
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{attacker_id}")
async def get_attacker(
    attacker_id: str, context: AppContext = Depends(get_context)
) -> dict[str, object]:
    attacker = await context.repository.get_attacker(attacker_id)
    if attacker is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    profile = context.profiler.get(attacker_id)
    behavior = await context.repository.latest_behavior_scores(attacker_id)
    return {
        **attacker,
        "stage_order": list(STAGE_ORDER),
        "live_scores": profile.scores if profile else {},
        "latest_behavior": behavior or {},
    }


@router.get("/{attacker_id}/timeline")
async def attacker_timeline(
    attacker_id: str,
    context: AppContext = Depends(get_context),
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, object]:
    attacker = await context.repository.get_attacker(attacker_id)
    if attacker is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    items = await context.repository.timeline(attacker_id, limit=limit)
    return {"items": items, "total": len(items)}


@router.get("/{attacker_id}/behavior")
async def attacker_behavior(
    attacker_id: str, context: AppContext = Depends(get_context)
) -> dict[str, object]:
    attacker = await context.repository.get_attacker(attacker_id)
    if attacker is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    history = await context.repository.behavior_history(attacker_id, limit=300)
    profile = context.profiler.get(attacker_id)
    return {
        "attacker_id": attacker_id,
        "current_stage": attacker["current_stage"],
        "risk_score": attacker["risk_score"],
        "risk_band": attacker["risk_band"],
        "live_scores": profile.scores if profile else {},
        "history": history,
    }


@router.get("/{attacker_id}/engagement")
async def attacker_engagement(
    attacker_id: str, context: AppContext = Depends(get_context)
) -> dict[str, object]:
    attacker = await context.repository.get_attacker(attacker_id)
    if attacker is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    return await engagement_metrics(context.repository, attacker_id)
