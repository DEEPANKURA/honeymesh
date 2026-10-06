from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_context, require_read
from app.context import AppContext

router = APIRouter(prefix="/events", tags=["events"], dependencies=[Depends(require_read)])


@router.get("")
async def list_events(
    context: AppContext = Depends(get_context),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    attacker_id: str | None = None,
    sensor: str | None = None,
    event_type: str | None = None,
    severity: str | None = Query(None, pattern="^(info|low|medium|high|critical)$"),
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, object]:
    items, total = await context.repository.list_events(
        limit=limit,
        offset=offset,
        attacker_id=attacker_id,
        sensor=sensor,
        event_type=event_type,
        severity=severity,
        since=since,
        until=until,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{event_id}")
async def get_event(event_id: str, context: AppContext = Depends(get_context)) -> dict[str, object]:
    event = await context.repository.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return event
