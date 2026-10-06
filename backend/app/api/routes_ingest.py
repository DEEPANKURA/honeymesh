from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_context, require_ingest_token
from app.context import AppContext
from app.events.collector import RateLimitExceededError
from app.events.normalizer import RawEvent

router = APIRouter(prefix="/ingest", tags=["ingest"], dependencies=[Depends(require_ingest_token)])


class IngestBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[RawEvent] = Field(default_factory=list)


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    event_ids: list[str]


@router.post("/events")
async def ingest_events(
    payload: RawEvent | IngestBatch,
    context: AppContext = Depends(get_context),
) -> IngestResult:
    raw_events = payload.events if isinstance(payload, IngestBatch) else [payload]
    if len(raw_events) > 500:
        raise HTTPException(status_code=413, detail="batch too large (max 500)")

    accepted = 0
    rejected = 0
    event_ids: list[str] = []
    errors: list[str] = []
    for raw in raw_events:
        try:
            event = await context.collector.collect(raw)
        except RateLimitExceededError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except ValueError as exc:
            rejected += 1
            errors.append(str(exc))
            continue
        accepted += 1
        event_ids.append(event.event_id)
    if rejected and not accepted:
        raise HTTPException(status_code=422, detail={"errors": errors[:10]})
    return IngestResult(accepted=accepted, rejected=rejected, event_ids=event_ids)
