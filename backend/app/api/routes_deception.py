from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_context, require_admin, require_read
from app.context import AppContext

router = APIRouter(prefix="/deception", tags=["deception"])


@router.get("/state", dependencies=[Depends(require_read)])
async def deception_state(context: AppContext = Depends(get_context)) -> dict[str, object]:
    state = context.engine.state
    return {
        **state.as_public_dict(),
        "adaptive_mode": context.settings.deception.adaptive_mode,
        "max_level": context.settings.deception.max_level,
        "cooldown_seconds": context.settings.deception.cooldown_seconds,
    }


@router.get("/actions", dependencies=[Depends(require_read)])
async def deception_actions(
    context: AppContext = Depends(get_context),
    attacker_id: str | None = None,
    limit: int = 100,
) -> dict[str, object]:
    items = await context.repository.list_deception_actions(
        limit=min(limit, 1000), attacker_id=attacker_id
    )
    return {"items": items, "total": len(items)}


@router.get("/decoys", dependencies=[Depends(require_read)])
async def list_decoys(context: AppContext = Depends(get_context)) -> dict[str, object]:
    stored = {item["name"]: item for item in await context.repository.list_decoys()}
    items = []
    for name, spec in context.orchestrator.specs.items():
        row = stored.get(name, {})
        items.append(
            {
                "name": name,
                "type": spec.type,
                "port": spec.port,
                "deception_level": spec.deception_level,
                "active": context.orchestrator.is_active(name),
                "status": row.get("status", "inactive"),
                "activated_at": row.get("activated_at"),
            }
        )
    return {"items": items, "total": len(items)}


@router.post("/decoys/{name}/activate", dependencies=[Depends(require_admin)])
async def activate_decoy(
    name: str, context: AppContext = Depends(get_context)
) -> dict[str, object]:
    try:
        activated = await context.orchestrator.activate(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    spec = context.orchestrator.specs[name]
    await context.repository.upsert_decoy(
        name=name,
        type_=spec.type,
        status="active",
        deception_level=spec.deception_level,
        port=spec.port,
        activated=True,
    )
    context.engine.state.active_decoys.add(name)
    return {"name": name, "activated": activated, "state": context.engine.state.as_public_dict()}


@router.post("/decoys/{name}/deactivate", dependencies=[Depends(require_admin)])
async def deactivate_decoy(
    name: str, context: AppContext = Depends(get_context)
) -> dict[str, object]:
    try:
        deactivated = await context.orchestrator.deactivate(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc.args[0])) from exc
    spec = context.orchestrator.specs.get(name)
    if spec is not None:
        await context.repository.upsert_decoy(
            name=name,
            type_=spec.type,
            status="inactive",
            deception_level=spec.deception_level,
            port=spec.port,
        )
    context.engine.state.active_decoys.discard(name)
    return {
        "name": name,
        "deactivated": deactivated,
        "state": context.engine.state.as_public_dict(),
    }
