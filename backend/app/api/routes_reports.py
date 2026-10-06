from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse

from app.api.deps import get_context, require_read
from app.context import AppContext
from app.reports.generator import build_report, render_html

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(require_read)])


@router.get("/{attacker_id}")
async def generate_report(
    attacker_id: str,
    context: AppContext = Depends(get_context),
    output_format: str = Query("json", alias="format", pattern="^(json|html)$"),
) -> object:
    report = await build_report(context.repository, attacker_id)
    if report is None:
        raise HTTPException(status_code=404, detail="attacker not found")
    if output_format == "html":
        return HTMLResponse(render_html(report))
    return report
