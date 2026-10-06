from __future__ import annotations

from fastapi import HTTPException, Request

from app.api.auth import AuthService
from app.context import AppContext


def get_context(request: Request) -> AppContext:
    context: AppContext | None = getattr(request.app.state, "honeymesh", None)
    if context is None:
        raise HTTPException(status_code=503, detail="service is starting")
    return context


def get_auth(request: Request) -> AuthService:
    auth: AuthService | None = getattr(request.app.state, "auth", None)
    if auth is None:
        raise HTTPException(status_code=503, detail="service is starting")
    return auth


def extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    token = request.headers.get("x-admin-token")
    return token.strip() if token else None


async def require_admin(request: Request) -> str:
    auth = get_auth(request)
    token = extract_token(request) or ""
    username = auth.verify(token)
    if username is None:
        raise HTTPException(
            status_code=401,
            detail="admin authentication required (POST /api/v1/auth/login)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


async def require_read(request: Request) -> None:
    context = get_context(request)
    if not context.settings.auth.require_read_auth:
        return
    auth = get_auth(request)
    if auth.verify(extract_token(request) or "") is None:
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_ingest_token(request: Request) -> None:
    context = get_context(request)
    expected = context.settings.ingest.token
    if not expected:
        return
    provided = request.headers.get("x-ingest-token", "")
    if provided != expected:
        raise HTTPException(status_code=401, detail="invalid ingest token")
