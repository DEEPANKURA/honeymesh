from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps import extract_token, get_auth, require_admin

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, auth=Depends(get_auth)) -> LoginResponse:
    token = auth.login(payload.username, payload.password)
    if token is None:
        raise HTTPException(status_code=401, detail="invalid credentials")
    return LoginResponse(
        access_token=token,
        expires_in=auth.config.token_ttl_seconds,
        username=payload.username,
    )


@router.get("/me")
async def me(username: str = Depends(require_admin)) -> dict[str, str]:
    return {"username": username, "role": "admin"}


@router.post("/logout")
async def logout(
    request: Request, auth=Depends(get_auth), username: str = Depends(require_admin)
) -> dict[str, object]:
    token = extract_token(request) or ""
    return {"revoked": auth.revoke(token), "username": username}
