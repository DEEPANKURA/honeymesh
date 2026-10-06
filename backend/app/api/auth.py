from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

import bcrypt

from app.config import AuthConfig


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))


def verify_password(password: str, password_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash)
    except ValueError:
        return False


@dataclass
class AuthService:
    config: AuthConfig
    password_hash: bytes = field(repr=False, default=b"")
    generated_password: str | None = field(repr=False, default=None)
    _tokens: dict[str, tuple[str, float]] = field(default_factory=dict, repr=False)

    @classmethod
    def create(cls, config: AuthConfig) -> AuthService:
        password = config.admin_password
        generated = None
        if not password:
            generated = secrets.token_urlsafe(12)
            password = generated
        return cls(
            config=config, password_hash=hash_password(password), generated_password=generated
        )

    def login(self, username: str, password: str) -> str | None:
        if username != self.config.admin_username:
            return None
        if not verify_password(password, self.password_hash):
            return None
        token = secrets.token_urlsafe(32)
        self._tokens[token] = (username, time.time() + self.config.token_ttl_seconds)
        return token

    def verify(self, token: str) -> str | None:
        if not token:
            return None
        entry = self._tokens.get(token)
        if entry is None:
            return None
        username, expires_at = entry
        if time.time() > expires_at:
            self._tokens.pop(token, None)
            return None
        return username

    def revoke(self, token: str) -> bool:
        return self._tokens.pop(token, None) is not None

    def prune(self) -> None:
        now = time.time()
        for token, (_, expires_at) in list(self._tokens.items()):
            if now > expires_at:
                self._tokens.pop(token, None)
