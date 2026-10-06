from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from app.config import HoneyMeshSettings, _deep_merge, load_settings


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_settings(tmp_path: Path, **overrides: Any) -> HoneyMeshSettings:
    base: dict[str, Any] = load_settings().model_dump()
    defaults: dict[str, Any] = {
        "database": {"url": f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"},
        "sensors": {
            "ssh": {"enabled": False},
            "web": {"enabled": False},
            "network": {"enabled": False},
        },
        "deception": {"cooldown_seconds": 0.0, "decision_interval_seconds": 60.0},
        "auth": {"admin_password": "unit-test-password-123"},
        "ingest": {"token": "", "rate_limit_per_minute": 100000},
        "decoys": {
            "finance-srv": {"type": "http", "port": free_port(), "deception_level": 3},
            "hr-srv": {"type": "http", "port": free_port(), "deception_level": 3},
            "backup-srv": {"type": "http", "port": free_port(), "deception_level": 3},
        },
    }
    merged = _deep_merge(_deep_merge(base, defaults), overrides)
    return HoneyMeshSettings(**merged)
