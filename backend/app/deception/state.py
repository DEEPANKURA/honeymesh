from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

TELEMETRY_LEVELS = ("normal", "high", "maximum")


@dataclass
class DeceptionState:
    level: int = 1
    strategy: str = "baseline"
    telemetry_level: str = "normal"
    active_decoys: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)
    applied_actions: set[str] = field(default_factory=set)
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def snapshot(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "active_decoys": sorted(self.active_decoys),
            "strategy": self.strategy,
            "telemetry_level": self.telemetry_level,
            "flags": sorted(self.flags),
            "applied_actions": sorted(self.applied_actions),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeceptionState:
        state = cls(
            level=int(data.get("level", 1)),
            strategy=str(data.get("strategy", "baseline")),
            telemetry_level=str(data.get("telemetry_level", "normal")),
            active_decoys=set(data.get("active_decoys", [])),
            flags=set(data.get("flags", [])),
            applied_actions=set(data.get("applied_actions", [])),
        )
        updated = data.get("updated_at")
        if isinstance(updated, str):
            with contextlib.suppress(ValueError):
                state.updated_at = datetime.fromisoformat(updated)
        return state

    def as_public_dict(self) -> dict[str, Any]:
        return self.snapshot()
