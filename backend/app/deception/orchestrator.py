from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

CommandFactory = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class DecoySpec:
    name: str
    type: str
    port: int
    deception_level: int
    compose_service: str = ""


class UnknownDecoyError(KeyError):
    pass


class DecoyOrchestrator:
    """Activate only pre-registered decoys. Attacker input never becomes a command."""

    def __init__(self, specs: dict[str, DecoySpec]) -> None:
        self._specs = dict(specs)
        self._active: set[str] = set()
        self._hooks: dict[str, Callable[[], Awaitable[None]]] = {}
        self._stoppers: dict[str, Callable[[], Awaitable[None]]] = {}

    def register(self, name: str, hook: Callable[[], Awaitable[None]]) -> None:
        self._hooks[name] = hook

    def register_stop(self, name: str, stopper: Callable[[], Awaitable[None]]) -> None:
        self._stoppers[name] = stopper

    @property
    def specs(self) -> dict[str, DecoySpec]:
        return dict(self._specs)

    @property
    def active(self) -> set[str]:
        return set(self._active)

    def is_active(self, name: str) -> bool:
        return name in self._active

    async def activate(self, name: str) -> bool:
        """Activate a decoy by allowlisted name. Raises on unknown names."""
        if name not in self._specs:
            raise UnknownDecoyError(f"decoy {name!r} is not in the allowlist")
        if name in self._active:
            return False
        hook = self._hooks.get(name)
        if hook is not None:
            await hook()
        self._active.add(name)
        logger.info("decoy activated: %s", name)
        return True

    async def deactivate(self, name: str) -> bool:
        if name not in self._specs:
            raise UnknownDecoyError(f"decoy {name!r} is not in the allowlist")
        if name not in self._active:
            return False
        stopper = self._stoppers.get(name)
        if stopper is not None:
            await stopper()
        self._active.discard(name)
        logger.info("decoy deactivated: %s", name)
        return True

    async def shutdown(self) -> None:
        for name in list(self._active):
            try:
                await self.deactivate(name)
            except Exception:
                logger.exception("failed to deactivate %s", name)


class DockerComposeOrchestrator(DecoyOrchestrator):
    """Drives `docker compose up -d <service>` with fixed service names only."""

    def __init__(self, specs: dict[str, DecoySpec], compose_file: Path) -> None:
        super().__init__(specs)
        self._compose_file = compose_file

    async def _run(self, *args: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "compose",
                "-f",
                str(self._compose_file),
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning("docker binary not available; decoy start skipped")
            return False
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.error("docker compose failed: %s", stderr.decode(errors="replace")[:500])
            return False
        return True

    async def activate(self, name: str) -> bool:
        if name not in self.specs:
            raise UnknownDecoyError(f"decoy {name!r} is not in the allowlist")
        if self.is_active(name):
            return False
        service = self.specs[name].compose_service or name
        if not await self._run("up", "-d", service):
            return False
        self._active.add(name)
        return True

    async def deactivate(self, name: str) -> bool:
        if name not in self.specs:
            raise UnknownDecoyError(f"decoy {name!r} is not in the allowlist")
        if not self.is_active(name):
            return False
        service = self.specs[name].compose_service or name
        await self._run("stop", service)
        self._active.discard(name)
        return True
