from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.behavior.classifier import BehaviorClassifier
from app.behavior.features import FeatureExtractor
from app.behavior.profiler import AttackerProfiler
from app.behavior.scoring import RiskScorer
from app.config import Settings
from app.database.repository import Repository
from app.database.session import Database
from app.deception.credentials import SyntheticCredentialStore
from app.deception.decoy_hosts import DecoyHost
from app.deception.engine import DeceptionEngine
from app.deception.orchestrator import DecoyOrchestrator, DecoySpec
from app.events.bus import EventBus
from app.events.collector import EventCollector
from app.pipeline import Pipeline
from app.sensors.network import NetworkSensor
from app.sensors.ssh import HoneySSHSensor
from app.sensors.web import HoneyWebSensor

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    settings: Settings
    db: Database
    repository: Repository
    bus: EventBus
    credentials: SyntheticCredentialStore
    orchestrator: DecoyOrchestrator
    engine: DeceptionEngine
    pipeline: Pipeline
    collector: EventCollector
    profiler: AttackerProfiler
    sensors: list[Any] = field(default_factory=list)
    decoy_hosts: dict[str, DecoyHost] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    async def shutdown(self) -> None:
        for sensor in self.sensors:
            try:
                await sensor.stop()
            except Exception:
                logger.exception("failed to stop sensor %s", getattr(sensor, "name", "?"))
        await self.orchestrator.shutdown()
        await self.db.disconnect()


def build_specs(settings: Settings) -> dict[str, DecoySpec]:
    return {
        name: DecoySpec(
            name=name,
            type=cfg.type,
            port=cfg.port,
            deception_level=cfg.deception_level,
            compose_service=name.replace("_", "-"),
        )
        for name, cfg in settings.decoys.items()
    }


async def create_context(settings: Settings) -> AppContext:
    db = Database(settings.database.url)
    await db.connect()
    await db.create_all()
    repository = Repository(db)
    bus = EventBus()
    credentials = SyntheticCredentialStore()
    specs = build_specs(settings)
    orchestrator = DecoyOrchestrator(specs)

    decoy_hosts: dict[str, DecoyHost] = {}
    for name, cfg in settings.decoys.items():
        host = DecoyHost(name, cfg.port, host=cfg.host)
        decoy_hosts[name] = host
        orchestrator.register(name, host.start)
        orchestrator.register_stop(name, host.stop)

    engine = DeceptionEngine(settings, orchestrator, credentials)
    extractor = FeatureExtractor(window_seconds=settings.detection.window_seconds)
    classifier = BehaviorClassifier(settings.detection)
    scorer = RiskScorer(settings.risk)
    profiler = AttackerProfiler()
    pipeline = Pipeline(settings, repository, bus, extractor, classifier, scorer, profiler, engine)
    collector = EventCollector(pipeline, settings.ingest.rate_limit_per_minute)

    sensors: list[Any] = []
    if settings.sensors.ssh.enabled:
        sensors.append(HoneySSHSensor(settings.sensors.ssh, credentials, collector.collect))
    if settings.sensors.web.enabled:
        sensors.append(
            HoneyWebSensor(
                settings.sensors.web,
                credentials,
                collector.collect,
                state_provider=lambda: engine.state,
            )
        )
    if settings.sensors.network.enabled:
        sensors.append(NetworkSensor(settings.sensors.network, collector.collect))

    context = AppContext(
        settings=settings,
        db=db,
        repository=repository,
        bus=bus,
        credentials=credentials,
        orchestrator=orchestrator,
        engine=engine,
        pipeline=pipeline,
        collector=collector,
        profiler=profiler,
        sensors=sensors,
        decoy_hosts=decoy_hosts,
    )

    await _seed_decoys(repository, settings, orchestrator)
    return context


async def _seed_decoys(
    repository: Repository, settings: Settings, orchestrator: DecoyOrchestrator
) -> None:
    for name, cfg in settings.decoys.items():
        status = "inactive"
        if cfg.auto_activate:
            await orchestrator.activate(name)
            status = "active"
        await repository.upsert_decoy(
            name=name,
            type_=cfg.type,
            status=status,
            deception_level=cfg.deception_level,
            port=cfg.port,
            activated=cfg.auto_activate,
        )


async def start_sensors(context: AppContext) -> None:
    for sensor in context.sensors:
        try:
            await sensor.start()
        except OSError as exc:
            logger.error("sensor %s failed to start: %s", getattr(sensor, "name", "?"), exc)


def compose_file() -> Path:
    return Path(__file__).resolve().parents[2] / "lab" / "docker-compose.yml"


__all__ = ["AppContext", "build_specs", "compose_file", "create_context", "start_sensors"]
