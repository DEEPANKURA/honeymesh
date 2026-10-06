from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from app.database.models import (
    Attacker,
    BehaviorScore,
    DeceptionAction,
    Decoy,
    Event,
    SessionRecord,
)
from app.database.session import Database
from app.events.schema import SecurityEvent

BEHAVIOR_FIELDS = (
    "recon_score",
    "credential_score",
    "web_score",
    "discovery_score",
    "lateral_score",
    "persistence_score",
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _db(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(tzinfo=None)


def _from_db(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _iso(dt: datetime | None) -> str:
    resolved = _from_db(dt)
    return resolved.isoformat() if resolved else ""


def attacker_to_dict(row: Attacker) -> dict[str, Any]:
    return {
        "attacker_id": row.id,
        "source_ip": row.source_ip,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "risk_score": round(row.risk_score, 4),
        "risk_band": row.risk_band,
        "current_stage": row.current_stage,
        "status": row.status,
        "event_count": row.event_count,
    }


def event_to_dict(row: Event) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "timestamp": _iso(row.timestamp),
        "attacker_id": row.attacker_id,
        "source_ip": row.source_ip,
        "sensor": row.sensor,
        "event_type": row.event_type,
        "severity": row.severity,
        "session_id": row.session_id,
        "metadata": row.event_metadata,
    }


def behavior_to_dict(row: BehaviorScore) -> dict[str, Any]:
    return {
        "timestamp": _iso(row.timestamp),
        **{name.removesuffix("_score"): round(getattr(row, name), 4) for name in BEHAVIOR_FIELDS},
    }


def action_to_dict(row: DeceptionAction) -> dict[str, Any]:
    return {
        "id": row.id,
        "attacker_id": row.attacker_id,
        "timestamp": _iso(row.timestamp),
        "policy": row.policy,
        "action": row.action,
        "target": row.target,
        "reason": row.reason,
        "confidence": round(row.confidence, 4),
        "previous_state": row.previous_state,
        "new_state": row.new_state,
    }


def decoy_to_dict(row: Decoy) -> dict[str, Any]:
    return {
        "name": row.name,
        "type": row.type,
        "status": row.status,
        "deception_level": row.deception_level,
        "port": row.port,
        "activated_at": _iso(row.activated_at) if row.activated_at else None,
    }


class Repository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # -- attackers ---------------------------------------------------------
    async def resolve_attacker(self, source_ip: str) -> Attacker:
        now = _utc_now()
        async with self._db.session() as session:
            row = (
                await session.execute(select(Attacker).where(Attacker.source_ip == source_ip))
            ).scalar_one_or_none()
            if row is not None:
                row.last_seen = now
                row.event_count += 1
                return row
            attacker = Attacker(
                id=await self._next_attacker_id(session),
                source_ip=source_ip,
                first_seen=now,
                last_seen=now,
                status="active",
                event_count=1,
            )
            session.add(attacker)
            await session.flush()
            return attacker

    @staticmethod
    async def _next_attacker_id(session: Any) -> str:
        rows = (await session.execute(select(Attacker.id))).scalars().all()
        used = {int(value.split("-")[1]) for value in rows if value.startswith("A-")}
        candidate = 1
        while candidate in used:
            candidate += 1
        return f"A-{candidate:03d}"

    async def update_attacker(
        self,
        attacker_id: str,
        *,
        risk_score: float,
        risk_band: str,
        stage: str,
        status: str = "active",
    ) -> None:
        async with self._db.session() as session:
            row = await session.get(Attacker, attacker_id)
            if row is None:
                return
            row.risk_score = risk_score
            row.risk_band = risk_band
            row.current_stage = stage
            row.status = status

    async def list_attackers(
        self, *, limit: int = 100, offset: int = 0, status: str | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        async with self._db.session() as session:
            base = select(Attacker)
            if status:
                base = base.where(Attacker.status == status)
            total = (
                await session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
            rows = (
                await session.execute(
                    base.order_by(Attacker.last_seen.desc()).limit(limit).offset(offset)
                )
            ).scalars()
            return [attacker_to_dict(row) for row in rows], total

    async def get_attacker(self, attacker_id: str) -> dict[str, Any] | None:
        async with self._db.session() as session:
            row = await session.get(Attacker, attacker_id)
            return attacker_to_dict(row) if row else None

    # -- events ------------------------------------------------------------
    async def record_event(self, event: SecurityEvent) -> None:
        async with self._db.session() as session:
            session.add(
                Event(
                    id=event.event_id,
                    timestamp=_db(event.timestamp),
                    attacker_id=event.source_id or None,
                    source_ip=event.source_ip,
                    sensor=event.sensor,
                    event_type=event.event_type,
                    severity=event.severity,
                    session_id=event.session_id,
                    event_metadata=event.metadata,
                )
            )

    async def get_event(self, event_id: str) -> dict[str, Any] | None:
        async with self._db.session() as session:
            row = await session.get(Event, event_id)
            return event_to_dict(row) if row else None

    async def list_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        attacker_id: str | None = None,
        sensor: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        async with self._db.session() as session:
            base = select(Event)
            if attacker_id:
                base = base.where(Event.attacker_id == attacker_id)
            if sensor:
                base = base.where(Event.sensor == sensor)
            if event_type:
                base = base.where(Event.event_type == event_type)
            if severity:
                base = base.where(Event.severity == severity)
            if since:
                base = base.where(Event.timestamp >= _db(since))
            if until:
                base = base.where(Event.timestamp <= _db(until))
            total = (
                await session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
            rows = (
                await session.execute(
                    base.order_by(Event.timestamp.desc()).limit(limit).offset(offset)
                )
            ).scalars()
            return [event_to_dict(row) for row in rows], total

    # -- sessions ----------------------------------------------------------
    async def open_session(self, session_id: str, sensor: str, attacker_id: str | None) -> None:
        async with self._db.session() as session:
            existing = await session.get(SessionRecord, session_id)
            if existing is not None:
                return
            session.add(
                SessionRecord(
                    id=session_id,
                    attacker_id=attacker_id,
                    start_time=_utc_now(),
                    sensor=sensor,
                    status="open",
                )
            )

    async def close_session(self, session_id: str) -> None:
        async with self._db.session() as session:
            row = await session.get(SessionRecord, session_id)
            if row is None or row.status == "closed":
                return
            row.status = "closed"
            row.end_time = _utc_now()

    # -- behavior ----------------------------------------------------------
    async def save_behavior_scores(self, attacker_id: str, scores: dict[str, float]) -> None:
        async with self._db.session() as session:
            session.add(
                BehaviorScore(
                    attacker_id=attacker_id,
                    timestamp=_utc_now(),
                    recon_score=scores.get("recon", 0.0),
                    credential_score=scores.get("credential", 0.0),
                    web_score=scores.get("web", 0.0),
                    discovery_score=scores.get("discovery", 0.0),
                    lateral_score=scores.get("lateral", 0.0),
                    persistence_score=scores.get("persistence", 0.0),
                )
            )

    async def latest_behavior_scores(self, attacker_id: str) -> dict[str, Any] | None:
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(BehaviorScore)
                    .where(BehaviorScore.attacker_id == attacker_id)
                    .order_by(BehaviorScore.timestamp.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            return behavior_to_dict(row) if row else None

    async def behavior_history(self, attacker_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            rows = (
                await session.execute(
                    select(BehaviorScore)
                    .where(BehaviorScore.attacker_id == attacker_id)
                    .order_by(BehaviorScore.timestamp.desc())
                    .limit(limit)
                )
            ).scalars()
            return [behavior_to_dict(row) for row in rows]

    # -- deception ---------------------------------------------------------
    async def record_deception_action(self, action: dict[str, Any]) -> dict[str, Any]:
        async with self._db.session() as session:
            row = DeceptionAction(
                attacker_id=action.get("attacker_id"),
                timestamp=_utc_now(),
                policy=action.get("policy", ""),
                action=action.get("action", ""),
                target=action.get("target", ""),
                reason=action.get("reason", ""),
                confidence=float(action.get("confidence", 0.0)),
                previous_state=action.get("previous_state", {}),
                new_state=action.get("new_state", {}),
            )
            session.add(row)
            await session.flush()
            return action_to_dict(row)

    async def list_deception_actions(
        self, *, limit: int = 100, attacker_id: str | None = None
    ) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            base = select(DeceptionAction)
            if attacker_id:
                base = base.where(DeceptionAction.attacker_id == attacker_id)
            rows = (
                await session.execute(base.order_by(DeceptionAction.timestamp.desc()).limit(limit))
            ).scalars()
            return [action_to_dict(row) for row in rows]

    # -- decoys ------------------------------------------------------------
    async def upsert_decoy(
        self,
        *,
        name: str,
        type_: str,
        status: str,
        deception_level: int,
        port: int | None,
        activated: bool = False,
    ) -> None:
        async with self._db.session() as session:
            row = await session.get(Decoy, name)
            if row is None:
                row = Decoy(id=name, name=name)
                session.add(row)
            row.type = type_
            row.status = status
            row.deception_level = deception_level
            row.port = port
            if activated:
                row.activated_at = _utc_now()

    async def list_decoys(self) -> list[dict[str, Any]]:
        async with self._db.session() as session:
            rows = (await session.execute(select(Decoy))).scalars()
            return [decoy_to_dict(row) for row in rows]

    # -- overview ----------------------------------------------------------
    async def overview(self) -> dict[str, Any]:
        async with self._db.session() as session:
            total_events = (
                await session.execute(select(func.count()).select_from(Event))
            ).scalar_one()
            total_attackers = (
                await session.execute(select(func.count()).select_from(Attacker))
            ).scalar_one()
            high_risk = (
                await session.execute(
                    select(func.count())
                    .select_from(Attacker)
                    .where(Attacker.risk_band.in_(("HIGH", "CRITICAL")))
                )
            ).scalar_one()
            active_decoys = (
                await session.execute(
                    select(func.count()).select_from(Decoy).where(Decoy.status == "active")
                )
            ).scalar_one()
            open_sessions = (
                await session.execute(
                    select(func.count())
                    .select_from(SessionRecord)
                    .where(SessionRecord.status == "open")
                )
            ).scalar_one()
            return {
                "total_events": total_events,
                "total_attackers": total_attackers,
                "high_risk_attackers": high_risk,
                "active_decoys": active_decoys,
                "open_sessions": open_sessions,
            }

    async def timeline(self, attacker_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        events, _ = await self.list_events(limit=limit, attacker_id=attacker_id)
        actions = await self.list_deception_actions(limit=limit, attacker_id=attacker_id)
        merged = [
            {
                "kind": "event",
                "timestamp": item["timestamp"],
                "label": f"{item['sensor']}: {item['event_type']}",
                "severity": item["severity"],
                "detail": item["metadata"],
            }
            for item in events
        ]
        merged += [
            {
                "kind": "deception",
                "timestamp": item["timestamp"],
                "label": f"{item['action']} -> {item['target'] or '-'}",
                "severity": "info",
                "detail": {"reason": item["reason"], "policy": item["policy"]},
            }
            for item in actions
        ]
        merged.sort(key=lambda item: item["timestamp"], reverse=True)
        return merged[:limit]
