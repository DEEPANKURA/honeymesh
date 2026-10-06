from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Attacker(Base):
    __tablename__ = "attackers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime())
    last_seen: Mapped[datetime] = mapped_column(DateTime())
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_band: Mapped[str] = mapped_column(String(16), default="LOW")
    current_stage: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    status: Mapped[str] = mapped_column(String(16), default="active")
    event_count: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(), index=True)
    attacker_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("attackers.id"), index=True, nullable=True
    )
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    sensor: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class BehaviorScore(Base):
    __tablename__ = "behavior_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[str] = mapped_column(String(32), ForeignKey("attackers.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(), index=True)
    recon_score: Mapped[float] = mapped_column(Float, default=0.0)
    credential_score: Mapped[float] = mapped_column(Float, default=0.0)
    web_score: Mapped[float] = mapped_column(Float, default=0.0)
    discovery_score: Mapped[float] = mapped_column(Float, default=0.0)
    lateral_score: Mapped[float] = mapped_column(Float, default=0.0)
    persistence_score: Mapped[float] = mapped_column(Float, default=0.0)


class DeceptionAction(Base):
    __tablename__ = "deception_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attacker_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("attackers.id"), index=True, nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(), index=True)
    policy: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    previous_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    new_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    attacker_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("attackers.id"), index=True, nullable=True
    )
    start_time: Mapped[datetime] = mapped_column(DateTime())
    end_time: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
    sensor: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open")


class Decoy(Base):
    __tablename__ = "decoys"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(32), default="http")
    status: Mapped[str] = mapped_column(String(32), default="inactive")
    deception_level: Mapped[int] = mapped_column(Integer, default=1)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(), nullable=True)
