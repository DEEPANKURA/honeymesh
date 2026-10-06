from __future__ import annotations

from typing import Any

from app.database.repository import Repository

WEIGHTS = {
    "decoy_interactions": 0.25,
    "assets_accessed": 0.15,
    "credential_attempts": 0.15,
    "session_duration": 0.15,
    "services_touched": 0.15,
    "deception_transitions": 0.15,
}

SATURATION = {
    "decoy_interactions": 20.0,
    "assets_accessed": 4.0,
    "credential_attempts": 15.0,
    "session_duration": 15.0,
    "services_touched": 4.0,
    "deception_transitions": 5.0,
}

DECOY_EVENT_TYPES = {"asset_access", "credential_harvest", "session_command"}
CREDENTIAL_EVENT_TYPES = {"authentication_attempt", "credential_harvest"}


def _sat(value: float, ceiling: float) -> float:
    return max(0.0, min(1.0, value / ceiling)) if ceiling > 0 else 0.0


async def engagement_metrics(repository: Repository, attacker_id: str) -> dict[str, Any]:
    """Lab engagement metric. Documented in docs/adaptive-engine.md - not an industry metric."""
    events, total_events = await repository.list_events(limit=10000, attacker_id=attacker_id)
    actions = await repository.list_deception_actions(limit=1000, attacker_id=attacker_id)
    attacker = await repository.get_attacker(attacker_id)

    decoy_interactions = sum(1 for e in events if e["event_type"] in DECOY_EVENT_TYPES)
    credential_attempts = sum(1 for e in events if e["event_type"] in CREDENTIAL_EVENT_TYPES)
    hosts = {
        e["metadata"].get("target_host") or e.get("host_id")
        for e in events
        if (e["metadata"].get("target_host") or e.get("host_id"))
    }
    services = {e["sensor"] for e in events} | {
        e["metadata"].get("service") for e in events if e["metadata"].get("service")
    }
    suspicious = sum(
        1
        for e in events
        if e["severity"] in {"high", "critical"}
        or e["event_type"] in {"http_suspicious_input", "path_enumeration"}
    )

    duration_minutes = 0.0
    if attacker and events:
        first = min(e["timestamp"] for e in events)
        last = max(e["timestamp"] for e in events)
        try:
            from datetime import datetime

            duration_minutes = (
                datetime.fromisoformat(last) - datetime.fromisoformat(first)
            ).total_seconds() / 60.0
        except ValueError:
            duration_minutes = 0.0

    raw = {
        "decoy_interactions": float(decoy_interactions),
        "assets_accessed": float(len(hosts)),
        "credential_attempts": float(credential_attempts),
        "session_duration": duration_minutes,
        "services_touched": float(len(services)),
        "deception_transitions": float(len(actions)),
    }
    components = {name: round(_sat(value, SATURATION[name]), 4) for name, value in raw.items()}
    score = sum(WEIGHTS[name] * components[name] for name in WEIGHTS)
    engagement_score = round(100 * score)

    return {
        "attacker_id": attacker_id,
        "engagement_score": engagement_score,
        "components": components,
        "weights": dict(WEIGHTS),
        "raw": {name: round(value, 4) for name, value in raw.items()},
        "totals": {
            "events": total_events,
            "suspicious_events": suspicious,
            "deception_actions": len(actions),
        },
        "formula": "engagement = 100 * sum(weight_i * saturation(raw_i / cap_i))",
    }
